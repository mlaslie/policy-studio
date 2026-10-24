"""P3: run modes, credential checks (/auth) and Apply (/apply) against the stateful fake GCP."""
import json

import pytest
from fastapi.testclient import TestClient
from google.oauth2 import credentials as user_creds
from google.oauth2 import service_account

import fakegcp as F
from policy_studio import apply as apply_mod, service, settings
from policy_studio.apply import add_binding, remove_binding
from policy_studio.conditions import READ_ONLY_EXPRESSION, READ_ONLY_TITLE
from policy_studio.app import create_app
from policy_studio.gcp import auth
from policy_studio.gcp.writer import Writer, WriteDisabled, allowed
from policy_studio.model import Condition

Q = {"project": F.P, "region": F.R}
CTX = {"project": F.P, "region": F.R}
MCP_RES = "mcpServers/agentregistry-mcp"


# ====================================================================== mode resolution
@pytest.mark.parametrize("env,mode", [
    ({}, "apply"),
    ({"K_SERVICE": "policy-studio"}, "generate"),
    ({"STUDIO_MODE": "generate"}, "generate"),
    ({"STUDIO_MODE": "apply"}, "apply"),
    ({"STUDIO_MODE": "APPLY"}, "apply"),
    ({"STUDIO_MODE": "bogus"}, "generate"),
    ({"K_SERVICE": "s", "STUDIO_MODE": "generate"}, "generate"),
    ({"K_SERVICE": "s", "STUDIO_MODE": "apply"}, "generate"),                       # refused on Cloud Run
    ({"K_SERVICE": "s", "STUDIO_MODE": "apply", "STUDIO_ALLOW_APPLY_ON_CLOUD_RUN": "true"}, "generate"),
    ({"K_SERVICE": "s", "STUDIO_MODE": "apply", "STUDIO_ALLOW_APPLY_ON_CLOUD_RUN": "1"}, "apply"),
    ({"K_SERVICE": "s", "STUDIO_ALLOW_APPLY_ON_CLOUD_RUN": "1"}, "generate"),        # still needs STUDIO_MODE=apply
    ({"STUDIO_CONTAINER": "1"}, "generate"),                                         # the Docker image (0.0.0.0)
    ({"STUDIO_CONTAINER": "1", "STUDIO_MODE": "apply"}, "apply"),                    # explicit, off Cloud Run
    ({"STUDIO_CONTAINER": "0"}, "apply"),
    ({"STUDIO_CONTAINER": "1", "K_SERVICE": "s", "STUDIO_MODE": "apply"}, "generate"),
])
def test_mode_matrix(env, mode):
    assert settings.resolve_mode(env)[0] == mode


def test_runtime_and_reason():
    assert settings.runtime({"K_SERVICE": "x"}) == "cloud_run" and settings.runtime({}) == "local"
    assert settings.generate_reason({"K_SERVICE": "x"}) == "Generate-only mode (Cloud Run service account)"
    assert "refused" in settings.resolve_mode({"K_SERVICE": "x", "STUDIO_MODE": "apply"})[1]
    assert settings.runtime({"STUDIO_CONTAINER": "1"}) == "local"
    assert "container image" in settings.generate_reason({"STUDIO_CONTAINER": "1"})


# ====================================================================== fixtures
@pytest.fixture
def gcp(monkeypatch):
    g = F.FakeWriteGcp(op_polls=2)
    monkeypatch.setattr(service, "rest_for", lambda ctx: g)
    monkeypatch.setenv("STUDIO_PROJECT", F.P)
    monkeypatch.setenv("STUDIO_REGION", F.R)
    monkeypatch.setenv("STUDIO_APPLY_POLL", "0")
    return g


@pytest.fixture
def client(gcp):
    return TestClient(create_app())


def use_adc(monkeypatch, creds, project=F.P, account="alice@example.com", gcloud=None):
    monkeypatch.setattr(auth, "load_adc", lambda: (creds, project))
    monkeypatch.setattr(auth, "refresh", lambda c: None)
    monkeypatch.setattr(auth, "tokeninfo_email", lambda c: account)
    monkeypatch.setattr(auth, "gcloud_info", lambda: gcloud or {"available": True, "account": account,
                                                                 "project": project})


@pytest.fixture
def adc(monkeypatch):
    use_adc(monkeypatch, user_creds.Credentials(token="t", quota_project_id=F.P))


def checks(a):
    return {c["id"]: c for c in a["checks"]}


# ====================================================================== /auth
def test_auth_no_adc(client):
    a = client.get("/api/studio/auth", params={"project": F.P}).json()
    c = checks(a)
    assert c["adc_present"]["status"] == "error"
    assert c["adc_present"]["fix"] == "gcloud auth application-default login"
    assert a["adc"]["ok"] is False and a["adc"]["error"].startswith("No Application Default Credentials")
    assert a["can_apply"] is False and a["can_apply_reason"] == "No Application Default Credentials"
    assert a["mode"] == "apply" and a["runtime"] == "local" and a["target_project"] == F.P
    assert "can_write" not in c


def test_auth_user_adc_mismatched_project(client, monkeypatch):
    use_adc(monkeypatch, user_creds.Credentials(token="t", quota_project_id="other-proj"), project="other-proj",
            gcloud={"available": True, "account": "bob@example.com", "project": "other-proj"})
    a = client.get("/api/studio/auth", params={"project": F.P}).json()
    c = checks(a)
    assert a["adc"]["type"] == "user" and a["adc"]["account"] == "alice@example.com"
    assert a["adc"]["quota_project"] == "other-proj" and a["adc"]["adc_project"] == "other-proj"
    assert c["adc_present"]["status"] == "ok" and c["adc_valid"]["status"] == "ok"
    assert c["account_matches_gcloud"]["status"] == "warn" and "bob@example.com" in c["account_matches_gcloud"]["detail"]
    assert c["quota_project"]["status"] == "warn"
    assert c["quota_project"]["fix"] == f"gcloud auth application-default set-quota-project {F.P}"
    assert c["project_matches"]["status"] == "warn"
    assert c["project_matches"]["fix"] == f"gcloud config set project {F.P}"
    assert c["can_write"]["status"] == "ok" and all(a["writable"].values())
    assert a["can_apply"] is True                                       # warnings don't block


def test_auth_missing_quota_project(client, monkeypatch):
    use_adc(monkeypatch, user_creds.Credentials(token="t"))
    c = checks(client.get("/api/studio/auth", params={"project": F.P}).json())
    assert c["quota_project"]["status"] == "warn" and c["quota_project"]["title"] == "No quota project on your ADC"
    assert c["quota_project"]["fix"] == f"gcloud auth application-default set-quota-project {F.P}"
    assert c["project_matches"]["status"] == "ok"


def test_auth_service_account(client, monkeypatch):
    sa = service_account.Credentials.__new__(service_account.Credentials)
    sa._service_account_email = "studio@acme-prod.iam.gserviceaccount.com"
    sa._quota_project_id = None
    use_adc(monkeypatch, sa, gcloud={"available": False, "account": "", "project": ""})
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/keys/sa.json")
    a = client.get("/api/studio/auth", params={"project": F.P}).json()
    c = checks(a)
    assert a["adc"]["type"] == "service_account"
    assert a["adc"]["account"] == "studio@acme-prod.iam.gserviceaccount.com"
    assert a["adc"]["source"] == "GOOGLE_APPLICATION_CREDENTIALS=/keys/sa.json"
    assert c["quota_project"]["status"] == "ok"                         # SAs bill their own project
    assert c["account_matches_gcloud"]["status"] == "ok" and a["gcloud"]["available"] is False
    assert a["can_apply"] is True


def test_auth_refresh_fails(client, monkeypatch):
    use_adc(monkeypatch, user_creds.Credentials(token="t", quota_project_id=F.P))

    def boom(c):
        raise RuntimeError("invalid_grant: reauth related error")
    monkeypatch.setattr(auth, "refresh", boom)
    a = client.get("/api/studio/auth", params={"project": F.P}).json()
    c = checks(a)
    assert c["adc_valid"]["status"] == "error" and c["adc_valid"]["fix"] == "gcloud auth application-default login"
    assert a["can_apply"] is False


def test_auth_no_write_permissions(client, gcp, monkeypatch, adc):
    monkeypatch.setattr(gcp, "post", super(F.FakeWriteGcp, gcp).post)  # plain FakeRest: denies write permissions
    a = client.get("/api/studio/auth", params={"project": F.P}).json()
    c = checks(a)
    assert c["can_write"]["status"] == "error" and a["can_apply"] is False
    assert "--role=roles/iap.admin" in c["can_write"]["fix"] and "user:alice@example.com" in c["can_write"]["fix"]
    assert a["writable"] == {k: False for k in auth.WRITE_PERMISSIONS}


def test_auth_partial_write_permissions(gcp, adc):
    orig = gcp.post

    def post(url, json=None, ok404=False):
        if url.endswith(":testIamPermissions"):
            return {"permissions": [p for p in json["permissions"] if p.startswith("iap.")]}
        return orig(url, json, ok404)
    gcp.post = post
    w, errs, _ = auth.writable_kinds(gcp, F.P)
    assert w["grant"] and w["revoke"] and not w["bind_gateway"] and not w["model_armor_on"] and not errs


def test_context_reports_mode(client, adc):
    c = client.get("/api/studio/context", params=Q).json()
    assert c["mode"] == "apply" and c["can_apply"] is True


# ====================================================================== generate mode
def test_generate_mode_has_no_write_path(client, gcp, monkeypatch, adc):
    monkeypatch.setenv("STUDIO_MODE", "generate")
    with pytest.raises(WriteDisabled):
        Writer(gcp)
    constructed = []
    monkeypatch.setattr("policy_studio.gcp.writer.Writer.__init__", lambda *a, **k: constructed.append(1))
    r = client.post("/api/studio/apply", json={"context": CTX, "intents": [grant_intent()],
                                               "confirm": {"project": F.P}})
    assert r.status_code == 403 and r.json()["detail"].startswith("Generate-only mode")
    assert not constructed and not gcp.writes
    a = client.get("/api/studio/auth", params={"project": F.P}).json()
    assert a["mode"] == "generate" and a["can_apply"] is False and a["can_apply_reason"].startswith("Generate-only")
    c = client.get("/api/studio/context", params=Q).json()
    assert c["mode"] == "generate" and c["can_apply"] is False


def test_cloud_run_default_is_generate(client, monkeypatch, adc):
    monkeypatch.setenv("K_SERVICE", "policy-studio")
    monkeypatch.setenv("STUDIO_MODE", "apply")                         # refused without the override
    r = client.post("/api/studio/apply", json={"context": CTX, "intents": [], "confirm": {"project": F.P}})
    assert r.status_code == 403 and "Cloud Run" in r.json()["detail"]


def test_apply_requires_can_apply(client):                             # no ADC (conftest)
    r = client.post("/api/studio/apply", json={"context": CTX, "intents": [], "confirm": {"project": F.P}})
    assert r.status_code == 403 and "Application Default Credentials" in r.json()["detail"]


def test_writer_allowlist():
    assert allowed("POST", f"https://iap.googleapis.com/v1/projects/{F.N}/locations/{F.R}/iap_web/agentRegistry/"
                           f"{MCP_RES}:setIamPolicy")
    assert allowed("PATCH", f"https://{F.R}-aiplatform.googleapis.com/v1/{F.E1}"
                            "?updateMask=spec.deploymentSpec.agentGatewayConfig")
    assert not allowed("PATCH", f"https://{F.R}-aiplatform.googleapis.com/v1/{F.E1}")              # no mask
    assert not allowed("DELETE", f"https://{F.R}-aiplatform.googleapis.com/v1/{F.E1}")
    assert not allowed("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{F.P}:setIamPolicy")


# ====================================================================== apply helpers
def grant_intent(iid="g1", access=None, principal=None, kind="grant"):
    return {"id": iid, "kind": kind,
            "source": {"type": "engine", "principal": principal or F.principal("222"), "label": "Pricing Analyst",
                       "engine": F.E2},
            "destination": {"kind": "mcp_server", "id": "agentregistry-mcp", "name": F.MCP, "label": "Tickets MCP"},
            "access": access or {"mode": "all"}}


def run(client, intents, ack=False, project=F.P):
    r = client.post("/api/studio/apply", json={"context": CTX, "intents": intents,
                                               "confirm": {"project": project, "acknowledge_destructive": ack}})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/x-ndjson")
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def final(events):
    out = {}
    for e in events:
        if "intent_id" in e and not e.get("progress"):
            out[e["intent_id"]] = e
    return out


# ====================================================================== confirm / destructive guards
def test_confirm_project_must_match(client, gcp, adc):
    r = client.post("/api/studio/apply", json={"context": CTX, "intents": [grant_intent()],
                                               "confirm": {"project": "wrong"}})
    assert r.status_code == 400 and "confirm.project" in r.json()["detail"] and not gcp.writes


@pytest.mark.parametrize("intent", [
    grant_intent(kind="revoke"),
    {"id": "u", "kind": "unbind_gateway", "engine": F.E1, "gateway": {"name": F.EG, "direction": "egress"}},
    {"id": "m", "kind": "model_armor_off", "gateway": {"name": "corp-in", "direction": "ingress"}},
])
def test_destructive_needs_ack(client, gcp, adc, intent):
    r = client.post("/api/studio/apply", json={"context": CTX, "intents": [intent], "confirm": {"project": F.P}})
    assert r.status_code == 400 and "acknowledge_destructive" in r.json()["detail"] and not gcp.writes


# ====================================================================== grant / revoke
def test_grant_with_condition_and_undo(client, gcp, adc, tmp_path):
    ev = run(client, [grant_intent(access={"mode": "read_only_hint"})])
    f = final(ev)["g1"]
    assert f["state"] == "verified"
    pol = gcp.iap[MCP_RES]
    new = [b for b in pol["bindings"] if F.principal("222") in b["members"]]
    assert new == [{"role": "roles/iap.egressor", "members": [F.principal("222")],
                    "condition": {"title": READ_ONLY_TITLE, "expression": READ_ONLY_EXPRESSION}}]
    assert pol["version"] == 3
    (method, url, body), = gcp.writes
    assert method == "POST" and url.endswith(f"/iap_web/agentRegistry/{MCP_RES}:setIamPolicy")
    assert body["policy"]["etag"] == "e0" and len(body["policy"]["bindings"]) == 3   # others kept
    assert f["undo"]["kind"] == "revoke" and f["undo"]["id"] == "undo-g1"
    assert f["undo"]["access"]["mode"] == "read_only_hint"
    assert ev[-1] == {"type": "done", "summary": {"total": 1, "verified": 1}}
    log = [json.loads(x) for x in (tmp_path / "apply-log.jsonl").read_text().splitlines()]
    assert [x["state"] for x in log if x.get("state")] == ["done", "verified"]
    assert log[0]["account"] == "alice@example.com" and log[0]["project"] == F.P

    # undo it: back to the original policy's bindings
    ev = run(client, [f["undo"]], ack=True)
    assert final(ev)["undo-g1"]["state"] == "verified"
    assert gcp.iap[MCP_RES]["bindings"] == F.IAP_POLICIES[MCP_RES]["bindings"]


def test_grant_already_present_is_skipped(client, gcp, adc):
    ev = run(client, [grant_intent(principal=F.principal("111"))])
    assert final(ev)["g1"]["state"] == "skipped" and not gcp.writes
    assert "undo" not in final(ev)["g1"]


def test_grant_retries_etag_conflict(client, gcp, adc):
    gcp.etag_conflicts = 2
    ev = run(client, [grant_intent()])
    assert final(ev)["g1"]["state"] == "verified"
    assert len(gcp.writes) == 3
    assert sum("etag conflict" in e.get("detail", "") for e in ev) == 2


def test_grant_gives_up_after_three_retries(client, gcp, adc):
    gcp.etag_conflicts = 10
    ev = run(client, [grant_intent()])
    f = final(ev)["g1"]
    assert f["state"] == "failed" and "changed while" in f["detail"] and "409" in f["raw_error"]
    assert len(gcp.writes) == 4


def test_revoke_precision(client, gcp, adc):
    """Revoke the conditional binding of 999: its unconditional neighbour (111) and other roles stay untouched."""
    gcp.iap[MCP_RES]["bindings"].append({"role": "roles/iap.egressor", "members": [F.principal("999"), "user:x@y.com"]})
    gcp.iap[MCP_RES]["bindings"].append({"role": "roles/iap.admin", "members": [F.principal("999")]})
    before = json.loads(json.dumps(gcp.iap[MCP_RES]["bindings"]))
    ev = run(client, [grant_intent("r1", access={"mode": "read_only_hint", "title": "ro"},
                                   principal=F.principal("999"), kind="revoke")], ack=True)
    f = final(ev)["r1"]
    assert f["state"] == "verified"
    after = gcp.iap[MCP_RES]["bindings"]
    assert after == [before[0], before[2], before[3]]                  # only the conditional 999 binding went
    # the undo restores the removed binding verbatim (exact expression and title)
    assert f["undo"]["kind"] == "grant" and f["undo"]["access"] == {"mode": "custom", "expression": F.RO_EXPR,
                                                                   "title": "ro"}


# A hand-written tools condition without the '' branch: classify() would regenerate it with '' (a different binding).
HAND_TOOLS = "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['get_ticket']"


def revoke_from_grant(g: dict, iid: str) -> dict:
    """What the UI builds from a /audit Grant (lib/grants.ts grantToIntent(g, ..., "revoke")): the binding's exact
    condition as access mode "custom", or mode "all" when it has none."""
    c = g.get("condition")
    return {"id": iid, "kind": "revoke", "source": {"type": "custom", "principal": g["member"], "label": "x"},
            "destination": {"kind": g["resource_kind"], "id": g["resource"].rsplit("/", 1)[-1],
                            "name": g["resource"], "label": g["resource_label"]},
            "access": {"mode": "custom", "expression": c["expression"], "title": c["title"]} if c else {"mode": "all"}}


def audit_grant(client, member, expr=None):
    gs = client.get("/api/studio/audit", params={**Q, "refresh": 1}).json()["grants"]
    return next(g for g in gs if g["resource"] == F.MCP and g["member"] == member
                and ((g.get("condition") or {}).get("expression") == expr))


@pytest.mark.parametrize("access,expr", [
    ({"mode": "read_only_hint"}, READ_ONLY_EXPRESSION),
    ({"mode": "tools", "tools": ["get_ticket"]}, "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in "
                                                 "['get_ticket', '']"),
    ({"mode": "all"}, None),
])
def test_grant_then_revoke_from_read_grant(client, gcp, adc, access, expr):
    """Grant (with or without a condition), read it back through /audit, revoke what was read: verified and gone,
    with the policy's other bindings untouched. Also the same member's other binding stays."""
    p = F.principal("222")
    before = json.loads(json.dumps(gcp.iap[MCP_RES]["bindings"]))
    other = {"mode": "all"} if expr else {"mode": "read_only_hint"}
    for iid, acc in (("g", access), ("o", other)):
        assert final(run(client, [grant_intent(iid, access=acc)]))[iid]["state"] == "verified"
    g = audit_grant(client, p, expr)
    it = revoke_from_grant(g, "r")
    assert client.post("/api/studio/diff", json={"context": CTX, "intents": [it]}).json()["items"][0]["status"] \
        == "remove"
    item = client.post("/api/studio/render", json={"context": CTX, "intents": [it]}).json()["items"][0]
    assert item["anatomy"]["condition"] == expr and "remove-iam-policy-binding" in item["outputs"]["gcloud"]
    f = final(run(client, [it], ack=True))["r"]
    assert f["state"] == "verified", f
    mine = [b for b in gcp.iap[MCP_RES]["bindings"] if p in b["members"]]
    assert [(b.get("condition") or {}).get("expression") for b in mine] == \
        [(F.RO_EXPR if other["mode"] == "read_only_hint" else None)]           # only the revoked binding went
    assert [b for b in gcp.iap[MCP_RES]["bindings"] if p not in b["members"]] == before
    # undo puts the same binding back
    assert final(run(client, [f["undo"]]))[f["undo"]["id"]]["state"] == "verified"
    assert audit_grant(client, p, expr)["condition"] == g.get("condition")


def test_revoke_without_access_misses_conditional_binding(client, gcp, adc):
    """The bug the exact access fixes: a revoke with no access means the unconditional binding, so a conditional
    grant isn't found ("Not granted")."""
    g = audit_grant(client, F.principal("999"), F.RO_EXPR)
    it = revoke_from_grant(g, "r")
    del it["access"]
    f = final(run(client, [it], ack=True))["r"]
    assert f["state"] == "skipped" and "Not granted" in f["detail"] and not gcp.writes


def test_audit_revoke_fix_keeps_exact_condition(client, gcp, adc):
    """A grant whose condition doesn't round-trip through classify() (no '' branch): the audit's
    revoke fix carries it verbatim, renders it, and removes it."""
    gcp.iap[MCP_RES]["bindings"].append({"role": "roles/iap.egressor", "members": ["allUsers"],
                                         "condition": {"title": "hand", "expression": HAND_TOOLS}})
    a = client.get("/api/studio/audit", params=Q).json()
    fix = next(f["fix"] for f in a["findings"] if f["fix"] and f["fix"]["kind"] == "revoke"
               and f["fix"]["source"]["principal"] == "allUsers" and f["resource"] == F.MCP)
    assert {k: v for k, v in fix["access"].items() if v is not None} == \
        {"mode": "custom", "expression": HAND_TOOLS, "title": "hand"}
    item = client.post("/api/studio/render", json={"context": CTX, "intents": [fix]}).json()["items"][0]
    assert item["anatomy"]["condition"] == HAND_TOOLS and "only these tools" in item["english"]
    f = final(run(client, [fix], ack=True))[fix["id"]]
    assert f["state"] == "verified", f
    assert not [b for b in gcp.iap[MCP_RES]["bindings"] if "allUsers" in b["members"]]
    assert f["undo"]["access"] == {"mode": "custom", "expression": HAND_TOOLS, "title": "hand"}


def test_revoke_absent_is_skipped(client, gcp, adc):
    ev = run(client, [grant_intent("r", kind="revoke")], ack=True)
    assert final(ev)["r"]["state"] == "skipped" and not gcp.writes


def test_remove_binding_unit():
    pol = {"etag": "x", "bindings": [
        {"role": "roles/iap.egressor", "members": ["a", "b"]},
        {"role": "roles/iap.egressor", "members": ["a"], "condition": {"title": "t", "expression": "e == 1"}},
        {"role": "roles/other", "members": ["a"]}]}
    new, changed, removed = remove_binding(pol, "a", "roles/iap.egressor", Condition(title="t2", expression="e  == 1"))
    assert changed and removed == [{"title": "t", "expression": "e == 1"}]
    assert new["bindings"] == [pol["bindings"][0], pol["bindings"][2]] and new["etag"] == "x"
    new, changed, _ = remove_binding(pol, "a", "roles/iap.egressor", None)
    assert new["bindings"][0]["members"] == ["b"] and len(new["bindings"]) == 3
    _, changed = add_binding(pol, "a", "roles/iap.egressor", None)
    assert not changed


# ====================================================================== bind / unbind
def test_bind_keeps_other_direction_and_verifies(client, gcp, adc):
    gcp.engines[F.E1]["spec"]["deploymentSpec"]["agentGatewayConfig"]["clientToAgentConfig"] = {"agentGateway": F.IG}
    ev = run(client, [{"id": "u1", "kind": "unbind_gateway", "engine": F.E1,
                       "gateway": {"name": F.EG, "direction": "egress"}}], ack=True)
    f = final(ev)["u1"]
    assert f["state"] == "verified" and f["operation"].startswith(F.E1 + "/operations/")
    (method, url, body), = gcp.writes
    assert method == "PATCH" and url.endswith("?updateMask=spec.deploymentSpec.agentGatewayConfig")
    assert body == {"spec": {"deploymentSpec": {"agentGatewayConfig": {"clientToAgentConfig": {"agentGateway": F.IG}}}}}
    states = [e["state"] for e in ev if e.get("intent_id") == "u1"]
    assert states[:2] == ["running", "running"] and "done" in states and states[-1] == "verified"
    assert any(e.get("progress") for e in ev)                            # LRO progress streamed
    assert f["undo"] == {"id": "undo-u1", "kind": "bind_gateway", "engine": F.E1,
                         "gateway": {"name": F.EG, "direction": "egress"}}


def test_bind_serialized_per_engine(client, gcp, adc):
    ev = run(client, [
        {"id": "b1", "kind": "bind_gateway", "engine": F.E2, "gateway": {"name": F.EG, "direction": "egress"}},
        {"id": "b2", "kind": "bind_gateway", "engine": F.E2, "gateway": {"name": F.IG, "direction": "ingress"}},
    ])
    f = final(ev)
    assert f["b1"]["state"] == "verified" and f["b2"]["state"] == "verified"
    assert len(gcp.writes) == 2
    # the second PATCH starts after the first operation finished, from the live config: both directions kept
    assert gcp.writes[1][2]["spec"]["deploymentSpec"]["agentGatewayConfig"] == {
        "agentToAnywhereConfig": {"agentGateway": F.EG}, "clientToAgentConfig": {"agentGateway": F.IG}}
    order = [(e.get("intent_id"), e.get("state")) for e in ev if not e.get("progress")]
    assert order.index(("b1", "verified")) < order.index(("b2", "done"))
    assert f["b1"]["undo"]["kind"] == "unbind_gateway"


def test_bind_already_bound_is_skipped(client, gcp, adc):
    ev = run(client, [{"id": "b", "kind": "bind_gateway", "engine": F.E1, "gateway": {"name": "corp-out"}}])
    assert final(ev)["b"]["state"] == "skipped" and not gcp.writes


def test_bind_replacing_gateway_undo_restores_previous(client, gcp, adc):
    other = f"projects/{F.P}/locations/{F.R}/agentGateways/other-out"
    ev = run(client, [{"id": "b", "kind": "bind_gateway", "engine": F.E1, "gateway": {"name": other}}])
    f = final(ev)["b"]
    assert f["state"] == "verified" and f["undo"]["kind"] == "bind_gateway" and f["undo"]["gateway"]["name"] == F.EG


def test_operation_error_fails(client, gcp, adc, monkeypatch):
    orig = gcp.get

    def get(url, params=None, ok404=False):
        if "/operations/" in url:
            return {"name": "x", "done": True, "error": {"code": 9, "message": "engine is busy"}}
        return orig(url, params, ok404)
    gcp.get = get
    ev = run(client, [{"id": "b", "kind": "bind_gateway", "engine": F.E2, "gateway": {"name": "corp-out"}}])
    assert final(ev)["b"]["state"] == "failed" and "engine is busy" in final(ev)["b"]["detail"]


def test_operation_timeout_stays_done(gcp, monkeypatch):
    from policy_studio.render import RenderEnv
    from policy_studio.model import Context, Intent

    gcp.op_polls = 10 ** 6
    env = RenderEnv(ctx=Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N))
    a = apply_mod.Applier(env, gcp, Writer(gcp), poll_interval=0, op_timeout=0.05)
    ev = a.events([Intent(id="b", kind="bind_gateway", engine=F.E2, gateway={"name": "corp-out"})])
    f = final(ev)["b"]
    assert f["state"] == "done" and "still running" in f["detail"]


# ====================================================================== Model Armor
def test_model_armor_on_and_undo(client, gcp, adc):
    ev = run(client, [{"id": "m1", "kind": "model_armor_on", "gateway": {"name": "corp-out", "direction": "egress"}}])
    f = final(ev)["m1"]
    assert f["state"] == "verified" and "/operations/" in f["operation"]
    (method, url, body), = gcp.writes
    assert method == "POST" and url.endswith("/authzPolicies?authzPolicyId=corp-out-ma-policy")
    assert body == {"target": {"resources": [F.EG]}, "policyProfile": "CONTENT_AUTHZ", "action": "CUSTOM",
                    "customProvider": {"authzExtension": {"resources": [
                        f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-ma"]}}}
    assert f["undo"]["kind"] == "model_armor_off" and f["undo"]["gateway"]["policy"] == "corp-out-ma-policy"
    ev = run(client, [f["undo"]], ack=True)
    assert final(ev)["undo-m1"]["state"] == "verified" and "corp-out-ma-policy" not in gcp.policies


def test_model_armor_on_when_already_on_is_skipped(client, gcp, adc):
    ev = run(client, [{"id": "m", "kind": "model_armor_on", "gateway": {"name": "corp-in", "direction": "ingress"}}])
    assert final(ev)["m"]["state"] == "skipped" and not gcp.writes


def test_model_armor_off_and_undo(client, gcp, adc):
    ev = run(client, [{"id": "m2", "kind": "model_armor_off", "gateway": {"name": "corp-in", "direction": "ingress"}}],
             ack=True)
    f = final(ev)["m2"]
    assert f["state"] == "verified" and "corp-in-ma" not in gcp.policies
    assert gcp.writes[0][0] == "DELETE" and gcp.writes[0][1].endswith("/authzPolicies/corp-in-ma")
    u = f["undo"]
    assert u["kind"] == "model_armor_on" and u["gateway"]["policy"] == "corp-in-ma"
    assert u["gateway"]["extension"] == f"projects/{F.N}/locations/{F.R}/authzExtensions/corp-ma"
    ev = run(client, [u])
    assert final(ev)["undo-m2"]["state"] == "verified" and gcp.policies["corp-in-ma"]["policyProfile"] == "CONTENT_AUTHZ"


def test_model_armor_off_refuses_non_content_policy(client, gcp, adc):
    ev = run(client, [{"id": "m", "kind": "model_armor_off",
                       "gateway": {"name": "corp-out", "policy": "corp-out-iap-policy"}}], ack=True)
    assert final(ev)["m"]["state"] == "failed" and not gcp.writes


# ====================================================================== mixed batch
def test_invalid_intent_fails_alone_in_apply(client, gcp, adc):
    ev = run(client, [{"id": "bad", "kind": "grant", "destination": {"kind": "bogus", "id": "y"}}, grant_intent()])
    f = final(ev)
    assert f["bad"]["state"] == "failed" and "invalid intent" in f["bad"]["detail"]
    assert f["g1"]["state"] == "verified"
    assert ev[-1]["summary"] == {"total": 2, "failed": 1, "verified": 1}


# ====================================================================== how long until it takes effect
def test_verified_events_and_log_carry_effect_timing(client, gcp, adc, tmp_path):
    ev = run(client, [grant_intent(),
                      grant_intent(iid="g2", principal=F.principal("111")),                  # already there: skipped
                      {"id": "b1", "kind": "bind_gateway", "engine": F.E2,
                       "gateway": {"name": F.EG, "direction": "egress"}}])
    f = final(ev)
    g, b, skipped = f["g1"], f["b1"], f["g2"]
    assert g["state"] == "verified" and b["state"] == "verified" and skipped["state"] == "skipped"
    # stored isn't in effect: the verified event says how long the gateway takes
    assert g["effect"] == "Stored. Takes effect in a few minutes (up to about 7)."
    assert (g["effect_after_s"], g["effect_max_s"], g["effect_measured"]) == (120, 420, False)
    assert b["effect"] == "Stored. Takes effect within about a minute of the redeploy finishing (not measured)."
    assert (b["effect_after_s"], b["effect_max_s"]) == (60, 120)
    assert "about 5 minutes" in next(e["detail"] for e in ev if e.get("intent_id") == "b1" and e["state"] == "done"
                                     and not e.get("progress"))
    assert not any("effect_after_s" in e for e in ev if e.get("state") != "verified")      # only once stored
    log = [json.loads(x) for x in (tmp_path / "apply-log.jsonl").read_text().splitlines()]
    verified = {x["intent_id"]: x for x in log if x.get("state") == "verified"}
    assert (verified["g1"]["effect_after_s"], verified["g1"]["effect_max_s"]) == (120, 420)
    assert (verified["b1"]["effect_after_s"], verified["b1"]["effect_max_s"]) == (60, 120)
    assert not any("effect_after_s" in x for x in log if x.get("state") == "skipped")
    done = log[-1]
    # the largest typical and the largest max among the verified items
    assert done["type"] == "done" and (done["ready_after_s"], done["ready_max_s"]) == (120, 420)
