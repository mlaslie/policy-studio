"""Per-gateway Enforce / Dry run: discovery (mode, shared extensions), render of set_enforcement and
dedicate_extension in every format, diff, preflight, Apply (with undo) against the stateful fake GCP, the writer
guard, the audit finding and the gateway request log classification."""
import json
import os
import subprocess

import pytest
from fastapi.testclient import TestClient
from google.oauth2 import credentials as user_creds

import fakegcp as F
from policy_studio import service
from policy_studio.app import create_app
from policy_studio.gcp import auth, gateways as gw_mod, logs as logs_mod
from policy_studio.gcp.writer import Writer, allowed
from policy_studio.model import Context, Intent
from policy_studio.render import RenderEnv, render
from test_model_armor_setup import TERRAFORM, check_syntax

Q = {"project": F.P, "region": F.R}
CTX = Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N)
EXT = f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-out-iap"
POLICY = f"projects/{F.P}/locations/{F.R}/authzPolicies/corp-out-iap-policy"
COPY = f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-out-own-iap"
ENFORCE = {"id": "enf", "kind": "set_enforcement", "gateway": {"name": F.EG, "direction": "egress"},
           "extension": EXT, "mode": "ENFORCE", "scope": "dedicated"}


def share_with_ingress(policies: dict) -> None:
    """Make corp-in's IAP policy use corp-out's extension (a shared extension)."""
    policies["corp-in-iap-policy"] = {
        "name": f"projects/{F.P}/locations/{F.R}/authzPolicies/corp-in-iap-policy", "policyProfile": "REQUEST_AUTHZ",
        "action": "CUSTOM", "target": {"resources": [f"projects/{F.N}/locations/{F.R}/agentGateways/corp-in"]},
        "customProvider": {"authzExtension": {"resources": [f"projects/{F.N}/locations/{F.R}/authzExtensions/"
                                                            "corp-out-iap"]}}}


def raw_region():
    """Gateways A and B share a dry-run extension; C has its own (enforcing); D has no IAP policy; E's policy
    points at an extension that isn't listed."""
    loc = f"projects/{F.P}/locations/{F.R}"
    num = f"projects/{F.N}/locations/{F.R}"
    gws = [{"name": f"{loc}/agentGateways/{g}", "_project": F.P, "googleManaged": {"governedAccessPath":
                                                                                    "AGENT_TO_ANYWHERE"}}
           for g in "ABCDE"]
    exts = [{"name": f"{loc}/authzExtensions/shared", "service": "iap.googleapis.com", "failOpen": True,
             "metadata": {"iapPolicyVersion": "V1", "iamEnforcementMode": "DRY_RUN"}, "_project": F.P},
            {"name": f"{loc}/authzExtensions/c-iap", "service": "iap.googleapis.com",
             "metadata": {"iapPolicyVersion": "V1"}, "_project": F.P}]

    def pol(name, gw, ext, profile="REQUEST_AUTHZ"):
        return {"name": f"{loc}/authzPolicies/{name}", "policyProfile": profile, "action": "CUSTOM",
                "target": {"resources": [f"{num}/agentGateways/{gw}"]}, "_project": F.P,
                "customProvider": {"authzExtension": {"resources": [f"{num}/authzExtensions/{ext}"]}}}
    pols = [pol("a-iap", "A", "shared"), pol("b-iap", "B", "shared"), pol("c-iap", "C", "c-iap"),
            pol("e-iap", "E", "gone")]
    return {"gateways": gws, "extensions": exts, "policies": pols, "errors": []}


# ====================================================================== discovery
def test_discovery_modes_and_shared_extensions():
    gws = {g.id: g.enforcement for g in gw_mod.build(raw_region(), [])}
    a, b, c, d, e = (gws[x] for x in "ABCDE")
    assert a.mode == "DRY_RUN" and a.failOpen is True and a.editable and a.extension.endswith("/shared")
    assert a.shared_with == [f"projects/{F.P}/locations/{F.R}/agentGateways/B"] and a.policy.endswith("/a-iap")
    assert b.shared_with == [f"projects/{F.P}/locations/{F.R}/agentGateways/A"]
    assert c.mode == "ENFORCE" and c.failOpen is False and c.shared_with == [] and c.editable
    assert d.mode is None and not d.editable and "No IAP REQUEST_AUTHZ policy" in d.reason
    assert e.mode is None and not e.editable and e.policy.endswith("/e-iap") and e.reason


def test_gateways_endpoint_reports_enforcement(monkeypatch):
    rest = F.FakeRest()
    monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
    gws = {g["id"]: g for g in TestClient(create_app()).get("/api/studio/gateways", params=Q).json()["gateways"]}
    out = gws["corp-out"]["enforcement"]
    assert out == {"mode": "DRY_RUN", "extension": EXT, "policy": POLICY, "failOpen": True, "shared_with": [],
                   "editable": True, "reason": None}
    assert gws["corp-in"]["enforcement"]["editable"] is False and gws["corp-in"]["enforcement"]["mode"] is None


# ====================================================================== render
def env_from(raw=None, ctx=CTX):
    raw = raw or {"gateways": [{**g, "_project": F.P} for g in F.GATEWAYS],
                  "extensions": [{**x, "_project": F.P} for x in F.EXTENSIONS],
                  "policies": [{**p, "_project": F.P} for p in F.POLICIES], "errors": []}
    env = RenderEnv(ctx=ctx)
    env.iap = gw_mod.iap_index(raw)
    return env


def test_render_set_enforcement_all_formats():
    res = render([Intent.model_validate(ENFORCE)], env_from())
    it = res.items[0]
    assert not it.error and not it.warnings, it
    check_syntax(it)
    o = it.outputs
    assert it.english.startswith("Enforce IAP on gateway corp-out")
    assert it.anatomy.resource == EXT and it.anatomy.role == "enforcement: Dry run → Enforce"
    assert any("not yet measured" in n for n in it.anatomy.notes)
    # REST: the PATCH with exactly metadata + failOpen; other metadata keys kept, the dry-run key gone
    assert f"https://networkservices.googleapis.com/v1/{EXT}?updateMask=metadata,failOpen" in o.rest
    assert '{"metadata":{"iapPolicyVersion":"V1"},"failOpen":false}' in o.rest
    # gcloud: the full spec, imported
    assert "gcloud service-extensions authz-extensions import corp-out-iap" in o.gcloud
    assert "failOpen: false" in o.gcloud and "iamEnforcementMode" not in o.gcloud
    assert "service: iap.googleapis.com" in o.gcloud
    # Terraform: import the existing extension, update it in place
    assert "import {" in o.terraform and f'id = "{EXT}"' in o.terraform
    assert 'resource "google_network_services_authz_extension"' in o.terraform and "fail_open = false" in o.terraform
    # Python: update_authz_extension with a field mask
    assert "update_authz_extension" in o.python and '"fail_open"' in o.python and "set_iap_enforcement(" in o.python


def test_render_dry_run_is_flagged_and_shared_listed():
    raw = raw_region()
    env = env_from(raw)
    it = Intent(id="d", kind="set_enforcement", gateway={"name": f"projects/{F.P}/locations/{F.R}/agentGateways/C"},
                mode="DRY_RUN")
    r = render([it], env).items[0]
    assert "iamEnforcementMode" in r.outputs.rest and '"failOpen":true' in r.outputs.rest
    assert any(w.startswith("Dry run: once applied, nothing is blocked on C") for w in r.warnings)
    shared = Intent(id="s", kind="set_enforcement", gateway={"name": f"projects/{F.P}/locations/{F.R}/agentGateways/A"},
                    mode="ENFORCE", scope="shared")
    r = render([shared], env).items[0]
    assert r.english.startswith("Enforce IAP on gateways A and B (they share the IAP extension shared)")
    assert any("also controls B" in w for w in r.warnings)
    # the PATCH keeps iapPolicyVersion and drops the dry-run key
    assert '{"metadata":{"iapPolicyVersion":"V1"},"failOpen":false}' in r.outputs.rest
    dedicated = Intent(id="x", kind="set_enforcement", mode="ENFORCE", scope="dedicated",
                       gateway={"name": f"projects/{F.P}/locations/{F.R}/agentGateways/A"})
    assert any("Give A its own extension first" in w for w in render([dedicated], env).items[0].warnings)
    no_iap = Intent(id="n", kind="set_enforcement", mode="ENFORCE",
                    gateway={"name": f"projects/{F.P}/locations/{F.R}/agentGateways/D"})
    assert "no IAP REQUEST_AUTHZ policy" in render([no_iap], env).items[0].error


def dedicate_pair(name="corp-out-own-iap", mode="ENFORCE"):
    return [{"id": "ded", "kind": "dedicate_extension", "gateway": {"name": F.EG, "direction": "egress"},
             "source_extension": EXT, "new_name": name},
            {"id": "flip", "kind": "set_enforcement", "gateway": {"name": F.EG, "direction": "egress"},
             "extension": f"projects/{F.P}/locations/{F.R}/authzExtensions/{name}", "mode": mode,
             "scope": "dedicated"}]


def test_render_dedicate_and_bundle(tmp_path):
    intents = [Intent.model_validate(x) for x in reversed(dedicate_pair())]     # out of order on purpose
    res = render(intents, env_from())
    flip, ded = res.items
    assert not ded.error and not flip.error, (ded, flip)
    for it in (ded, flip):
        check_syntax(it)
    assert ded.english.startswith("Give corp-out its own IAP extension corp-out-own-iap (a copy of corp-out-iap)")
    o = ded.outputs
    assert f"authzExtensions?authzExtensionId=corp-out-own-iap" in o.rest
    assert f"{POLICY}?updateMask=customProvider.authzExtension.resources" in o.rest
    assert '{"customProvider":{"authzExtension":{"resources":["' + COPY + '"]}}}' in o.rest
    assert "authz-extensions import corp-out-own-iap" in o.gcloud and "authz-policies import corp-out-iap-policy" in o.gcloud
    assert "policyProfile: REQUEST_AUTHZ" in o.gcloud
    assert "point_policy_at(" in o.python and "custom_provider.authz_extension.resources" in o.python
    assert 'resource "google_network_security_authz_policy"' in o.terraform and f'id = "{POLICY}"' in o.terraform
    # the copy keeps the source's mode until the flip; the flip of a staged copy says so
    assert "iamEnforcementMode" in o.rest and flip.anatomy.role == "enforcement: Dry run → Enforce"
    assert "created by an earlier item" in " ".join(flip.anatomy.notes)
    b = res.bundle
    assert b.gcloud.index("authz-extensions import corp-out-own-iap") < b.gcloud.index("authz-policies import") \
        < b.gcloud.rindex("authz-extensions import corp-out-own-iap")
    main = b.terraform["main.tf"]
    # Terraform: the flip is folded into the copy's resource (no second resource for the same extension)
    assert main.count('resource "google_network_services_authz_extension"') == 1
    copy_block = main.split('resource "google_network_services_authz_extension"', 1)[1].split("\n}\n", 1)[0]
    assert "fail_open = false" in copy_block and "iamEnforcementMode" not in copy_block
    for text in (b.gcloud, b.rest):
        assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0
    compile(b.python, "<bundle>", "exec")
    if TERRAFORM:
        for k, v in b.terraform.items():
            (tmp_path / k).write_text(v)
        r = subprocess.run([TERRAFORM, "fmt", "-check", "-diff", str(tmp_path)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout
        if os.environ.get("STUDIO_TF_VALIDATE"):
            assert subprocess.run([TERRAFORM, "init", "-backend=false", "-input=false"], cwd=tmp_path,
                                  capture_output=True).returncode == 0
            r = subprocess.run([TERRAFORM, "validate"], cwd=tmp_path, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr


def test_render_revert():
    it = Intent(id="r", kind="dedicate_extension", gateway={"name": F.EG}, source_extension=EXT,
                new_name="corp-out-own-iap", revert=True)
    r = render([it], env_from()).items[0]
    check_syntax(r)
    assert r.english.startswith("Point corp-out's IAP policy back at corp-out-iap and delete")
    assert "-X DELETE" in r.outputs.rest and "authz-extensions delete corp-out-own-iap" in r.outputs.gcloud
    assert it.is_destructive


# ====================================================================== preflight / diff
@pytest.fixture
def read_client(monkeypatch):
    rest = F.FakeRest()
    monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
    return TestClient(create_app()), rest


def test_preflight(read_client):
    c, _ = read_client
    items = [
        {**ENFORCE, "id": "ok"},
        {**ENFORCE, "id": "already", "mode": "DRY_RUN"},
        {"id": "noiap", "kind": "set_enforcement", "gateway": {"name": F.IG, "direction": "ingress"},
         "mode": "ENFORCE"},
        {"id": "taken", "kind": "dedicate_extension", "gateway": {"name": F.EG}, "new_name": "corp-ma"},
        *dedicate_pair(mode="ENFORCE"),
    ]
    st = {i["intent_id"]: i for i in c.post("/api/studio/preflight", json={"context": Q, "intents": items}).json()["items"]}
    assert st["ok"]["status"] == "ok" and "warning" not in st["ok"]
    assert st["already"]["status"] == "blocked" and st["already"]["fix"] == "already"
    assert st["already"]["reason"].startswith("Already in dry run")
    assert st["noiap"]["status"] == "blocked" and "no IAP REQUEST_AUTHZ policy" in st["noiap"]["reason"]
    assert st["taken"]["status"] == "blocked" and "already exists" in st["taken"]["reason"]
    assert st["ded"]["status"] == "ok" and st["flip"]["status"] == "ok"


def test_preflight_warns_shared(monkeypatch):
    g = F.FakeWriteGcp()
    share_with_ingress(g.policies)
    monkeypatch.setattr(service, "rest_for", lambda ctx: g)
    c = TestClient(create_app())
    r = c.post("/api/studio/preflight", json={"context": Q, "intents": [{**ENFORCE, "scope": "shared"}]}).json()
    assert r["items"][0]["status"] == "ok" and "also controls corp-in" in r["items"][0]["warning"]
    gws = {x["id"]: x for x in c.get("/api/studio/gateways", params=Q).json()["gateways"]}
    assert gws["corp-out"]["enforcement"]["shared_with"] == [F.IG]
    assert gws["corp-in"]["enforcement"]["shared_with"] == [F.EG] and gws["corp-in"]["enforcement"]["mode"] == "DRY_RUN"
    f = {x["title"]: x for x in c.get("/api/studio/audit", params=Q).json()["findings"]}
    dry = f["Gateways corp-out and corp-in are in dry run: nothing is blocked"]
    assert dry["severity"] == "high" and dry["fix"]["scope"] == "shared" and dry["fix"]["mode"] == "ENFORCE"
    assert not any(t.startswith("Gateway corp-in is in dry run") for t in f)       # one finding per extension


def test_diff(read_client):
    c, _ = read_client
    items = [ENFORCE, {**ENFORCE, "id": "same", "mode": "DRY_RUN"}, *dedicate_pair()]
    d = {i["intent_id"]: i for i in c.post("/api/studio/diff", json={"context": Q, "intents": items}).json()["items"]}
    assert d["enf"]["status"] == "replace" and d["enf"]["detail"] == "corp-out: Dry run → Enforce"
    assert d["enf"]["current_mode"] == "DRY_RUN" and d["enf"]["target_mode"] == "ENFORCE"
    assert d["same"]["status"] == "present"
    assert d["ded"]["status"] == "add" and "creates corp-out-own-iap" in d["ded"]["detail"]
    assert d["flip"]["status"] == "replace" and "own extension corp-out-own-iap" in d["flip"]["detail"]


# ====================================================================== apply
@pytest.fixture
def gcp(monkeypatch):
    g = F.FakeWriteGcp(op_polls=2)
    monkeypatch.setattr(service, "rest_for", lambda ctx: g)
    monkeypatch.setenv("STUDIO_APPLY_POLL", "0")
    monkeypatch.setattr(auth, "load_adc", lambda: (user_creds.Credentials(token="t", quota_project_id=F.P), F.P))
    monkeypatch.setattr(auth, "refresh", lambda c: None)
    monkeypatch.setattr(auth, "tokeninfo_email", lambda c: "alice@example.com")
    monkeypatch.setattr(auth, "gcloud_info", lambda: {"available": True, "account": "alice@example.com",
                                                      "project": F.P})
    return g


def run(intents, ack=False, status=200):
    r = TestClient(create_app()).post("/api/studio/apply", json={
        "context": Q, "intents": intents, "confirm": {"project": F.P, "acknowledge_destructive": ack}})
    assert r.status_code == status, r.text
    if status != 200:
        return r.json(), {}
    events = [json.loads(x) for x in r.text.splitlines() if x.strip()]
    return events, {e["intent_id"]: e for e in events if e.get("intent_id") and not e.get("progress")}


def test_apply_enforce_then_undo_dry_run(gcp):
    _, f = run([ENFORCE])
    assert f["enf"]["state"] == "verified", f
    (method, url, body), = gcp.writes
    assert method == "PATCH" and url == f"https://networkservices.googleapis.com/v1/{EXT}?updateMask=metadata,failOpen"
    assert body == {"metadata": {"iapPolicyVersion": "V1"}, "failOpen": False}
    assert gcp.extensions["corp-out-iap"]["metadata"] == {"iapPolicyVersion": "V1"}
    assert "not yet measured" in f["enf"]["detail"]
    undo = f["enf"]["undo"]
    assert undo["kind"] == "set_enforcement" and undo["mode"] == "DRY_RUN" and undo["extension"] == EXT
    detail, _ = run([undo], ack=False, status=400)                     # dry run is destructive
    assert "acknowledge_destructive" in detail["detail"]
    _, f = run([undo], ack=True)
    assert f["undo-enf"]["state"] == "verified"
    assert gcp.extensions["corp-out-iap"]["metadata"] == {"iapPolicyVersion": "V1", "iamEnforcementMode": "DRY_RUN"}
    assert gcp.extensions["corp-out-iap"]["failOpen"] is True


def test_apply_already_in_mode_is_blocked(gcp):
    _, f = run([{**ENFORCE, "mode": "DRY_RUN"}], ack=True)
    assert f["enf"]["state"] == "failed" and f["enf"]["blocked"] is True and f["enf"]["fix"] == "already"
    assert not gcp.writes


def test_apply_dedicate_then_flip_then_undo(gcp):
    share_with_ingress(gcp.policies)
    _, f = run(list(reversed(dedicate_pair())))                    # dedicate runs first anyway
    assert f["ded"]["state"] == "verified" and f["flip"]["state"] == "verified", f
    assert [m for m, _, _ in gcp.writes] == ["POST", "PATCH", "PATCH"]
    assert gcp.writes[0][1].endswith("/authzExtensions?authzExtensionId=corp-out-own-iap")
    assert gcp.writes[0][2] == {"service": "iap.googleapis.com", "failOpen": True,
                                "metadata": {"iapPolicyVersion": "V1", "iamEnforcementMode": "DRY_RUN"}}
    assert gcp.writes[1][1].endswith("/authzPolicies/corp-out-iap-policy"
                                     "?updateMask=customProvider.authzExtension.resources")
    assert gcp.writes[2][1].endswith("/authzExtensions/corp-out-own-iap?updateMask=metadata,failOpen")
    # corp-out now has its own enforcing extension; corp-in keeps the original, still in dry run
    assert gcp.policies["corp-out-iap-policy"]["customProvider"]["authzExtension"]["resources"] == [COPY]
    assert gcp.extensions["corp-out-own-iap"]["metadata"] == {"iapPolicyVersion": "V1"}
    assert gcp.extensions["corp-out-iap"]["metadata"]["iamEnforcementMode"] == "DRY_RUN"
    gws = {g["id"]: g for g in TestClient(create_app()).get("/api/studio/gateways",
                                                             params={**Q, "refresh": 1}).json()["gateways"]}
    assert gws["corp-out"]["enforcement"]["mode"] == "ENFORCE" and gws["corp-out"]["enforcement"]["shared_with"] == []
    assert gws["corp-in"]["enforcement"]["mode"] == "DRY_RUN"
    # undo: the flip back (destructive: dry run) and the revert (destructive: deletes the copy)
    undo = [f["flip"]["undo"], f["ded"]["undo"]]
    assert undo[1]["revert"] is True and undo[1]["new_name"] == "corp-out-own-iap"
    run(undo, ack=False, status=400)
    gcp.writes.clear()
    _, u = run(undo, ack=True)
    assert u["undo-flip"]["state"] == "verified" and u["undo-ded"]["state"] == "verified", u
    assert gcp.policies["corp-out-iap-policy"]["customProvider"]["authzExtension"]["resources"] == [EXT]
    assert "corp-out-own-iap" not in gcp.extensions
    assert [m for m, _, _ in gcp.writes] == ["PATCH", "PATCH", "DELETE"]


def test_apply_flip_skipped_when_copy_fails(gcp):
    gcp.extensions["corp-out-own-iap"] = {"name": COPY, "service": "iap.googleapis.com"}   # name taken
    _, f = run(dedicate_pair())
    assert f["ded"]["state"] == "failed" and "already exists" in f["ded"]["detail"]
    assert f["flip"]["state"] == "skipped" and not gcp.writes


def test_revert_keeps_copy_still_used_elsewhere(gcp):
    _, f = run(dedicate_pair())
    assert f["ded"]["state"] == "verified"
    gcp.policies["other"] = {"name": f"projects/{F.P}/locations/{F.R}/authzPolicies/other",
                             "policyProfile": "REQUEST_AUTHZ", "target": {"resources": []},
                             "customProvider": {"authzExtension": {"resources": [COPY]}}}
    _, u = run([f["ded"]["undo"]], ack=True)
    assert u["undo-ded"]["state"] == "done" and "is kept because other" in u["undo-ded"]["detail"]
    assert "corp-out-own-iap" in gcp.extensions


def test_writer_guard(gcp):
    base = f"https://networkservices.googleapis.com/v1/{EXT}"
    assert allowed("PATCH", f"{base}?updateMask=metadata,failOpen")
    assert not allowed("PATCH", f"{base}?updateMask=service")
    assert not allowed("PATCH", base)
    assert allowed("PATCH", f"https://networksecurity.googleapis.com/v1/{POLICY}"
                            "?updateMask=customProvider.authzExtension.resources")
    assert not allowed("PATCH", f"https://networksecurity.googleapis.com/v1/{POLICY}?updateMask=target")
    w = Writer(gcp)
    with pytest.raises(ValueError):
        w.patch_authz_extension(f"{base}?updateMask=metadata,failOpen", {"metadata": {}, "service": "x"})
    with pytest.raises(ValueError):
        w.patch_authz_policy(f"https://networksecurity.googleapis.com/v1/{POLICY}"
                             "?updateMask=customProvider.authzExtension.resources",
                             {"customProvider": {"authzExtension": {"resources": ["a", "b"]}}})
    assert not gcp.writes


# ====================================================================== logs
def entry(status, result=None, tool=None, ts="2026-10-09T14:09:23Z", policy_result=None, **jp):
    """A gateway_requests entry in the format seen live (identifiers replaced with placeholders)."""
    e = {"insertId": f"id-{status}-{result}-{tool}", "timestamp": ts,
         "logName": "projects/my-demo-project/logs/networkservices.googleapis.com%2Fgateway_requests",
         "resource": {"type": "networkservices.googleapis.com/Gateway",
                      "labels": {"gateway_name": "corp-out", "location": F.R, "resource_container": "123456789012"}},
         "httpRequest": {"requestMethod": "POST", "status": status,
                         "requestUrl": "https://tickets-mcp-123456789012.europe-west4.run.app/mcp"},
         "jsonPayload": {"enforcedGatewaySecurityPolicy": {"hostname": "tickets-mcp-123456789012.europe-west4.run.app"},
                         "agentGatewayInfo": {"agentRegistryResource": f"projects/123456789012/locations/{F.R}/"
                                                                        "mcpServers/agentregistry-mcp",
                                              **({"mcpInfo": {"method": "tools/call", "parameter": tool}}
                                                 if tool else {})}, **jp}}
    if result:
        e["jsonPayload"]["authzPolicyInfo"] = {"result": result, "policies": [
            {"result": policy_result or result,
             "name": f"projects/123456789012/locations/{F.R}/authzPolicies/corp-out-iap-policy"}]}
    return e


def test_log_classification():
    assert logs_mod.classify(entry(200, "ALLOWED")) == "allowed"
    assert logs_mod.classify(entry(200)) == "allowed"                       # no authzPolicyInfo
    assert logs_mod.classify(entry(403, "DENIED", "delete_ticket")) == "denied"
    assert logs_mod.classify(entry(200, "DENIED", "delete_ticket")) == "would_deny"
    assert logs_mod.classify(entry(None, "DENIED")) == "denied"
    assert logs_mod.classify(entry(403, "DRY_RUN_DENIED")) == "would_deny"     # tolerant of a dry-run marker
    assert logs_mod.classify(entry(200, "ALLOWED", policy_result="DENIED")) == "would_deny"
    p = logs_mod.parse_entry(entry(200, "DENIED", "delete_ticket"), "my-demo-project",
                             {f"locations/{F.R}/mcpServers/agentregistry-mcp": "Tickets MCP"})
    assert p["decision"] == "would_deny" and p["mcp_tool"] == "delete_ticket" and p["destination"] == "Tickets MCP"
    assert p["host"] == "tickets-mcp-123456789012.europe-west4.run.app" and p["status"] == 200
    assert p["policies"] == [{"name": f"projects/123456789012/locations/{F.R}/authzPolicies/corp-out-iap-policy",
                              "result": "DENIED"}]
    assert p["console_url"].startswith("https://console.cloud.google.com/logs/query;query=insertId%3D")
    assert logs_mod.parse_since("2h", now=__import__("datetime").datetime(2026, 10, 9, 12, tzinfo=__import__(
        "datetime").timezone.utc)) == "2026-10-09T10:00:00Z"
    with pytest.raises(ValueError):
        logs_mod.parse_since("yesterday")


def test_gateway_logs_endpoint(read_client, monkeypatch):
    c, rest = read_client
    rest.log_entries = [entry(200, "DENIED", "delete_ticket"), entry(403, "DENIED", "close_ticket"),
                        entry(200, "ALLOWED", "list_tickets")]
    c.get("/api/studio/gateways", params=Q)                                   # warms the cache (agent inference)
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "since": "24h", "limit": 50}).json()
    assert r["counts"] == {"allowed": 1, "denied": 1, "would_deny": 1}
    assert [e["decision"] for e in r["entries"]] == ["would_deny", "denied", "allowed"]
    assert r["entries"][0]["agent"] == "HR Assistant" and r["entries"][0]["agent_inferred"] is True
    req, = rest.log_requests
    assert req["resourceNames"] == [f"projects/{F.P}"] and req["orderBy"] == "timestamp desc"
    assert f'logName="projects/{F.P}/logs/networkservices.googleapis.com%2Fgateway_requests"' in req["filter"]
    assert 'resource.labels.gateway_name="corp-out"' in req["filter"] and 'timestamp>="' in req["filter"]
    assert r["console_url"].startswith("https://console.cloud.google.com/logs/query;query=")
    assert c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "since": "soon"}).status_code == 400
