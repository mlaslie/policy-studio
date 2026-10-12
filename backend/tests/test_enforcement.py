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
from policy_studio import dryrun, service
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
    assert any("about 2–3 minutes (measured)" in n and "before the operation reports done" in n
               for n in it.anatomy.notes)
    assert not any("not yet measured" in n or "verified live" in n for n in it.anatomy.notes)
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


def labelled_env():
    raw = {"gateways": [{**g, "_project": F.P} for g in F.GATEWAYS],
           "extensions": [{**x, "_project": F.P} for x in F.EXTENSIONS],
           "policies": [{**p, "_project": F.P, **({"labels": {"team": "payments", "env": "prod"}}
                                                   if p["name"].endswith("/corp-out-iap-policy") else {})}
                        for p in F.POLICIES], "errors": []}
    return env_from(raw)


def test_render_dedicate_keeps_labels_in_every_format():
    """The policy PATCH clears labels unless they are in the mask (seen live): every output re-sends them."""
    res = render([Intent.model_validate(x) for x in dedicate_pair()], labelled_env())
    ded = res.items[0]
    check_syntax(ded)
    o = ded.outputs
    assert f"{POLICY}?updateMask=customProvider.authzExtension.resources,labels" in o.rest
    assert ('{"customProvider":{"authzExtension":{"resources":["' + COPY + '"]}},'
            '"labels":{"team":"payments","env":"prod"}}') in o.rest
    assert "labels:\n  team: payments\n  env: prod\n" in o.gcloud
    assert "labels=" in o.python and '"team": "payments"' in o.python and '"labels"]' in o.python
    pol = o.terraform.split('resource "google_network_security_authz_policy"', 1)[1]
    assert "labels = {" in pol and 'team = "payments"' in pol
    assert any("clears the policy's labels" in n for n in ded.anatomy.notes)
    assert not any("hasn't been verified" in n for n in ded.anatomy.notes)
    rev = render([Intent(id="r", kind="dedicate_extension", gateway={"name": F.EG}, source_extension=EXT,
                         new_name="corp-out-own-iap", revert=True)], labelled_env()).items[0]
    assert ('{"customProvider":{"authzExtension":{"resources":["' + EXT + '"]}},'
            '"labels":{"team":"payments","env":"prod"}}') in rev.outputs.rest
    # policy not looked up: the outputs say to add the labels
    env = RenderEnv(ctx=CTX)
    unknown = render([Intent.model_validate(dedicate_pair()[0])], env).items[0]
    assert "The policy wasn't read" in unknown.outputs.rest and "The policy wasn't read" in unknown.outputs.python


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
    assert "about 2–3 minutes (measured)" in f["enf"]["detail"]
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
                                     "?updateMask=customProvider.authzExtension.resources,labels")
    assert gcp.writes[2][1].endswith("/authzExtensions/corp-out-own-iap?updateMask=metadata,failOpen")
    # corp-out now has its own enforcing extension; corp-in keeps the original, still in dry run
    assert gcp.policies["corp-out-iap-policy"]["customProvider"]["authzExtension"]["resources"] == [COPY]
    assert gcp.extensions["corp-out-own-iap"]["metadata"] == {"iapPolicyVersion": "V1"}
    assert gcp.extensions["corp-out-iap"]["metadata"]["iamEnforcementMode"] == "DRY_RUN"
    gws = {g["id"]: g for g in TestClient(create_app()).get("/api/studio/gateways",
                                                             params={**Q, "refresh": 1}).json()["gateways"]}
    assert gws["corp-out"]["enforcement"]["mode"] == "ENFORCE" and gws["corp-out"]["enforcement"]["shared_with"] == []
    assert gws["corp-in"]["enforcement"]["mode"] == "DRY_RUN"
    # undo: only the revert (destructive: deletes the copy). The copy didn't exist before, so flipping it back
    # first would be wasted: the flip has no undo of its own.
    assert "undo" not in f["flip"] and "deletes corp-out-own-iap" in f["flip"]["detail"]
    undo = [f["ded"]["undo"]]
    assert undo[0]["revert"] is True and undo[0]["new_name"] == "corp-out-own-iap"
    run(undo, ack=False, status=400)
    gcp.writes.clear()
    _, u = run(undo, ack=True)
    assert u["undo-ded"]["state"] == "verified", u
    assert gcp.policies["corp-out-iap-policy"]["customProvider"]["authzExtension"]["resources"] == [EXT]
    assert "corp-out-own-iap" not in gcp.extensions
    assert [m for m, _, _ in gcp.writes] == ["PATCH", "DELETE"]


def test_flip_of_existing_copy_keeps_its_undo(gcp):
    """Flipping a copy made by an earlier apply (not this one) keeps its undo: the previous mode."""
    _, f = run([dedicate_pair()[0]])
    assert f["ded"]["state"] == "verified"
    _, f = run([dedicate_pair()[1]], ack=True)
    assert f["flip"]["state"] == "verified"
    assert f["flip"]["undo"]["mode"] == "DRY_RUN" and f["flip"]["undo"]["extension"].endswith("/corp-out-own-iap")


def flip_back():
    return {"id": "undo-flip", "kind": "set_enforcement", "gateway": {"name": F.EG, "direction": "egress"},
            "extension": COPY, "mode": "DRY_RUN", "scope": "dedicated"}


def test_undo_flip_skipped_when_revert_deletes_copy(gcp):
    """An older undo list with both the flip back and the revert: the flip is skipped (the copy is deleted)."""
    _, f = run(dedicate_pair())
    gcp.writes.clear()
    _, u = run([flip_back(), f["ded"]["undo"]], ack=True)
    assert u["undo-flip"]["state"] == "skipped" and "deleted by the revert" in u["undo-flip"]["detail"], u
    assert u["undo-ded"]["state"] == "verified"
    assert [m for m, _, _ in gcp.writes] == ["PATCH", "DELETE"]


def test_undo_flip_runs_when_revert_keeps_copy(gcp):
    """When another policy still uses the copy, the revert keeps it, so the flip back still runs."""
    _, f = run(dedicate_pair())
    gcp.policies["other"] = {"name": f"projects/{F.P}/locations/{F.R}/authzPolicies/other",
                             "policyProfile": "REQUEST_AUTHZ", "target": {"resources": []},
                             "customProvider": {"authzExtension": {"resources": [COPY]}}}
    gcp.writes.clear()
    _, u = run([flip_back(), f["ded"]["undo"]], ack=True)
    assert u["undo-flip"]["state"] == "verified" and u["undo-ded"]["state"] == "done", u
    assert gcp.extensions["corp-out-own-iap"]["metadata"]["iamEnforcementMode"] == "DRY_RUN"
    assert [m for m, _, _ in gcp.writes] == ["PATCH", "PATCH"]


LABELS = {"team": "payments", "env": "prod"}


def test_dedicate_and_revert_keep_policy_labels(gcp):
    gcp.policies["corp-out-iap-policy"]["labels"] = dict(LABELS)
    _, f = run(dedicate_pair())
    assert f["ded"]["state"] == "verified" and "labels kept: env=prod, team=payments" in f["ded"]["detail"], f
    _, url, body = gcp.writes[1]
    assert url.endswith("?updateMask=customProvider.authzExtension.resources,labels")
    assert body == {"customProvider": {"authzExtension": {"resources": [COPY]}}, "labels": LABELS}
    pol = gcp.policies["corp-out-iap-policy"]
    assert pol["labels"] == LABELS and pol["customProvider"]["authzExtension"]["resources"] == [COPY]
    gcp.writes.clear()
    _, u = run([f["ded"]["undo"]], ack=True)
    assert u["undo-ded"]["state"] == "verified", u
    assert gcp.writes[0][2] == {"customProvider": {"authzExtension": {"resources": [EXT]}}, "labels": LABELS}
    assert gcp.policies["corp-out-iap-policy"]["labels"] == LABELS


def test_dedicate_read_back_catches_lost_labels(gcp, monkeypatch):
    """If the labels didn't survive the PATCH, the read-back says so (the fake now ignores labels in the mask)."""
    gcp.policies["corp-out-iap-policy"]["labels"] = dict(LABELS)
    orig = gcp._request

    def lossy(method, url, *, json=None, **kw):
        if method == "PATCH" and "/authzPolicies/" in url:
            json = {k: v for k, v in json.items() if k != "labels"}
        return orig(method, url, json=json, **kw)
    monkeypatch.setattr(gcp, "_request", lossy)
    _, f = run([dedicate_pair()[0]])
    assert f["ded"]["state"] == "failed" and "labels changed (env=prod, team=payments → none)" in f["ded"]["detail"]
    assert f["ded"]["undo"]["revert"] is True


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
                            "?updateMask=customProvider.authzExtension.resources,labels")
    # without labels in the mask the PATCH clears the policy's labels (seen live), so that mask isn't allowed
    assert not allowed("PATCH", f"https://networksecurity.googleapis.com/v1/{POLICY}"
                                "?updateMask=customProvider.authzExtension.resources")
    assert not allowed("PATCH", f"https://networksecurity.googleapis.com/v1/{POLICY}?updateMask=labels")
    assert not allowed("PATCH", f"https://networksecurity.googleapis.com/v1/{POLICY}?updateMask=target")
    w = Writer(gcp)
    with pytest.raises(ValueError):
        w.patch_authz_extension(f"{base}?updateMask=metadata,failOpen", {"metadata": {}, "service": "x"})
    purl = f"https://networksecurity.googleapis.com/v1/{POLICY}?updateMask=customProvider.authzExtension.resources,labels"
    for bad in ({"customProvider": {"authzExtension": {"resources": ["a", "b"]}}},
                {"customProvider": {"authzExtension": {"resources": ["a"]}}, "target": {}},
                {"customProvider": {"authzExtension": {"resources": ["a"]}}, "labels": {"k": 1}},
                {"labels": {"k": "v"}}):
        with pytest.raises(ValueError):
            w.patch_authz_policy(purl, bad)
    assert not gcp.writes


# ====================================================================== logs
NUM_LOC = f"projects/123456789012/locations/{F.R}"     # log entries name registry resources by project number


def entry(status=200, result="ALLOWED", tool=None, resource="mcpServers/agentregistry-mcp", fp="fp-hr",
          ts="2026-10-09T14:09:23Z", policy_result=None, method="tools/call",
          host="tickets-mcp-123456789012.europe-west4.run.app", iid=None):
    """A gateway_requests entry in the format seen live (identifiers replaced with placeholders). In dry run a call
    IAP would deny looks exactly like this too: status 200, result ALLOWED, matchedRules default_denied."""
    gi = {"agentRegistryResource": f"{NUM_LOC}/{resource}"} if resource else {}
    if tool or (method and method != "tools/call"):
        gi["mcpInfo"] = {"method": method, **({"parameter": tool} if tool else {})}
    e = {"insertId": iid or f"id-{status}-{result}-{tool}-{resource}-{fp}", "timestamp": ts,
         "logName": "projects/my-demo-project/logs/networkservices.googleapis.com%2Fgateway_requests",
         "resource": {"type": "networkservices.googleapis.com/Gateway",
                      "labels": {"gateway_name": "corp-out", "location": F.R, "resource_container": "123456789012"}},
         "httpRequest": {"requestMethod": "POST", "status": status,
                         "requestUrl": "https://tickets-mcp-123456789012.europe-west4.run.app/mcp"},
         "jsonPayload": {"enforcedGatewaySecurityPolicy": {
                             "hostname": host,
                             "matchedRules": [{"action": "ALLOWED", "name": "default_denied"}]},
                         "agentGatewayInfo": gi}}
    if fp:
        e["jsonPayload"]["mtls"] = {"clientCertSha256Fingerprint": fp}
    if result:
        e["jsonPayload"]["authzPolicyInfo"] = {"result": result, "policies": [
            {"result": policy_result or result,
             "name": f"projects/123456789012/locations/{F.R}/authzPolicies/corp-out-iap-policy"}]}
    return e


def platform(engine_id, fp):
    """An engine's own Agent Runtime call through the gateway: its URL names the engine."""
    return {"insertId": f"p-{engine_id}", "timestamp": "2026-10-09T14:00:00Z",
            "httpRequest": {"requestMethod": "POST", "status": 200,
                            "requestUrl": f"https://{F.R}-aiplatform.googleapis.com/v1beta1/projects/123456789012/"
                                          f"locations/{F.R}/reasoningEngines/{engine_id}/sessions/s1:appendEvent"},
            "jsonPayload": {"mtls": {"clientCertSha256Fingerprint": fp}}}


def test_log_classification():
    """What the log says: DENIED (or 403) is denied, everything else allowed. Dry run can't be read off an entry."""
    assert logs_mod.classify(entry()) == "allowed"
    assert logs_mod.classify(entry(result=None)) == "allowed"                       # no authzPolicyInfo
    assert logs_mod.classify(entry(403, "DENIED", "delete_ticket")) == "denied"
    assert logs_mod.classify(entry(None, "DENIED")) == "denied"
    assert logs_mod.classify(entry(403, None)) == "denied"
    assert logs_mod.classify(entry(200, "ALLOWED", policy_result="DENIED")) == "denied"
    p = logs_mod.parse_entry(entry(tool="delete_ticket"), "my-demo-project",
                             {f"locations/{F.R}/mcpServers/agentregistry-mcp": "Tickets MCP"})
    assert p["decision"] == "allowed" and p["mcp_tool"] == "delete_ticket" and p["destination"] == "Tickets MCP"
    assert p["host"] == "tickets-mcp-123456789012.europe-west4.run.app" and p["status"] == 200
    assert p["client_cert"] == "fp-hr" and p["registry_resource"] == f"{NUM_LOC}/mcpServers/agentregistry-mcp"
    assert p["policies"] == [{"name": f"projects/123456789012/locations/{F.R}/authzPolicies/corp-out-iap-policy",
                              "result": "ALLOWED"}]
    assert p["console_url"].startswith("https://console.cloud.google.com/logs/query;query=insertId%3D")
    assert logs_mod.parse_since("2h", now=__import__("datetime").datetime(2026, 10, 9, 12, tzinfo=__import__(
        "datetime").timezone.utc)) == "2026-10-09T10:00:00Z"
    with pytest.raises(ValueError):
        logs_mod.parse_since("yesterday")


def test_caller_map():
    m = logs_mod.caller_map([platform("111", "fp-a"), platform("222", "fp-b"), platform("111", "fp-x"),
                             platform("222", "fp-x"), entry(fp="fp-c")], ["111", "222"])
    assert m == {"fp-a": "111", "fp-b": "222"}                       # fp-x is ambiguous, fp-c isn't a platform call
    f = logs_mod.caller_filter([F.P], "corp-out", "2026-10-09T08:00:00Z", ["111", "222"])
    assert f.endswith('AND (httpRequest.requestUrl:"reasoningEngines/111/" OR '
                      'httpRequest.requestUrl:"reasoningEngines/222/")')


@pytest.fixture
def inv(read_client):
    return service.inventory_view(service.resolve(Context(project=F.P, region=F.R)))


def caller(eid, number=F.N, name=None):
    return dryrun.Caller(engine=f"projects/{number}/locations/{F.R}/reasoningEngines/{eid}",
                         display_name=name or f"agent {eid}", principal=F.principal(eid, number), how="mtls")


def check(e, c, inv):
    return dryrun.check(logs_mod.parse_entry(e, F.P), c, inv)


def test_would_deny_grants_and_conditions(inv):
    hr = caller("111", name="HR Assistant")
    # unconditional grant on the MCP server
    d, why = check(entry(tool="delete_ticket"), hr, inv)
    assert d == "allowed" and why == "HR Assistant holds roles/iap.egressor on Tickets MCP."
    # no grant at all
    d, why = check(entry(resource="agents/agentregistry-rt1", method=None), hr, inv)
    assert d == "would_deny" and "holds no roles/iap.egressor grant on HR Assistant" in why
    # allUsers on the KB agent
    assert check(entry(resource="agents/agentregistry-aaa", method=None), caller("555"), inv)[0] == "allowed"
    # "all agents in project": same project number allowed, another project's agent not
    d, why = check(entry(tool="lookup", resource="mcpServers/agentregistry-ro"), caller("222"), inv)
    assert d == "allowed" and "through All agents in project" in why
    assert check(entry(tool="lookup", resource="mcpServers/agentregistry-ro"), caller("222", number="9999"),
                 inv)[0] == "would_deny"
    # read-only-hint condition (principal 999): read-only tool yes, destructive no, unknown tool unknown, setup yes
    ro = caller("999")
    assert check(entry(tool="list_tickets"), ro, inv)[0] == "allowed"
    d, why = check(entry(tool="delete_ticket"), ro, inv)
    assert d == "would_deny" and "is limited (ro)" in why and "doesn't cover delete_ticket" in why
    d, why = check(entry(tool="brand_new_tool"), ro, inv)
    assert d == "unknown" and "can't be evaluated" in why
    assert check(entry(method="tools/list"), ro, inv)[0] == "allowed"


def test_would_deny_tool_list_custom_group_and_unknowns(inv):
    from policy_studio.conditions import tools_expression
    from policy_studio.model import Binding, Condition
    key = next(k for k in inv.access if k.endswith("/mcpServers/agentregistry-mcp"))
    inv.access[key] += [
        Binding(role="roles/iap.egressor", member=F.principal("777"),
                condition=Condition(title="Only MCP tools: add_note", expression=tools_expression(["add_note"]))),
        Binding(role="roles/iap.egressor", member=F.principal("888"),
                condition=Condition(title="Weekdays", expression="request.time.getDayOfWeek() < 5"))]
    t = caller("777")
    assert check(entry(tool="add_note"), t, inv)[0] == "allowed"
    d, why = check(entry(tool="delete_ticket"), t, inv)
    assert d == "would_deny" and "Only MCP tools: add_note" in why
    assert check(entry(method="initialize"), t, inv)[0] == "allowed"           # toolName '' is in the list
    d, why = check(entry(tool="add_note"), caller("888"), inv)
    assert d == "unknown" and "Weekdays" in why                                 # custom condition: never would_deny
    inv.access[key].append(Binding(role="roles/iap.egressor", member="group:agents@example.com"))
    d, why = check(entry(tool="add_note"), caller("666"), inv)
    assert d == "unknown" and "group or domain" in why                          # might be in the group
    assert check(entry(tool="add_note"), None, inv)[0] == "unknown"             # caller not identified
    d, why = check(entry(resource=None, method=None), t, inv)
    assert d == "unknown" and "names no Agent Registry" in why
    d, why = check(entry(resource="agents/agentregistry-elsewhere", method=None), t, inv)
    assert d == "unknown" and "isn't in the inventory" in why
    inv.access_errors[key] = "permission denied"
    assert check(entry(tool="add_note"), t, inv)[0] == "unknown"
    assert dryrun.check(logs_mod.parse_entry(entry(), F.P), t, None)[0] == "unknown"


def test_gateway_logs_endpoint(read_client):
    """Dry-run egress gateway with one bound agent (HR Assistant): allowed entries are checked against its grants."""
    c, rest = read_client
    rest.log_entries = [entry(tool="delete_ticket"), entry(resource="agents/agentregistry-rt1", method=None),
                        entry(403, "DENIED", "close_ticket"), entry(resource=None, method=None)]
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "since": "24h", "limit": 50}).json()
    assert r["counts"] == {"allowed": 1, "denied": 1, "would_deny": 1, "unknown": 1, "platform": 0}, r["entries"]
    assert [e["decision"] for e in r["entries"]] == ["allowed", "would_deny", "denied", "unknown"]
    assert [e["computed"] for e in r["entries"]] == [True, True, False, True]
    wd = r["entries"][1]
    assert wd["reason"].startswith("HR Assistant holds no roles/iap.egressor grant")
    assert wd["agent"] == "HR Assistant" and wd["agent_inferred"] is True
    assert wd["caller"] == {"engine": F.E1, "display_name": "HR Assistant", "how": "only_bound_agent"}
    assert r["entries"][2]["reason"] is None and r["dry_run"] is True
    assert any("not reported by Google" in n for n in r["notes"])
    req, = rest.log_requests                                          # one bound agent: no caller query
    assert req["resourceNames"] == [f"projects/{F.P}"] and req["orderBy"] == "timestamp desc"
    assert f'logName="projects/{F.P}/logs/networkservices.googleapis.com%2Fgateway_requests"' in req["filter"]
    assert 'resource.labels.gateway_name="corp-out"' in req["filter"] and 'timestamp>="' in req["filter"]
    assert r["console_url"].startswith("https://console.cloud.google.com/logs/query;query=")
    assert c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "since": "soon"}).status_code == 400


def test_gateway_logs_caller_by_client_cert(read_client, monkeypatch):
    """Two agents bound: each entry's caller comes from the client certificate seen on its own platform calls."""
    engines = [dict(e) for e in F.ENGINES]
    engines[1] = {**engines[1], "spec": {**engines[1]["spec"], "deploymentSpec": engines[0]["spec"]["deploymentSpec"]}}
    monkeypatch.setattr(F, "ENGINES", engines)
    c, rest = read_client
    rest.platform_entries = [platform("111", "fp-hr"), platform("222", "fp-pricing")]
    rest.log_entries = [entry(tool="delete_ticket", fp="fp-hr"), entry(tool="delete_ticket", fp="fp-pricing"),
                        entry(tool="delete_ticket", fp="fp-stranger")]
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out"}).json()
    hr, pricing, stranger = r["entries"]
    assert hr["decision"] == "allowed" and hr["caller"]["how"] == "mtls" and hr["agent"] == "HR Assistant"
    assert pricing["decision"] == "would_deny" and pricing["agent"] == "Pricing Analyst"
    assert "Pricing Analyst holds no roles/iap.egressor grant on Tickets MCP" in pricing["reason"]
    assert stranger["decision"] == "unknown" and stranger["agent"] is None and stranger["caller"] is None
    main, callers = rest.log_requests
    assert 'httpRequest.requestUrl:"reasoningEngines/111/"' in callers["filter"]
    assert callers["filter"].split('timestamp>="')[1][:19] < main["filter"].split('timestamp>="')[1][:19]


def test_gateway_logs_enforcing_gateway_is_not_computed(read_client, monkeypatch):
    exts = [dict(x) for x in F.EXTENSIONS]
    exts[0] = {**exts[0], "metadata": {"iapPolicyVersion": "V1"}, "failOpen": False}
    monkeypatch.setattr(F, "EXTENSIONS", exts)
    c, rest = read_client
    rest.log_entries = [entry(resource="agents/agentregistry-rt1", method=None), entry(403, "DENIED", "x")]
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out"}).json()
    assert [e["decision"] for e in r["entries"]] == ["allowed", "denied"] and r["dry_run"] is False
    assert not any(e["computed"] for e in r["entries"])


# ---------------------------------------------------------------------- platform traffic, window coverage
AIP = "us-east4-aiplatform.mtls.googleapis.com"


def test_platform_hosts():
    assert logs_mod.is_platform("240.0.0.2:443", False) and logs_mod.is_platform("240.0.0.2", True)
    assert logs_mod.is_platform("[fd00::2]:443", False) and logs_mod.is_platform("metadata.google.internal", False)
    assert logs_mod.is_platform(AIP, True) and logs_mod.is_platform(f"{AIP}:443", False)
    assert logs_mod.is_platform("logging.googleapis.com", False)             # unregistered Google API
    assert not logs_mod.is_platform("logging.googleapis.com", True)          # registered: an agent's destination
    assert not logs_mod.is_platform("tickets-mcp-123456789012.europe-west4.run.app", False)
    assert not logs_mod.is_platform("", False)
    rx = __import__("re").compile(logs_mod.PLATFORM_HOST_RE)                   # what the second query leaves out
    assert rx.match(AIP) and rx.match(f"{AIP}:443") and rx.match("240.0.0.2:443") and rx.match("europe-west4-aiplatform.googleapis.com")
    assert not rx.match("tickets-mcp-123456789012.europe-west4.run.app") and not rx.match("logging.googleapis.com")
    assert "\\" not in logs_mod.PLATFORM_HOST_RE
    f = logs_mod.checked_filter([F.P], "corp-out", "2026-10-09T08:00:00Z")
    assert f.endswith(f' AND NOT jsonPayload.enforcedGatewaySecurityPolicy.hostname=~"{logs_mod.PLATFORM_HOST_RE}"')


def test_would_deny_platform(inv):
    hr = caller("111", name="HR Assistant")
    # unregistered platform address: "platform", whoever the caller is and even without the grants
    for c, i in ((hr, inv), (None, inv), (hr, None)):
        d, why = check(entry(resource=None, method=None, host="240.0.0.2:443"), c, i)
        assert d == "platform" and "240.0.0.2:443" in why
    # registered aiplatform endpoint: still checked against the grants (all agents in project hold egressor)
    p = logs_mod.parse_entry(entry(resource="endpoints/agentregistry-ep", method=None, host=AIP), F.P)
    assert p["platform"] is True
    d, why = dryrun.check(p, hr, inv)
    assert d == "allowed" and "through All agents in project" in why
    # an unregistered non-platform host is still unknown
    assert check(entry(resource=None, method=None), hr, inv)[0] == "unknown"


def test_gateway_logs_platform_and_window_coverage(read_client):
    """Dry run, limit 3: the newest entries are platform calls, so a second query without the platform hosts adds
    the older would-deny entry; platform calls aren't unknown."""
    c, rest = read_client
    plat = [entry(resource=None, method=None, host="240.0.0.2:443", ts=f"2026-10-09T14:5{i}:00Z", iid=f"ip{i}")
            for i in range(3)]
    aip = [entry(resource="endpoints/agentregistry-ep", method=None, host=AIP, ts=f"2026-10-09T14:4{i}:00Z",
                 iid=f"aip{i}") for i in range(3)]
    old = entry(resource="agents/agentregistry-rt1", method=None, ts="2026-10-09T10:00:00Z", iid="old")
    rest.log_entries = plat[::-1] + aip[::-1] + [old]
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "limit": 3}).json()
    assert [e["insert_id"] for e in r["entries"]] == ["ip2", "ip1", "ip0", "old"]
    assert [e["decision"] for e in r["entries"]] == ["platform"] * 3 + ["would_deny"]
    assert r["counts"] == {"allowed": 0, "denied": 0, "would_deny": 1, "unknown": 0, "platform": 3}
    assert r["truncated"] is True and r["checked_truncated"] is False
    assert any("every non-platform entry of the window was checked" in n for n in r["notes"])
    main, second = rest.log_requests
    assert main["pageSize"] == 3 and "NOT jsonPayload" not in main["filter"]
    assert second["filter"] == logs_mod.checked_filter([F.P], "corp-out", main["filter"].split('timestamp>="')[1][:20])
    # the second query is capped (and paged): checked_truncated, and the note says older entries were left out
    service.cache.clear()
    rest.log_requests.clear()
    rest.log_entries = plat[::-1] + [entry(resource="agents/agentregistry-rt1", method=None,
                                           ts=f"2026-10-09T1{i % 10}:00:00Z", iid=f"x{i}") for i in range(12)]
    orig = logs_mod.CHECK_CAP
    logs_mod.CHECK_CAP = 5
    try:
        r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "limit": 3, "refresh": 1}).json()
    finally:
        logs_mod.CHECK_CAP = orig
    assert r["truncated"] is True and r["checked_truncated"] is True and r["counts"]["would_deny"] == 5
    assert any("may be missing" in n for n in r["notes"])


def test_gateway_logs_second_query_only_when_needed(read_client, monkeypatch):
    c, rest = read_client
    rest.log_entries = [entry(resource=None, method=None, host="240.0.0.2:443"), entry(tool="delete_ticket")]
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "limit": 50}).json()
    assert len(rest.log_requests) == 1 and r["truncated"] is False and r["counts"]["platform"] == 1
    # enforcing gateway: no second query even when truncated; platform entries keep their logged decision
    exts = [dict(x) for x in F.EXTENSIONS]
    exts[0] = {**exts[0], "metadata": {"iapPolicyVersion": "V1"}, "failOpen": False}
    monkeypatch.setattr(F, "EXTENSIONS", exts)
    service.cache.clear()
    rest.log_requests.clear()
    r = c.get("/api/studio/gateway-logs", params={**Q, "gateway": "corp-out", "limit": 1}).json()
    assert len(rest.log_requests) == 1 and r["truncated"] is True and r["checked_truncated"] is False
    assert r["entries"][0]["decision"] == "allowed" and r["entries"][0]["platform"] is True
