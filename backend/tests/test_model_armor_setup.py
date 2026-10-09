"""Model Armor setup: discovery (templates, service agents, roles, `setup`), render of the setup kinds, bundle order,
placeholder replacement, writer guard and Apply against the stateful fake GCP."""
import json
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient
from google.oauth2 import credentials as user_creds

import fakegcp as F
from policy_studio import service
from policy_studio.app import create_app
from policy_studio.gcp import auth, model_armor as ma
from policy_studio.gcp.writer import Writer, allowed, check_project_policy_change
from policy_studio.model import Context, GatewayRef, Intent, SetupParams, TemplateFilters
from policy_studio.render import RenderEnv, render

TERRAFORM = shutil.which("terraform") or ("/opt/homebrew/bin/terraform"
                                          if os.path.exists("/opt/homebrew/bin/terraform") else None)
CTX = Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N)
ENV = RenderEnv(ctx=CTX)
Q = {"project": F.P, "region": F.R}
TNAME = f"projects/{F.P}/locations/{F.R}/templates/corp-shield"
XNAME = f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-ma-authz"


def setup_intents(member=F.DEP_SA, gateway="corp-out", direction="egress", extension_on_intent=False):
    on = {"name": gateway, "direction": direction}
    if extension_on_intent:
        on["extension"] = XNAME
    return [
        {"id": "on", "kind": "model_armor_on", "gateway": on},                       # out of order on purpose
        {"id": "iam", "kind": "iam_project_grant", "params": {"member": member, "roles": ma.MA_ROLES}},
        {"id": "ext", "kind": "model_armor_extension", "params": {"name": "corp-ma-authz", "template": "corp-shield"}},
        {"id": "tmpl", "kind": "model_armor_template", "params": {
            "template_id": "corp-shield", "block_message": "Blocked: it's against policy",
            "filters": {"pi_jailbreak": "HIGH", "sdp": "basic", "rai": {"HATE_SPEECH": "LOW_AND_ABOVE",
                                                                         "DANGEROUS": "off"},
                        "malicious_uri": True}}},
    ]


def check_syntax(item):
    for k in ("gcloud", "rest"):
        r = subprocess.run(["bash", "-n"], input=item.outputs.model_dump()[k], capture_output=True, text=True)
        assert r.returncode == 0, (k, r.stderr, item.outputs.model_dump()[k])
    compile(item.outputs.python, "<python>", "exec")
    if TERRAFORM:
        r = subprocess.run([TERRAFORM, "fmt", "-check", "-"], input=item.outputs.terraform, capture_output=True,
                           text=True)
        assert r.returncode == 0, item.outputs.terraform


# ====================================================================== discovery
@pytest.fixture
def read_client(monkeypatch):
    def make(model_armor=True):
        rest = F.FakeRest(model_armor=model_armor)
        monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
        return TestClient(create_app())
    return make


def test_setup_discovery_with_model_armor(read_client):
    m = read_client().get("/api/studio/model-armor", params=Q).json()
    s = m["setup"]
    assert s["missing"] == ["service_agent_roles"] and s["ready"] is False
    agents = {a["email"]: a for a in s["service_agents"]}
    dep, re_ = agents[F.DEP_SA], agents[F.RE_SA]
    assert dep["gateway"] == F.EG and dep["source"].startswith("agentGatewayCard")
    # the conditional binding doesn't count
    assert dep["roles"] == {"roles/modelarmor.calloutUser": True, "roles/modelarmor.user": True,
                            "roles/serviceusage.serviceUsageConsumer": False}
    assert re_["gateway"] == F.IG and not any(re_["roles"].values()) and "check yours" in re_["note"]
    assert [t["id"] for t in s["templates"]] == ["strict"] and s["extensions"][0]["name"].endswith("/corp-ma")
    assert s["suggested"]["template"] == f"projects/{F.P}/locations/{F.R}/templates/strict"


def test_setup_discovery_without_model_armor(read_client):
    m = read_client(model_armor=False).get("/api/studio/model-armor", params=Q).json()
    s = m["setup"]
    assert s["missing"] == ["template", "extension", "service_agent_roles"] and not s["ready"]
    assert m["templates"] == [] and m["extensions"] == [] and s["templates"] == []
    assert s["suggested"] == {"template_id": "corp-shield", "template": None, "extension_name": "corp-ma-authz"}
    assert len(s["service_agents"]) == 2
    assert all(not r["enabled"] for r in m["gateways"])


def test_setup_unit_helpers():
    assert ma.roles_of({"bindings": [{"role": "roles/modelarmor.user", "members": ["serviceAccount:a@x.iam."
                                                                                     "gserviceaccount.com"]}]},
                       "a@x.iam.gserviceaccount.com")["roles/modelarmor.user"] is True
    agents = ma.service_agents([{**g, "_project": F.P} for g in F.GATEWAYS], {F.P: F.N})
    assert [a["email"] for a in agents] == [F.DEP_SA, F.RE_SA]
    assert ma.suggested_prefix(["gateway-1", "acme-egress"]) == "acme"
    assert ma.unique("x", {"x", "x-2"}) == "x-3"
    body = ma.template_body(TemplateFilters(pi_jailbreak="off", sdp="off", rai={}, malicious_uri=False), None)
    assert body["filterConfig"] == {} and "customPromptSafetyErrorMessage" not in body["templateMetadata"]
    ext = ma.extension_body("us-east4", TNAME)
    assert ext["service"] == "modelarmor.us-east4.rep.googleapis.com" and ext["failOpen"] is False
    assert json.loads(ext["metadata"]["model_armor_settings"]) == [{"request_template_id": TNAME,
                                                                   "response_template_id": TNAME}]


def test_context_checks_get_iam_policy(read_client):
    c = read_client().get("/api/studio/context", params=Q).json()
    perms = {p["permission"]: p for p in c["permissions"]}
    assert perms["resourcemanager.projects.getIamPolicy"]["write"] is False
    assert perms["resourcemanager.projects.setIamPolicy"]["write"] is True


# ====================================================================== render
def intents():
    return [Intent.model_validate(x) for x in setup_intents()]


def test_render_each_setup_kind():
    res = render(intents(), ENV)
    items = {i.intent_id: i for i in res.items}
    t = items["tmpl"]
    assert "gcloud model-armor templates create corp-shield" in t.outputs.gcloud
    assert "CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR=https://modelarmor.europe-west4.rep.googleapis.com/" in \
        t.outputs.gcloud
    assert "--pi-and-jailbreak-filter-settings-confidence-level=high" in t.outputs.gcloud
    assert "--basic-config-filter-enforcement=enabled" in t.outputs.gcloud
    assert '"filterType":"HATE_SPEECH"' in t.outputs.gcloud and "DANGEROUS" not in t.outputs.gcloud
    assert f"modelarmor.{F.R}.rep.googleapis.com/v1/projects/{F.P}/locations/{F.R}/templates?templateId=corp-shield" \
        in t.outputs.rest
    assert 'resource "google_model_armor_template"' in t.outputs.terraform
    assert "create_template(" in t.outputs.python and "True" in t.outputs.python
    assert any("Prompt injection" in n for n in t.anatomy.notes)
    x = items["ext"]
    assert "gcloud service-extensions authz-extensions import corp-ma-authz" in x.outputs.gcloud
    assert f"service: modelarmor.{F.R}.rep.googleapis.com" in x.outputs.gcloud
    assert f"authzExtensions?authzExtensionId=corp-ma-authz" in x.outputs.rest
    assert "jsonencode(" in x.outputs.terraform and TNAME in x.outputs.terraform
    assert any("earlier item" in n for n in x.anatomy.notes)
    i = items["iam"]
    assert i.outputs.gcloud.count("gcloud projects add-iam-policy-binding") == 3
    assert f"--member=serviceAccount:{F.DEP_SA}" in i.outputs.gcloud
    assert "for_each = toset(" in i.outputs.terraform and "google_project_iam_member" in i.outputs.terraform
    assert "grant_project_roles(" in i.outputs.python
    for it in (t, x, i):
        assert not it.warnings, it.warnings
        check_syntax(it)


def test_model_armor_on_uses_staged_extension_without_warning():
    res = render(intents(), ENV)
    on = next(i for i in res.items if i.intent_id == "on")
    assert not on.warnings and "MODEL_ARMOR_EXTENSION" not in on.outputs.terraform
    assert XNAME in on.outputs.rest and any("earlier item" in n for n in on.anatomy.notes)
    alone = render([Intent(id="x", kind="model_armor_on", gateway=GatewayRef(name="corp-out"))], ENV).items[0]
    assert any("MODEL_ARMOR_EXTENSION" in w and "isn't set up" in w for w in alone.warnings)


def test_bundle_order_and_terraform(tmp_path):
    res = render(intents() + [Intent(id="on2", kind="model_armor_on",
                                     gateway=GatewayRef(name="corp-in", direction="ingress"))], ENV)
    sh = res.bundle.gcloud
    i = [sh.index(s) for s in ("model-armor templates create", "authz-extensions import",
                               "projects add-iam-policy-binding", "authz-policies import")]
    assert i == sorted(i)
    for text in (res.bundle.gcloud, res.bundle.rest):
        assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0
    compile(res.bundle.python, "<bundle>", "exec")
    main = res.bundle.terraform["main.tf"]
    assert main.index("google_model_armor_template") < main.index("google_network_services_authz_extension") < \
        main.index("google_project_iam_member") < main.index("google_network_security_authz_policy")
    assert "depends_on = [google_model_armor_template.ma_template_corp_shield]" in main
    assert ("depends_on = [google_network_services_authz_extension.ma_extension_corp_ma_authz, "
            "google_project_iam_member.ma_roles_service_9090]") in main
    if TERRAFORM:
        for k, v in res.bundle.terraform.items():
            (tmp_path / k).write_text(v)
        r = subprocess.run([TERRAFORM, "fmt", "-check", "-diff", str(tmp_path)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout
        if os.environ.get("STUDIO_TF_VALIDATE"):
            assert subprocess.run([TERRAFORM, "init", "-backend=false", "-input=false"], cwd=tmp_path,
                                  capture_output=True).returncode == 0
            r = subprocess.run([TERRAFORM, "validate"], cwd=tmp_path, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr


def test_delete_variants_and_warnings():
    res = render([
        Intent(id="dt", kind="model_armor_template", params=SetupParams(template_id="corp-shield", delete=True)),
        Intent(id="dx", kind="model_armor_extension", params=SetupParams(name="corp-ma-authz", delete=True)),
        Intent(id="di", kind="iam_project_grant", params=SetupParams(member=F.DEP_SA, roles=ma.MA_ROLES[:1],
                                                                     delete=True)),
        Intent(id="off", kind="model_armor_off", gateway=GatewayRef(name="corp-in", direction="ingress",
                                                                    policy="corp-in-ma")),
    ], ENV)
    items = {i.intent_id: i for i in res.items}
    assert "templates delete corp-shield" in items["dt"].outputs.gcloud
    assert "authz-extensions delete corp-ma-authz" in items["dx"].outputs.gcloud
    assert "remove-iam-policy-binding" in items["di"].outputs.gcloud
    for it in items.values():
        check_syntax(it)
    sh = res.bundle.gcloud
    i = [sh.index(s) for s in ("authz-policies delete", "remove-iam-policy-binding", "authz-extensions delete",
                               "templates delete")]
    assert i == sorted(i)
    bad = render([Intent(id="b", kind="iam_project_grant", params=SetupParams(member="x@y.iam.gserviceaccount.com",
                                                                              roles=["roles/owner"])),
                  Intent(id="a", kind="model_armor_template", params=SetupParams(
                      template_id="t", filters=TemplateFilters(sdp="advanced")))], ENV).items
    assert any("refuses roles/owner" in w for w in bad[0].warnings)
    assert any("INSPECT_TEMPLATE" in w for w in bad[1].warnings)


# ====================================================================== writer guard
def test_writer_allows_setup_urls_only():
    base = f"https://modelarmor.{F.R}.rep.googleapis.com/v1/projects/{F.P}/locations/{F.R}/templates"
    assert allowed("POST", f"{base}?templateId=t1") and allowed("DELETE", f"{base}/t1")
    assert not allowed("PATCH", f"{base}/t1")
    ns = f"https://networkservices.googleapis.com/v1/projects/{F.P}/locations/{F.R}/authzExtensions"
    assert allowed("POST", f"{ns}?authzExtensionId=x") and allowed("DELETE", f"{ns}/x")
    assert not allowed("PATCH", f"{ns}/x")
    assert not allowed("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{F.P}:setIamPolicy")


def test_project_policy_guard():
    old = json.loads(json.dumps(F.PROJECT_POLICY))
    ok = json.loads(json.dumps(old))
    ok["bindings"].append({"role": "roles/modelarmor.user", "members": ["serviceAccount:z@x.iam.gserviceaccount.com"]})
    check_project_policy_change(old, ok)
    for mutate in (lambda p: p["bindings"].append({"role": "roles/owner", "members": ["user:eve@x.com"]}),
                   lambda p: p["bindings"][3]["members"].append("user:eve@x.com"),          # conditional MA binding
                   lambda p: p.update(etag="other"),
                   lambda p: p.update(auditConfigs=[{"service": "allServices"}])):
        bad = json.loads(json.dumps(old))
        mutate(bad)
        with pytest.raises(ValueError):
            check_project_policy_change(old, bad)
    g = F.FakeWriteGcp()
    w = Writer(g)
    with pytest.raises(ValueError):             # the generic IAP method can't reach the project policy
        w.set_iam_policy(f"https://cloudresourcemanager.googleapis.com/v1/projects/{F.P}", ok)
    assert not g.writes


# ====================================================================== apply
@pytest.fixture
def gcp(monkeypatch):
    g = F.FakeWriteGcp(op_polls=2)
    g.extensions = {k: v for k, v in g.extensions.items() if v["service"] == "iap.googleapis.com"}
    g.policies = {k: v for k, v in g.policies.items() if v["policyProfile"] != "CONTENT_AUTHZ"}
    g.templates = {}
    monkeypatch.setattr(service, "rest_for", lambda ctx: g)
    monkeypatch.setenv("STUDIO_APPLY_POLL", "0")
    monkeypatch.setattr(auth, "load_adc", lambda: (user_creds.Credentials(token="t", quota_project_id=F.P), F.P))
    monkeypatch.setattr(auth, "refresh", lambda c: None)
    monkeypatch.setattr(auth, "tokeninfo_email", lambda c: "alice@example.com")
    monkeypatch.setattr(auth, "gcloud_info", lambda: {"available": True, "account": "alice@example.com",
                                                      "project": F.P})
    return g


def run(intents, ack=False):
    client = TestClient(create_app())
    r = client.post("/api/studio/apply", json={"context": {"project": F.P, "region": F.R}, "intents": intents,
                                               "confirm": {"project": F.P, "acknowledge_destructive": ack}})
    assert r.status_code == 200, r.text
    events = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    final = {e["intent_id"]: e for e in events if "intent_id" in e and not e.get("progress") and e["intent_id"]}
    return events, final


def test_apply_full_setup_in_order_then_undo(gcp):
    events, f = run(setup_intents())
    assert {k: v["state"] for k, v in f.items()} == {"tmpl": "verified", "ext": "verified", "iam": "verified",
                                                    "on": "verified"}, f
    kinds = [(m, u.split("/v1/", 1)[0]) for m, u, _ in gcp.writes]
    assert [m for m, _ in kinds] == ["POST", "POST", "POST", "POST"]
    assert "modelarmor" in gcp.writes[0][1] and "authzExtensions" in gcp.writes[1][1]
    assert gcp.writes[2][1].endswith(f"/projects/{F.P}:setIamPolicy") and "authzPolicies" in gcp.writes[3][1]
    assert gcp.templates[TNAME]["filterConfig"]["piAndJailbreakFilterSettings"]["confidenceLevel"] == "HIGH"
    assert gcp.writes[3][2]["customProvider"]["authzExtension"]["resources"] == [XNAME]
    assert ma.roles_of(gcp.project_policy, F.DEP_SA) == dict.fromkeys(ma.MA_ROLES, True)
    # only the missing role was added; the conditional binding and owner are untouched
    assert f["iam"]["undo"]["params"]["roles"] == ["roles/serviceusage.serviceUsageConsumer"]
    assert {"role": "roles/owner", "members": ["user:alice@example.com"]} in gcp.project_policy["bindings"]
    undo = [f[k]["undo"] for k in ("tmpl", "ext", "iam", "on")]
    assert all(u["params"]["delete"] for u in undo[:3]) and undo[3]["kind"] == "model_armor_off"
    r = TestClient(create_app()).post("/api/studio/apply", json={
        "context": {"project": F.P, "region": F.R}, "intents": undo, "confirm": {"project": F.P}})
    assert r.status_code == 400 and "acknowledge_destructive" in r.json()["detail"]
    _, f2 = run(undo, ack=True)
    assert all(v["state"] == "verified" for v in f2.values()), f2
    assert TNAME not in gcp.templates and "corp-ma-authz" not in gcp.extensions
    assert ma.roles_of(gcp.project_policy, F.DEP_SA)["roles/serviceusage.serviceUsageConsumer"] is False
    assert ma.roles_of(gcp.project_policy, F.DEP_SA)["roles/modelarmor.user"] is True


def test_apply_setup_skips_existing_and_refuses_other_roles(gcp):
    run(setup_intents()[1:])
    n = len(gcp.writes)
    _, f = run(setup_intents()[1:])
    assert {v["state"] for v in f.values()} == {"skipped"} and len(gcp.writes) == n
    _, f = run([{"id": "x", "kind": "iam_project_grant", "params": {"member": F.DEP_SA, "roles": ["roles/owner"]}}])
    assert f["x"]["state"] == "failed" and len(gcp.writes) == n


def test_apply_model_armor_on_without_extension_fails_clearly(gcp):
    _, f = run([{"id": "on", "kind": "model_armor_on", "gateway": {"name": "corp-out", "direction": "egress"}}])
    assert f["on"]["state"] == "failed" and "isn't set up" in f["on"]["detail"] and not gcp.writes


def test_apply_on_skipped_when_extension_create_fails(gcp):
    gcp.fail = {"authzExtensionId=": 403}
    _, f = run(setup_intents())
    assert f["ext"]["state"] == "failed" and f["on"]["state"] == "skipped"


def test_generate_mode_never_writes(gcp, monkeypatch):
    monkeypatch.setenv("STUDIO_MODE", "generate")
    r = TestClient(create_app()).post("/api/studio/apply", json={
        "context": {"project": F.P, "region": F.R}, "intents": setup_intents(), "confirm": {"project": F.P}})
    assert r.status_code == 403 and not gcp.writes


def test_diff_setup(read_client):
    c = read_client()
    d = c.post("/api/studio/diff", json={"context": Q, "intents": setup_intents() + [
        {"id": "have", "kind": "model_armor_template", "params": {"template_id": "strict"}}]}).json()
    st = {i["intent_id"]: (i["status"], i["detail"]) for i in d["items"]}
    assert st["tmpl"][0] == "add" and st["have"][0] == "present" and st["ext"][0] == "add"
    assert st["iam"] == ("add", "will grant roles/serviceusage.serviceUsageConsumer")
