"""Agent Registry entries (registry_service): discovery of Services, render, preflight, diff, writer guard, Apply
(create + a grant on the new entry in one request, delete), read-back and undo, against the stateful fake GCP."""
import json
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient
from google.oauth2 import credentials as user_creds

import fakegcp as F
from policy_studio import preflight as pf, service
from policy_studio.app import create_app
from policy_studio.gcp import auth, registry as reg_mod
from policy_studio.gcp.writer import Writer, allowed, check_service_body
from policy_studio.model import Context, Intent
from policy_studio.render import RenderEnv, render

TERRAFORM = shutil.which("terraform") or ("/opt/homebrew/bin/terraform"
                                          if os.path.exists("/opt/homebrew/bin/terraform") else None)
CTX = {"project": F.P, "region": F.R}
Q = {"project": F.P, "region": F.R}
RUN_A = "https://notes-mcp-4242.europe-west4.run.app/mcp"
RUN_B = "https://notes-mcp-abc123xyz-ez.a.run.app/mcp"
SVC_BASE = f"https://agentregistry.googleapis.com/v1/projects/{F.P}/locations/{F.R}/services"


def create(sid="notes-mcp", urls=(RUN_A, RUN_B), kind="mcp_server", binding="JSONRPC", iid="reg", **extra):
    return {"id": iid, "kind": "registry_service", "params": {
        "kind": kind, "service_id": sid, "display_name": "Notes MCP", "description": "team notes",
        "interfaces": [{"url": u, "protocol_binding": binding} for u in urls], **extra}}


def grant_new(sid="notes-mcp", mode="all", iid="g"):
    return {"id": iid, "kind": "grant", "source": {"type": "engine", "principal": F.principal("111"),
                                                   "label": "HR Assistant", "engine": F.E1},
            "destination": {"kind": "mcp_server", "id": "", "name": "", "label": "Notes MCP",
                            "pending_service": sid},
            "access": {"mode": mode}}


def delete(sid="weather-api", kind="endpoint", iid="del"):
    return {"id": iid, "kind": "registry_service", "params": {"kind": kind, "service_id": sid, "delete": True}}


def check_syntax(outputs):
    for k in ("gcloud", "rest"):
        r = subprocess.run(["bash", "-n"], input=outputs[k], capture_output=True, text=True)
        assert r.returncode == 0, (k, r.stderr, outputs[k])
    compile(outputs["python"], "<python>", "exec")
    if TERRAFORM:
        r = subprocess.run([TERRAFORM, "fmt", "-check", "-"], input=outputs["terraform"], capture_output=True,
                           text=True)
        assert r.returncode == 0, outputs["terraform"]


# ====================================================================== fixtures
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


@pytest.fixture
def client(gcp):
    return TestClient(create_app())


def run(intents, ack=False, region=F.R):
    r = TestClient(create_app()).post("/api/studio/apply", json={
        "context": {"project": F.P, "region": region}, "intents": intents,
        "confirm": {"project": F.P, "acknowledge_destructive": ack}})
    assert r.status_code == 200, r.text
    events = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    final = {e["intent_id"]: e for e in events if "intent_id" in e and not e.get("progress") and e["intent_id"]}
    return events, final


def preflight(client, intents, region=F.R):
    r = client.post("/api/studio/preflight", json={"context": {"project": F.P, "region": region}, "intents": intents})
    assert r.status_code == 200, r.text
    return {i["intent_id"]: i for i in r.json()["items"]}


# ====================================================================== discovery
def test_inventory_lists_services_and_links_entries(client):
    inv = client.get("/api/studio/inventory", params=Q).json()
    svcs = {s["id"]: s for s in inv["services"]}
    assert set(svcs) == {"tickets-mcp", "weather-api"}
    assert svcs["tickets-mcp"]["kind"] == "mcp_server" and svcs["tickets-mcp"]["tool_spec"]["tools"]
    assert svcs["weather-api"]["interfaces"] == [{"url": "https://api.weather.example", "protocol_binding": "HTTP_JSON"}]
    mcp = {m["id"]: m for m in inv["mcp_servers"]}
    assert mcp["agentregistry-mcp"]["service"] == F.SVC_TICKETS
    assert mcp["agentregistry-ro"]["service"] is None                  # auto-registered: no Service to delete
    assert mcp["agentregistry-mcp"]["urls"] == ["https://tickets.example.com/mcp"]
    assert inv["endpoints"][0]["service"] == F.SVC_WEATHER


def test_url_helpers():
    assert reg_mod.url_problem("https://x.example/mcp") is None
    assert "https" in reg_mod.url_problem("http://x.example")
    assert "wildcard" in reg_mod.url_problem("https://*.example.com")
    assert "host" in reg_mod.url_problem("https:///path")
    assert reg_mod.norm_url("HTTPS://X.Example/mcp/") == "https://x.example/mcp"
    assert reg_mod.run_app_form(RUN_A) == "number" and reg_mod.run_app_form(RUN_B) == "hash"
    assert reg_mod.run_app_form("https://x.example") is None
    assert reg_mod.run_app_hint([RUN_A, RUN_B]) is None
    assert "other run.app URL shown on the Cloud Run page" in reg_mod.run_app_hint([RUN_A])
    assert reg_mod.SERVICE_ID_RE.match("notes-mcp") and reg_mod.SERVICE_ID_RE.match("plat-telemetry-443")
    assert not any(reg_mod.SERVICE_ID_RE.match(x) for x in ("abc", "Notes", "1abc", "abc-", "a_bc", "x" * 64))


# ====================================================================== render
def test_render_create_all_outputs(client):
    r = client.post("/api/studio/render", json={"context": CTX, "intents": [create()]}).json()
    it = r["items"][0]
    assert not it.get("error"), it
    o = it["outputs"]
    assert it["english"].startswith("Register MCP server Notes MCP (notes-mcp) in Agent Registry, at 2 URLs")
    assert "gcloud agent-registry services create notes-mcp" in o["gcloud"]
    assert o["gcloud"].count("--interfaces=") == 2 and "--mcp-server-spec-type=no-spec" in o["gcloud"]
    assert f"protocolBinding=jsonrpc,url={RUN_A}" in o["gcloud"]
    assert f"{SVC_BASE}?serviceId=notes-mcp" in o["rest"] and '"mcpServerSpec":{"type":"NO_SPEC"}' in o["rest"]
    assert 'resource "google_agent_registry_service" "registry_notes_mcp"' in o["terraform"]
    assert o["terraform"].count("interfaces {") == 2 and 'type = "NO_SPEC"' in o["terraform"]
    assert "create_registry_service(" in o["python"]
    assert any("tool conditions" in n for n in it["anatomy"]["notes"])
    assert not [w for w in it["warnings"] if not w.startswith("(lookup)")], it["warnings"]
    check_syntax(o)


def test_render_endpoint_and_delete(client):
    r = client.post("/api/studio/render", json={"context": CTX, "intents": [
        create("orders-api", ["https://orders.example.com/v1"], kind="endpoint", binding="HTTP_JSON"),
        delete()]}).json()
    ep, de = r["items"]
    assert "--endpoint-spec-type=no-spec" in ep["outputs"]["gcloud"]
    assert "protocolBinding=http-json" in ep["outputs"]["gcloud"]
    assert "endpoint_spec {" in ep["outputs"]["terraform"]
    assert de["english"].startswith("Delete the Agent Registry API endpoint Weather API (weather-api)")
    assert "gcloud agent-registry services delete weather-api" in de["outputs"]["gcloud"]
    assert f"-X DELETE {SVC_BASE}/weather-api" in de["outputs"]["rest"]
    assert all(ln.startswith("#") for ln in de["outputs"]["terraform"].splitlines() if ln.strip())
    assert any("don't come back" in w for w in de["warnings"])
    assert any("grants" in n and "1 today" in n for n in de["anatomy"]["notes"])
    for x in (ep, de):
        check_syntax(x["outputs"])


def test_render_create_plus_grant_bundle(client, tmp_path):
    r = client.post("/api/studio/render", json={"context": CTX, "intents": [grant_new(), create()]}).json()
    g, c = r["items"]
    assert not g.get("error") and not c.get("error")
    var = "ENTRY_NOTES_MCP"
    assert f'--mcp-server="${var}"' in g["outputs"]["gcloud"]
    assert "gcloud agent-registry services describe notes-mcp" in g["outputs"]["gcloud"]
    assert f'RESOURCE="https://iap.googleapis.com/v1/projects/{F.N}/locations/{F.R}/iap_web/agentRegistry/' \
           f'mcpServers/${{{var}}}"' in g["outputs"]["rest"]
    assert "registry_entry_id(" in g["outputs"]["python"]
    assert "mcp_server_id = basename(google_agent_registry_service.registry_notes_mcp.registry_resource)" in \
        g["outputs"]["terraform"]
    assert any("created by the registry_service item for notes-mcp" in n for n in g["anatomy"]["notes"])
    check_syntax(g["outputs"])
    b = r["bundle"]
    sh = b["gcloud"]
    assert sh.index("services create notes-mcp") < sh.index("services describe notes-mcp") < \
        sh.index("add-iam-policy-binding")
    for text in (b["gcloud"], b["rest"]):
        assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0
    compile(b["python"], "<bundle>", "exec")
    main = b["terraform"]["main.tf"]
    assert 'version = ">= 8.6.0"' in main and main.index("google_agent_registry_service") < main.index(
        "google_iap_agent_registry_mcp_server_iam_member")
    if TERRAFORM:
        for k, v in b["terraform"].items():
            (tmp_path / k).write_text(v)
        rr = subprocess.run([TERRAFORM, "fmt", "-check", "-diff", str(tmp_path)], capture_output=True, text=True)
        assert rr.returncode == 0, rr.stdout
        if os.environ.get("STUDIO_TF_VALIDATE"):
            assert subprocess.run([TERRAFORM, "init", "-backend=false", "-input=false"], cwd=tmp_path,
                                  capture_output=True).returncode == 0
            rr = subprocess.run([TERRAFORM, "validate"], cwd=tmp_path, capture_output=True, text=True)
            assert rr.returncode == 0, rr.stdout + rr.stderr


def test_render_warns_read_only_on_a_new_mcp_without_tools():
    env = RenderEnv(ctx=Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N))
    res = render([Intent.model_validate(create()), Intent.model_validate(grant_new(mode="read_only_hint"))], env)
    assert any("without a tool list" in w for w in res.items[1].warnings)
    tools = {"tools": [{"name": "read_note", "annotations": {"readOnlyHint": True}}]}
    res = render([Intent.model_validate(create(tool_spec=tools)),
                  Intent.model_validate(grant_new(mode="read_only_hint"))], env)
    assert not any("without a tool list" in w for w in res.items[1].warnings)
    assert '"type":"TOOL_SPEC"' in res.items[0].outputs.rest and "--mcp-server-spec-type=tool-spec" in \
        res.items[0].outputs.gcloud
    for item in res.items:
        check_syntax(item.outputs.model_dump())


def test_render_a2a_is_out_of_scope():
    env = RenderEnv(ctx=Context(project=F.P, region=F.R))
    item = render([Intent.model_validate(create(kind="agent"))], env).items[0]
    assert item.error and "agent card" in item.error


def modify_new(sid="notes-mcp", froms=({"mode": "all"},), tos=({"mode": "read_only_hint"},), iid="m"):
    """Change access on an entry registered in the same cart (one binding -> one binding, or several)."""
    g = grant_new(sid=sid, iid=iid)
    g.pop("access")
    if len(froms) == 1 and len(tos) == 1:
        return {**g, "kind": "modify", "access_from": froms[0], "access": tos[0]}
    return {**g, "kind": "modify", "access_from_list": list(froms), "access_list": list(tos)}


@pytest.mark.parametrize("multi", [False, True])
def test_render_modify_on_a_new_entry(multi):
    """modify on a pending entry: every format looks the entry id up (no ENTRY_ID placeholder), and the Python
    defines both registry_entry_id() and modify()/modify_many(), alone and in the bundle."""
    env = RenderEnv(ctx=Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N))
    m = modify_new(froms=({"mode": "all"}, {"mode": "read_only_hint"}), tos=({"mode": "tools", "tools": ["a"]},)) \
        if multi else modify_new()
    res = render([Intent.model_validate(create()), Intent.model_validate(m)], env)
    item = res.items[1]
    assert not item.error, item.error
    o = item.outputs
    fn = "modify_many" if multi else "modify"
    var = "ENTRY_NOTES_MCP"
    assert "ENTRY_ID" not in o.gcloud and f'--mcp-server="${var}"' in o.gcloud
    assert o.gcloud.index("services describe notes-mcp") < o.gcloud.index("get-iam-policy")
    assert f'RESOURCE="https://iap.googleapis.com/v1/projects/{F.N}/locations/{F.R}/iap_web/agentRegistry/' \
           f'mcpServers/${{{var}}}"' in o.rest
    assert "registry_resource" in o.terraform and "ENTRY_ID" not in o.terraform
    for py in (o.python, res.bundle.python):
        code = compile(py, "<python>", "exec")
        names = set(code.co_names)
        assert {fn, "registry_entry_id"} <= names
        assert f"def {fn}(" in py and "def registry_entry_id(" in py and "def _get_policy(" in py
        assert py.count("def registry_entry_id(") == 1 and py.count(f"def {fn}(") == 1
    assert "registry_entry_id(" in o.python.split(f"{fn}(\n")[-1]
    check_syntax(o.model_dump())
    for text in (res.bundle.gcloud, res.bundle.rest):
        assert "ENTRY_ID" not in text.replace("ENTRY_NOTES_MCP", "")
        assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0


def test_render_pending_lookup_uses_the_service_project():
    """A registry_service created in its own project (params.project): the entry id is looked up there."""
    env = RenderEnv(ctx=Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N))
    res = render([Intent.model_validate(create(project="other-proj")), Intent.model_validate(grant_new()),
                  Intent.model_validate(modify_new(iid="m"))], env)
    for item in res.items[1:]:
        o = item.outputs
        assert "services describe notes-mcp --project=other-proj" in o.gcloud
        assert "/projects/other-proj/locations/" in o.rest
        assert 'registry_entry_id("other-proj"' in o.python


# ====================================================================== preflight
@pytest.mark.parametrize("intent,why", [
    (create(urls=["https://tickets.example.com/mcp/"]), "Duplicate: https://tickets.example.com/mcp/ is already "
                                                       "registered in europe-west4 as Tickets MCP"),
    (create(urls=["http://notes.example.com"]), "isn't https"),
    (create(urls=["https://*.example.com"]), "wildcard"),
    (create(urls=[RUN_A, RUN_A]), "listed twice"),
    (create(urls=[]), "at least one URL"),
    (create(sid="tickets-mcp"), "already exists"),
    (create(sid="Bad_Id"), "isn't valid"),
    (create(binding="REST"), "must be one of"),
    (create(kind="agent"), "agent card"),
    (delete(sid="no-such-entry"), "no registry entry no-such-entry"),
])
def test_preflight_blocks(client, intent, why):
    item = preflight(client, [intent])[intent["id"]]
    assert item["status"] == "blocked" and why in item["reason"], item


def test_preflight_wrong_region_and_pending_grant(client):
    item = preflight(client, [create()], region="us")["reg"]
    assert item["status"] == "blocked" and "single region" in item["reason"]
    items = preflight(client, [grant_new(sid="not-staged")])
    assert items["g"]["status"] == "blocked" and "isn't registered by an item" in items["g"]["reason"]
    items = preflight(client, [create(urls=["http://x.example"]), grant_new()])
    assert items["g"]["status"] == "blocked" and items["g"]["reason"].startswith("Not attempted")
    items = preflight(client, [create(), grant_new()])
    assert items["reg"]["status"] == "ok" and items["g"]["status"] == "ok"
    # two staged entries can't both register one URL
    items = preflight(client, [create(), create(sid="notes-two", iid="reg2", urls=[RUN_B])])
    assert items["reg2"]["status"] == "blocked" and "also registered by notes-mcp" in items["reg2"]["reason"]


def test_preflight_warnings(client):
    items = preflight(client, [create(urls=[RUN_A]), delete()])
    assert items["reg"]["status"] == "ok" and "also register the other run.app URL" in items["reg"]["warning"]
    assert items["del"]["status"] == "ok" and items["del"]["warning"].startswith("1 grant on this entry will be "
                                                                                "removed")
    env = RenderEnv(ctx=Context(project=F.P, region=F.R), registry=[reg_mod.parse_service(
        {"name": f"projects/{F.P}/locations/{F.R}/services/plat-trace", "displayName": "Trace",
         "interfaces": [{"url": "https://cloudtrace.googleapis.com", "protocolBinding": "HTTP_JSON"}],
         "endpointSpec": {"type": "NO_SPEC"}})])
    w = pf.advisories([Intent.model_validate(delete(sid="plat-trace"))], env)["del"]
    assert "Google API" in w and "lose access" in w


def test_diff(client):
    r = client.post("/api/studio/diff", json={"context": CTX, "intents": [create(), grant_new(), delete()]}).json()
    c, g, d = r["items"]
    assert c["status"] == "add" and "2 URLs" in c["detail"]
    assert g["status"] == "add" and "new entry notes-mcp" in g["detail"] and g["after"]
    assert d["status"] == "remove" and "1 grant goes with it" in d["detail"] and "don't come back" in d["detail"]
    assert len(d["current"]) == 1 and d["after"] == []


# ====================================================================== writer
def test_writer_allowlist_and_body_guard(gcp):
    assert allowed("POST", f"{SVC_BASE}?serviceId=notes-mcp")
    assert allowed("DELETE", f"{SVC_BASE}/notes-mcp")
    assert not allowed("PATCH", f"{SVC_BASE}/notes-mcp?updateMask=interfaces")
    assert not allowed("POST", f"{SVC_BASE}")
    assert not allowed("DELETE", f"https://agentregistry.googleapis.com/v1/projects/{F.P}/locations/{F.R}/"
                                 "mcpServers/agentregistry-mcp")
    good = reg_mod.service_body("mcp_server", "Notes", [{"url": RUN_A, "protocol_binding": "JSONRPC"}])
    check_service_body(good)
    for bad in ({**good, "agentSpec": {"type": "NO_SPEC"}},
                {**good, "registryResource": "x"},
                {**good, "interfaces": [{"url": "http://x", "protocolBinding": "JSONRPC"}]},
                {**good, "interfaces": [{"url": RUN_A, "protocolBinding": "SOAP"}]},
                {**good, "interfaces": []},
                {"displayName": "x", "interfaces": good["interfaces"]},
                {**good, "mcpServerSpec": {"type": "NO_SPEC", "content": {"tools": []}}},
                {k: v for k, v in good.items() if k != "mcpServerSpec"} | {"endpointSpec": {"type": "TOOL_SPEC"}}):
        with pytest.raises(ValueError):
            check_service_body(bad)
    w = Writer(gcp)
    with pytest.raises(ValueError):
        w.create_registry_service(f"{SVC_BASE}?serviceId=x1x1", {**good, "name": "x"})
    assert not gcp.writes


def test_auth_lists_the_registry_kind():
    assert auth.WRITE_PERMISSIONS["registry_service"][0] == ["agentregistry.services.create",
                                                             "agentregistry.services.delete"]
    assert auth.WRITE_PERMISSIONS["registry_service"][3] == "roles/agentregistry.editor"


# ====================================================================== apply
def test_apply_create_plus_grant_then_undo_round_trip(gcp):
    gcp.projection_lag = 2                         # registryResource shows up on the third GET
    events, f = run([grant_new(), create()])       # the grant is first in the cart: create still runs first
    assert f["reg"]["state"] == "verified" and f["g"]["state"] == "verified", f
    assert "registered with 2 URLs" in f["reg"]["detail"] and "agentregistry-notes-mcp" in f["reg"]["detail"]
    order = [e["intent_id"] for e in events if e.get("state") == "running"]
    assert order.index("reg") < order.index("g")
    method, url, body = gcp.writes[0]
    assert method == "POST" and url == f"{SVC_BASE}?serviceId=notes-mcp"
    assert body["interfaces"] == [{"url": RUN_A, "protocolBinding": "JSONRPC"},
                                  {"url": RUN_B, "protocolBinding": "JSONRPC"}]
    assert body["mcpServerSpec"] == {"type": "NO_SPEC"}
    assert gcp.writes[1][1].endswith("/iap_web/agentRegistry/mcpServers/agentregistry-notes-mcp:setIamPolicy")
    pol = gcp.iap["mcpServers/agentregistry-notes-mcp"]
    assert pol["bindings"] == [{"role": "roles/iap.egressor", "members": [F.principal("111")]}]
    # undo: the grant's undo names the real entry; the create's undo is a delete (destructive)
    ug, ur = f["g"]["undo"], f["reg"]["undo"]
    assert ug["kind"] == "revoke" and ug["destination"]["id"] == "agentregistry-notes-mcp"
    assert "pending_service" not in ug["destination"]
    assert ur["params"]["delete"] is True and ur["params"]["service_id"] == "notes-mcp"
    r = TestClient(create_app()).post("/api/studio/apply", json={
        "context": CTX, "intents": [ur, ug], "confirm": {"project": F.P}})
    assert r.status_code == 400 and "acknowledge_destructive" in r.json()["detail"]
    events, f2 = run([ur, ug], ack=True)
    assert f2[ug["id"]]["state"] == "verified" and f2[ur["id"]]["state"] == "verified", f2
    order = [e["intent_id"] for e in events if e.get("state") == "running"]
    assert order.index(ug["id"]) < order.index(ur["id"])          # revoke first, delete last
    assert "notes-mcp" not in gcp.services and "gone (not found)" in f2[ur["id"]]["detail"]
    # undo of the delete registers it again with the same body (a new entry, no grants)
    again = f2[ur["id"]]["undo"]
    assert again["params"]["delete"] is False and len(again["params"]["interfaces"]) == 2
    _, f3 = run([again])
    assert f3[again["id"]]["state"] == "verified"
    assert gcp.services["notes-mcp"]["interfaces"] == body["interfaces"]


def test_apply_delete_existing_reads_body_for_undo(gcp):
    before = json.loads(json.dumps(gcp.services["tickets-mcp"]))
    _, f = run([delete(sid="tickets-mcp", kind="mcp_server")], ack=True)
    assert f["del"]["state"] == "verified", f
    assert "tickets-mcp" not in gcp.services and "mcpServers/agentregistry-mcp" not in gcp.iap
    undo = f["del"]["undo"]["params"]
    assert undo["tool_spec"] == before["mcpServerSpec"]["content"] and undo["description"] == "ticketing"
    _, f2 = run([f["del"]["undo"]])
    assert f2["undo-del"]["state"] == "verified"
    svc = gcp.services["tickets-mcp"]
    assert svc["mcpServerSpec"] == before["mcpServerSpec"] and svc["interfaces"] == before["interfaces"]
    assert svc["registryResource"] != before["registryResource"]            # a new entry: grants don't come back


def test_apply_delete_needs_ack_and_create_failure_skips_grant(gcp):
    r = TestClient(create_app()).post("/api/studio/apply", json={
        "context": CTX, "intents": [delete()], "confirm": {"project": F.P}})
    assert r.status_code == 400
    gcp.fail = {"services?serviceId=": 500}
    _, f = run([create(), grant_new()])
    assert f["reg"]["state"] == "failed" and f["g"]["state"] == "skipped"
    assert "wasn't registered" in f["g"]["detail"]


def test_apply_blocked_duplicate_writes_nothing(gcp):
    _, f = run([create(urls=["https://api.weather.example"])])
    assert f["reg"]["state"] == "failed" and f["reg"].get("blocked") and "Duplicate" in f["reg"]["detail"]
    assert not gcp.writes


def test_apply_skips_existing_same_body(gcp):
    _, f = run([create(sid="weather-api", kind="endpoint", urls=["https://api.weather.example"],
                       binding="HTTP_JSON")])
    # preflight blocks an id that exists
    assert f["reg"]["state"] == "failed" and "already exists" in f["reg"]["detail"]
    assert not gcp.writes
