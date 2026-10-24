import pytest
from fastapi.testclient import TestClient

import fakegcp as F
from policy_studio import service
from policy_studio.app import create_app


@pytest.fixture
def fake(monkeypatch):
    rest = F.FakeRest()
    monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
    monkeypatch.setenv("STUDIO_PROJECT", F.P)
    monkeypatch.setenv("STUDIO_REGION", F.R)
    return rest


@pytest.fixture
def client(fake):
    return TestClient(create_app())


Q = {"project": F.P, "region": F.R}


def test_health_and_defaults(client):
    assert client.get("/api/studio/health").json()["ok"] is True
    assert client.get("/api/studio/defaults").json() == {"project": F.P, "region": F.R}


def test_context(client):
    c = client.get("/api/studio/context", params=Q).json()
    assert c["project_number"] == F.N and c["gateway_project"] == F.P and c["can_apply"] is False
    assert c["principal"] == "alice@example.com"
    assert c["apis"]["networkservices.googleapis.com"] is True and c["apis"]["modelarmor.googleapis.com"] is False
    perms = {p["permission"]: p for p in c["permissions"]}
    assert perms["networkservices.agentGateways.list"]["granted"] is True
    w = perms["iap.webServiceVersions.setIamPolicy"]
    assert w["granted"] is False and w["write"] is True
    assert w["fix"] == f"gcloud projects add-iam-policy-binding {F.P} --member='user:alice@example.com' --role=roles/iap.admin"


def test_gateways(client):
    g = client.get("/api/studio/gateways", params=Q).json()
    by = {x["id"]: x for x in g["gateways"]}
    eg, ig = by["corp-out"], by["corp-in"]
    assert eg["type"] == "egress" and ig["type"] == "ingress"
    assert eg["authz_policies"][0]["provider"] == "iap" and eg["authz_policies"][0]["enforcement"] == "DRY_RUN"
    assert ig["authz_policies"][0]["provider"] == "model_armor"
    assert [b["display_name"] for b in eg["bound_engines"]] == ["HR Assistant"]
    assert g["notes"]


def test_model_armor(client):
    m = client.get("/api/studio/model-armor", params=Q).json()
    rows = {r["gateway"].rsplit("/", 1)[-1]: r for r in m["gateways"]}
    assert rows["corp-out"]["enabled"] is False and rows["corp-out"]["available_extensions"]
    t = rows["corp-in"]["template"]
    assert t["id"] == "strict" and t["filters"]["pi_jailbreak"] == {"enabled": True, "level": "HIGH"}
    assert t["filters"]["sdp"] == {"enabled": True, "mode": "advanced"}
    assert t["filters"]["rai"] == [{"category": "HARASSMENT", "level": "MEDIUM_AND_ABOVE"}]
    assert t["block_message"] == "Blocked by policy"
    assert m["templates"][0]["id"] == "strict"


def test_inventory(client):
    inv = client.get("/api/studio/inventory", params=Q).json()
    engines = {e["display_name"]: e for e in inv["engines"]}
    assert engines["HR Assistant"]["gateways"] == {"egress": F.EG} and engines["HR Assistant"]["bindable"]
    assert engines["Legacy Bot"]["bindable"] is False
    assert engines["Legacy Bot"]["principal"].startswith("serviceAccount:service-")
    kinds = {a["display_name"]: a for a in inv["agents"]}
    assert kinds["HR Assistant"]["kind"] == "runtime" and kinds["HR Assistant"]["engine"] == F.E1
    assert kinds["KB Agent"]["kind"] == "a2a" and kinds["KB Agent"]["url"] == "https://kb.example.com"
    tools = {t["name"]: t for t in inv["mcp_servers"][1]["tools"]}  # sorted: Directory, Tickets
    assert tools["delete_ticket"]["destructive"] and tools["list_tickets"]["read_only"]
    acc = inv["access"][F.MCP]
    assert acc[0]["member_label"] == "HR Assistant (Agent Identity)"
    assert acc[0]["english"] == "HR Assistant (Agent Identity) → Tickets MCP: all tools"
    assert acc[1]["english"].endswith("only read-only tools (by MCP hint)")
    assert inv["access"][F.EP][0]["member_label"] == "All agents in project"
    assert inv["project_agents_principal"] == F.PROJECT_SET
    assert f"projects/{F.P}/locations/{F.R}" in inv["access"]       # whole-registry policy


def test_audit(client):
    a = client.get("/api/studio/audit", params=Q).json()
    titles = [f["title"] for f in a["findings"]]
    assert "Unprotected egress: Pricing Analyst" in titles
    assert any(t.startswith("Unconditional access to Tickets MCP") for t in titles)
    assert a["synced_at"] and a["grants"]


def test_partial_failure_is_per_item(client, fake):
    fake.fail = {"mcpServers/agentregistry-ro:getIamPolicy": 403}
    inv = client.get("/api/studio/inventory", params={**Q, "refresh": 1}).json()
    ro = next(m for m in inv["mcp_servers"] if m["id"] == "agentregistry-ro")
    assert "HTTP 403" in ro["error"] and F.MCP_RO in inv["access_errors"]
    assert inv["access"][F.MCP]                              # others still there


def test_cache_and_refresh(client, fake):
    client.get("/api/studio/gateways", params=Q)
    n = len(fake.calls)
    client.get("/api/studio/gateways", params=Q)
    assert len(fake.calls) == n                               # cached
    client.get("/api/studio/gateways", params={**Q, "refresh": 1})
    assert len(fake.calls) > n


def test_render_and_diff(client):
    ctx = {"project": F.P, "region": F.R}
    intents = [
        {"id": "g1", "kind": "grant", "source": {"type": "engine", "principal": F.principal("111"),
                                                  "label": "HR Assistant", "engine": F.E1},
         "destination": {"kind": "mcp_server", "id": "agentregistry-mcp", "name": F.MCP, "label": "Tickets MCP"},
         "access": {"mode": "read_only_hint"}},
        {"id": "g2", "kind": "grant", "source": {"type": "engine", "principal": F.principal("111"), "label": "HR"},
         "destination": {"kind": "mcp_server", "id": "agentregistry-mcp", "label": "Tickets MCP"},
         "access": {"mode": "all"}},
        {"id": "b1", "kind": "bind_gateway", "engine": F.E2, "gateway": {"name": F.EG, "direction": "egress"}},
        {"id": "m1", "kind": "model_armor_on", "gateway": {"name": "corp-out", "direction": "egress"}},
        {"id": "m2", "kind": "model_armor_off", "gateway": {"name": "corp-in", "direction": "ingress"}},
    ]
    r = client.post("/api/studio/render", json={"context": ctx, "intents": intents}).json()
    items = {i["intent_id"]: i for i in r["items"]}
    assert f"projects/{F.N}/locations/{F.R}/iap_web/agentRegistry/mcpServers/agentregistry-mcp" == \
        items["g1"]["anatomy"]["resource"]
    assert "authzExtensions/corp-ma" in items["m1"]["outputs"]["terraform"]       # extension discovered
    assert "corp-in-ma" in items["m2"]["outputs"]["gcloud"]                       # policy name discovered
    assert r["context"]["project_number"] == F.N
    assert set(r["bundle"]["terraform"]) == {"main.tf", "variables.tf"}
    d = client.post("/api/studio/diff", json={"context": ctx, "intents": intents}).json()
    st = {i["intent_id"]: i["status"] for i in d["items"]}
    assert st == {"g1": "replace", "g2": "present", "b1": "add", "m1": "add", "m2": "remove"}


def test_spa_fallback(tmp_path, monkeypatch, fake):
    (tmp_path / "index.html").write_text("<html>studio</html>")
    (tmp_path / "app.js").write_text("console.log(1)")
    monkeypatch.setenv("STUDIO_FRONTEND_DIST", str(tmp_path))
    c = TestClient(create_app())
    assert c.get("/").text == "<html>studio</html>"
    assert c.get("/audit/deep/link").text == "<html>studio</html>"
    assert c.get("/app.js").text == "console.log(1)"
    assert c.get("/api/studio/nope").status_code == 404


def test_contract_alignment(client, fake):
    c = client.get("/api/studio/context", params=Q).json()
    assert c["principal_set"] == F.PROJECT_SET
    inv = client.get("/api/studio/inventory", params=Q).json()
    names = [x["name"] for k in ("agents", "mcp_servers", "endpoints") for x in inv[k]]
    assert all(n in inv["access"] for n in names)                        # [] when nobody has access
    assert inv["access"][F.AGENT_RT] == []
    eng = {e["name"]: e for e in inv["engines"]}
    assert all(n.startswith(f"projects/{F.N}/") for n in eng)
    rt = next(a for a in inv["agents"] if a["kind"] == "runtime")
    assert rt["engine"] in eng
    members = {b["member"] for b in inv["access"][F.MCP]}
    assert eng[F.E1]["principal"] in members
    a = client.get("/api/studio/audit", params=Q).json()
    for f in a["findings"]:
        fx = f.get("fix")
        if fx and fx["kind"] in ("grant", "revoke"):
            assert fx["source"]["label"] and fx["destination"]["label"]
        if fx and fx["kind"] == "bind_gateway":
            assert fx["source"]["label"] == "Pricing Analyst"
    # registry-wide grants are revocable
    reg = f"projects/{F.P}/locations/{F.R}"
    intent = {"id": "r", "kind": "revoke", "source": {"type": "custom", "principal": "user:x@y.com"},
              "destination": {"kind": "registry", "id": "", "name": reg, "label": "Agent Registry"}}
    d = client.post("/api/studio/diff", json={"context": Q, "intents": [intent]}).json()["items"][0]
    assert d["status"] == "absent" and d["after"] == []


def test_diff_after(client):
    g = {"id": "g", "kind": "grant", "source": {"type": "engine", "principal": F.principal("111"), "label": "HR"},
         "destination": {"kind": "mcp_server", "id": "agentregistry-mcp", "label": "Tickets MCP"},
         "access": {"mode": "read_only_hint"}, "engine_label": "client-only"}
    r = {**g, "id": "r", "kind": "revoke", "access": {"mode": "all"}}
    out = {i["intent_id"]: i for i in client.post("/api/studio/diff", json={"context": Q, "intents": [g, r]})
           .json()["items"]}
    assert out["g"]["status"] == "replace" and len(out["g"]["after"]) == 2
    assert out["g"]["after"][1]["condition"]["expression"].startswith("api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly'")
    assert out["r"]["status"] == "remove" and out["r"]["after"] == []


def test_permission_not_checked_is_null(client, fake):
    fake.fail = {":testIamPermissions": 500}
    c = client.get("/api/studio/context", params={**Q, "refresh": 1}).json()
    assert all(p["granted"] is None for p in c["permissions"])


def test_invalid_intent_fails_alone(client):
    good = {"id": "ok", "kind": "model_armor_on", "gateway": {"name": "corp-out"}}
    bad = {"id": "bad", "kind": "grant", "destination": {"kind": "bogus", "id": "y"}}
    r = client.post("/api/studio/render", json={"context": Q, "intents": [bad, good]})
    assert r.status_code == 200
    items = r.json()["items"]
    assert [i["intent_id"] for i in items] == ["bad", "ok"]
    assert "destination.kind" in items[0]["error"] and items[1]["error"] is None
    d = client.post("/api/studio/diff", json={"context": Q, "intents": [bad, good]}).json()["items"]
    assert d[0]["error"] and d[1]["status"] == "add"


def test_hostile_tool_name_intent_is_invalid(client):
    bad = {"id": "bad", "kind": "grant", "source": {"type": "custom", "principal": "user:x@example.com"},
           "destination": {"kind": "mcp_server", "id": "agentregistry-mcp", "label": "Tickets MCP"},
           "access": {"mode": "tools", "tools": ["get_ticket", "x'] || true || ['"]}}
    items = client.post("/api/studio/render", json={"context": Q, "intents": [bad]}).json()["items"]
    assert "not allowed in a condition" in items[0]["error"] and not items[0]["outputs"]["gcloud"]
    p = client.post("/api/studio/preflight", json={"context": Q, "intents": [bad]}).json()["items"]
    assert p[0]["status"] == "invalid"
