import pytest

import fakegcp as F
from policy_studio import service
from policy_studio.audit import audit, write_tools
from policy_studio.diff import diff
from policy_studio.model import (Access, AuthzPolicyRef, Binding, Context, Destination, Engine, Gateway, GatewayRef,
                                 Intent, Inventory, McpServer, Source, Tool)
from policy_studio.render import RenderEnv

CTX = Context(project=F.P, region=F.R)


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(service, "rest_for", lambda ctx: F.FakeRest())
    inv = service.inventory_view(CTX)
    gws = service.gateways_view(CTX)["gateways"]
    return inv, gws


def by_title(findings):
    return {f.title: f for f in findings}


def test_findings_from_fixture(state):
    inv, gws = state
    res = audit(inv, gws, service.resolve(CTX, F.FakeRest()))
    f = by_title(res["findings"])
    # unprotected egress: bindable engine gets a bind fix to the only egress gateway; old engine can't be bound
    pa = f["Unprotected egress: Pricing Analyst"]
    assert pa.severity == "high" and pa.fix.kind == "bind_gateway" and pa.fix.engine == F.E2
    assert pa.fix.gateway.name == F.EG and pa.fix.gateway.direction == "egress"
    lb = f["Unprotected egress: Legacy Bot"]
    assert lb.severity == "medium" and lb.fix is None
    assert "Unprotected egress: HR Assistant" not in f
    # unconditional egressor on an MCP server with destructive tools -> read-only grant fix (+ revoke)
    un = f["Unconditional access to Tickets MCP"]
    assert un.severity == "high" and "delete_ticket" in un.detail
    assert un.fix.kind == "grant" and un.fix.access.mode == "read_only_hint" and un.fix.source.engine == F.E1
    assert [x.kind for x in un.model_extra["fixes"]] == ["grant", "revoke"]
    assert "Unconditional access to Directory MCP" not in f        # read-only server
    # grant to a deleted engine (999) -> revoke with the same condition
    gone = f["Grant to a deleted agent on Tickets MCP"]
    assert gone.severity == "medium" and gone.fix.kind == "revoke"
    assert gone.fix.access.mode == "read_only_hint" and gone.fix.access.title == "ro"
    # public member
    pub = f["allUsers on KB Agent"]
    assert pub.severity == "high" and pub.fix.kind == "revoke" and pub.fix.source.principal == "allUsers"
    assert pub.fix.destination.kind == "agent"
    # gateways: no Model Armor on egress (info + fix), IAP in dry run (medium)
    ma = f["No Model Armor on corp-out"]
    assert ma.severity == "info" and ma.fix.kind == "model_armor_on"
    assert "No Model Armor on corp-in" not in f
    assert f["IAP in dry run on corp-out"].severity == "medium"
    # ordering: high first
    sev = [x.severity for x in res["findings"]]
    assert sev == sorted(sev, key={"high": 0, "medium": 1, "info": 2}.get)


def test_grants_plain_english(state):
    inv, gws = state
    gs = audit(inv, gws)["grants"]
    eng = {g.english for g in gs}
    assert "HR Assistant (Agent Identity) → Tickets MCP: all tools" in eng
    assert "All agents in project → Weather API: full access" in eng
    assert "HR Assistant (Agent Identity) → KB Agent: full access" in eng
    kinds = {g.resource_kind for g in gs}
    assert kinds == {"agent", "mcp_server", "endpoint"}


def test_no_gateways_and_unenforced_grant():
    e = Engine(name="projects/1/locations/r/reasoningEngines/5", id="5", display_name="Solo",
               principal="principal://x/resources/aiplatform/projects/1/locations/r/reasoningEngines/5",
               bindable=True, create_time="2026-09-01T00:00:00Z")
    m = McpServer(name="projects/p/locations/r/mcpServers/m", id="m", display_name="M",
                  tools=[Tool(name="w", annotations={})])
    inv = Inventory(engines=[e], mcp_servers=[m], access={m.name: [
        Binding(role="roles/iap.egressor", member=e.principal, member_label="Solo (Agent Identity)")]})
    f = by_title(audit(inv, [], Context(project="p", region="r"))["findings"])
    assert f["Unprotected egress: Solo"].fix is None and "Create an egress gateway" in f["Unprotected egress: Solo"].detail
    assert f["Grant not enforced: Solo → M"].severity == "info"
    assert "Unconditional access to M" in f                                     # no hints = destructive by default
    assert write_tools(m) == ["w"]


def test_egress_gateway_without_iap():
    gw = Gateway(name="projects/p/locations/r/agentGateways/g", id="g", type="egress",
                 authz_policies=[AuthzPolicyRef(name="x", profile="CONTENT_AUTHZ", provider="model_armor")])
    f = by_title(audit(Inventory(), [gw])["findings"])
    assert f["No IAP authorization on g"].severity == "medium"


def test_diff_statuses(state):
    inv, gws = state
    env = RenderEnv(ctx=Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N))
    hr = Source(type="engine", principal=F.principal("111"), label="HR", engine=F.E1)
    gone = Source(type="engine", principal=F.principal("999"), label="gone")
    mcp = Destination(kind="mcp_server", id="agentregistry-mcp", label="Tickets MCP")
    intents = [
        Intent(id="present", kind="grant", source=hr, destination=mcp),
        Intent(id="replace", kind="grant", source=hr, destination=mcp, access=Access(mode="tools", tools=["x"])),
        Intent(id="add", kind="grant", source=gone, destination=Destination(kind="endpoint", id="agentregistry-ep")),
        Intent(id="remove", kind="revoke", source=gone, destination=mcp, access=Access(mode="read_only_hint")),
        Intent(id="absent", kind="revoke", source=gone, destination=mcp),
        Intent(id="b-present", kind="bind_gateway", engine=F.E1, gateway=GatewayRef(name="corp-out")),
        Intent(id="b-add", kind="bind_gateway", engine=F.E2, gateway=GatewayRef(name="corp-out")),
        Intent(id="u-absent", kind="unbind_gateway", engine=F.E2, gateway=GatewayRef(name="corp-out")),
        Intent(id="u-remove", kind="unbind_gateway", engine=F.E1, gateway=GatewayRef(name="corp-out")),
        Intent(id="ma-add", kind="model_armor_on", gateway=GatewayRef(name="corp-out")),
        Intent(id="ma-present", kind="model_armor_on", gateway=GatewayRef(name="corp-in", direction="ingress")),
        Intent(id="ma-absent", kind="model_armor_off", gateway=GatewayRef(name="corp-out")),
        Intent(id="missing", kind="grant", source=hr, destination=Destination(kind="agent", id="agentregistry-zzz")),
    ]
    out = {d.intent_id: d for d in diff(intents, inv, gws, env)}
    for k in ("present", "replace", "add", "remove", "absent"):
        assert out[k].status == k, (k, out[k])
    assert out["replace"].current[0].member == F.principal("111") and "revoke the old one" in out["replace"].detail
    assert out["b-present"].status == "present" and out["b-add"].status == "add"
    assert out["u-absent"].status == "absent" and out["u-remove"].status == "remove"
    assert out["ma-add"].status == "add" and out["ma-present"].status == "present"
    assert out["ma-absent"].status == "absent"
    assert out["missing"].status == "add" and "not found" in out["missing"].detail
