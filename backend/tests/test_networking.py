"""Private networking, detection only: networking.py parsers and rules N1–N5, the PSC-interface bind block, and the
discovery wiring (template read by project id, attachment for the VPC name, 403 degrades)."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import fakegcp as F
from policy_studio import service
from policy_studio.app import create_app
from policy_studio.gcp import networking as net
from policy_studio.gcp.engines import REASON_IDENTITY, REASON_PSC, parse_engine

Q = {"project": F.P, "region": F.R}
NUMBERS = {F.N: F.P}
TMPL = F.CONNECTIVITY_TEMPLATES["corp-tmpl"]
ATT = F.NETWORK_ATTACHMENTS["corp-att"]


@pytest.fixture
def net_client(monkeypatch):
    def make(**kw):
        rest = F.FakeRest(networking=True, **kw)
        monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
        return TestClient(create_app()), rest
    return make


# ====================================================================== parsers
def test_gateway_template_form():
    gw = F.GATEWAYS[0]
    pe = net.gateway_private_egress(gw, TMPL, attachment=ATT, numbers=NUMBERS)
    assert pe == {"source": "template", "template": F.CT, "network_attachment": F.ATT, "vpc": "corp-vpc",
                  "dns_domains": ["run.app.", "corp.internal."], "vpc_egress": "PRIVATE_RANGES_ONLY",
                  "custom_trust": False}
    # without the attachment, the VPC comes from the DNS targetNetwork
    assert net.gateway_private_egress(gw, TMPL)["vpc"] == "corp-vpc"
    sc = net.gateway_private_egress(F.NET_GATEWAYS[1], F.CONNECTIVITY_TEMPLATES["vpcsc-tmpl"])
    assert sc["custom_trust"] is True and sc["vpc_egress"] == "ALL_TRAFFIC" and "vpc" not in sc


def test_gateway_inline_form_and_none():
    pe = net.gateway_private_egress(F.NET_GATEWAYS[0], attachment=ATT)
    assert pe == {"source": "inline", "network_attachment": F.ATT, "dns_domains": ["run.app."], "vpc": "corp-vpc"}
    assert net.gateway_private_egress(F.GATEWAYS[1]) is None
    assert net.gateway_private_egress({"name": "g", "networkConfig": {}}) is None


def test_template_number_vs_id():
    ref = net.template_ref(F.GATEWAYS[0])
    assert ref.startswith(f"projects/{F.N}/")
    assert net.resolve_project(ref, NUMBERS) == F.CT                     # known number -> project id
    assert net.resolve_project(ref, {"999": "other"}) == ref             # unknown number stays as is
    assert net.resolve_project(f"//networkservices.googleapis.com/{ref}", NUMBERS) == F.CT
    assert net.template_url(F.CT) == f"https://networkservices.googleapis.com/v1/{F.CT}"
    assert net.attachment_url(ATT["subnetworks"][0]).startswith("https://compute.googleapis.com/compute/v1/projects/")


def test_template_unreadable():
    pe = net.gateway_private_egress(F.GATEWAYS[0], None, "HTTP 403: denied", numbers=NUMBERS)
    assert pe["source"] == "template" and pe["template"] == F.CT and pe["dns_domains"] == []
    assert pe["error"] == "can't read details: HTTP 403: denied"


def test_engine_psc_interface():
    e4, e5 = F.NET_ENGINES
    assert net.engine_psc_interface(e4) == {"network_attachment": F.PSCI["networkAttachment"],
                                            "dns_domains": ["corp.internal."], "vpc": "lab-vpc"}
    assert net.engine_psc_interface(e5) == {"network_attachment": F.PSCI["networkAttachment"], "dns_domains": []}
    assert net.engine_psc_interface(e5, F.NETWORK_ATTACHMENTS["psci-att"])["vpc"] == "lab-vpc"
    assert net.engine_psc_interface(F.ENGINES[0]) is None


def test_psc_engine_is_not_bindable_and_reason_wins():
    e = parse_engine(F.NET_ENGINES[0])
    assert not e.bindable and e.bindable_reason == REASON_PSC and "PSC interface" in REASON_PSC
    sa = parse_engine({**F.NET_ENGINES[0], "spec": {**F.NET_ENGINES[0]["spec"], "identityType": "SERVICE_ACCOUNT"}})
    assert sa.bindable_reason == REASON_PSC != REASON_IDENTITY
    assert parse_engine(F.ENGINES[1]).psc_interface is None


# ====================================================================== rules
def _rules(engines=(), gateways=()):
    return {(f["rule"], f["resource"]): f for f in net.audit_rules(list(engines), list(gateways))}


def test_rules_n1_n2():
    e4 = {"name": "e4", "display_name": "Lab", "gateways": {}, "psc_interface": {"network_attachment": "a", "vpc": "v"}}
    e5 = {**e4, "name": "e5", "gateways": {"egress": "projects/p/locations/r/agentGateways/gw"}}
    e6 = {**e4, "name": "e6", "psc_interface": None}
    out = _rules([e4, e5, e6])
    assert set(out) == {("N1", "e4"), ("N2", "e5")}
    n1, n2 = out[("N1", "e4")], out[("N2", "e5")]
    assert n1["severity"] == n2["severity"] == "high"
    assert "bypasses the gateway" in n1["title"] and "the VPC v" in n1["detail"]
    assert n2["title"].startswith("Broken") and "can't reach Google" in n2["detail"] and "gw" in n2["detail"]
    for f in (n1, n2):
        assert "psc_interface_config" in f["redeploy"] and "AGENT_IDENTITY" in f["redeploy"]


def test_rules_n3_n4_n5():
    gws = [{"name": "g/inline", "id": "inline", "private_egress": {"source": "inline", "vpc": "v"}},
           {"name": "g/err", "id": "err", "private_egress": {"source": "template", "template": "x/t", "error": "e"}},
           {"name": "g/all", "id": "all", "private_egress": {"source": "template", "vpc_egress": "ALL_TRAFFIC"}},
           {"name": "g/ok", "id": "ok", "private_egress": {"source": "template", "vpc_egress": "PRIVATE_RANGES_ONLY"}},
           {"name": "g/pub", "id": "pub", "private_egress": None}]
    out = _rules(gateways=gws)
    assert set(out) == {("N3", "g/inline"), ("N4", "g/err"), ("N5", "g/all")}
    assert out[("N3", "g/inline")]["severity"] == "info" and "agentConnectivityTemplate,networkConfig" in \
        out[("N3", "g/inline")]["guidance"]
    assert out[("N4", "g/err")]["severity"] == "medium" and net.TEMPLATE_PERMISSION in out[("N4", "g/err")]["detail"]
    assert out[("N5", "g/all")]["severity"] == "info" and "NAT" in out[("N5", "g/all")]["detail"]


def test_rules_match_shared_fixture():
    """The frontend port (lib/networking.ts) reads the same file: wording changes must land on both sides."""
    cases = json.loads((Path(__file__).parent / "fixtures" / "networking_cases.json").read_text())
    assert net.audit_rules(cases["engines"], cases["gateways"]) == cases["expected"]


# ====================================================================== discovery wiring
def test_gateways_and_inventory_show_private_networking(net_client):
    c, rest = net_client()
    gws = {g["id"]: g for g in c.get("/api/studio/gateways", params=Q).json()["gateways"]}
    assert gws["corp-out"]["private_egress"]["template"] == F.CT          # number form resolved to the project id
    assert gws["corp-out"]["private_egress"]["vpc"] == "corp-vpc"
    assert gws["corp-out"]["private_egress"]["dns_domains"] == ["run.app.", "corp.internal."]
    assert gws["corp-out-inline"]["private_egress"]["source"] == "inline"
    assert gws["corp-in"]["private_egress"] is None
    gets = [u for m, u in rest.calls if m == "GET"]
    assert f"https://networkservices.googleapis.com/v1/{F.CT}" in gets
    assert any("compute.googleapis.com" in u and u.endswith("/networkAttachments/corp-att") for u in gets)
    eng = {e["id"]: e for e in c.get("/api/studio/inventory", params=Q).json()["engines"]}
    assert eng["444"]["psc_interface"]["vpc"] == "lab-vpc" and eng["444"]["bindable"] is False
    assert eng["555"]["psc_interface"]["vpc"] == "lab-vpc"                # from the attachment
    assert eng["111"]["psc_interface"] is None and eng["111"]["bindable"] is True
    n = len(rest.calls)
    c.get("/api/studio/gateways", params=Q)
    assert len(rest.calls) == n                                           # cached like the other reads


def test_template_403_degrades(net_client):
    c, _ = net_client(fail={"agentConnectivityTemplates": 403, "networkAttachments": 403})
    r = c.get("/api/studio/gateways", params=Q)
    assert r.status_code == 200
    gws = {g["id"]: g for g in r.json()["gateways"]}
    pe = gws["corp-out"]["private_egress"]
    assert pe["error"].startswith("can't read details") and "403" in pe["error"] and pe["template"] == F.CT
    assert gws["corp-out-inline"]["private_egress"]["vpc"] == "corp-vpc"     # from targetNetwork, attachment denied
    eng = {e["id"]: e for e in c.get("/api/studio/inventory", params=Q).json()["engines"]}
    assert eng["555"]["psc_interface"] == {"network_attachment": F.PSCI["networkAttachment"], "vpc": None,
                                           "dns_domains": []}
    findings = c.get("/api/studio/audit", params=Q).json()["findings"]
    assert {f["resource"] for f in findings if f.get("rule") == "N4"} == {gws["corp-out"]["name"],
                                                                          gws["corp-out-sc"]["name"]}


def test_audit_n1_to_n5(net_client):
    c, _ = net_client()
    findings = c.get("/api/studio/audit", params=Q).json()["findings"]
    by = {}
    for f in findings:
        if f.get("rule"):
            by.setdefault(f["rule"], []).append(f)
    assert sorted(by) == ["N1", "N2", "N3", "N5"]
    assert by["N1"][0]["resource"] == F.E4 and by["N1"][0]["redeploy"]
    assert by["N2"][0]["resource"] == F.E5
    assert by["N3"][0]["resource"].endswith("/corp-out-inline") and by["N3"][0]["guidance"]
    assert by["N5"][0]["resource"].endswith("/corp-out-sc")
    # the PSC engines don't also get the generic "Unprotected egress" finding
    assert not any(f["title"] == "Unprotected egress: Lab Agent" for f in findings)


def test_permissions_listed(net_client):
    c, _ = net_client()
    perms = {p["permission"]: p for p in c.get("/api/studio/context", params=Q).json()["permissions"]}
    for p in (net.TEMPLATE_PERMISSION, "networkservices.agentConnectivityTemplates.list", net.ATTACHMENT_PERMISSION):
        assert perms[p]["write"] is False and perms[p]["granted"] is True


# ====================================================================== preflight
def test_bind_of_psc_engine_is_blocked(net_client):
    c, _ = net_client()
    bind = {"id": "b4", "kind": "bind_gateway", "engine": F.E4, "gateway": {"name": F.EG, "direction": "egress"}}
    item = c.post("/api/studio/preflight", json={"context": Q, "intents": [bind]}).json()["items"][0]
    assert item["status"] == "blocked" and item["fix"] == "redeploy"
    assert item["reason"] == f"Lab Agent can't be bound to Agent Gateway. {REASON_PSC}"
    r = c.post("/api/studio/render", json={"context": Q, "intents": [bind]}).json()
    assert REASON_PSC in r["items"][0]["error"]
