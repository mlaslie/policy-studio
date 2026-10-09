"""Bindability (Agent Identity), duplicate intents, preflight blockers (/preflight and enforced by /apply) and
friendlier Apply errors."""
import json

from fastapi.testclient import TestClient

import fakegcp as F
from policy_studio import apply as apply_mod, audit as audit_mod, preflight as pf
from policy_studio.app import create_app
from policy_studio.gcp.engines import REASON_DATE, REASON_IDENTITY, parse_engine
from policy_studio.model import Context, GatewayRef, Intent
from policy_studio.render import RenderEnv, render
from test_model_armor_setup import gcp, read_client, run, setup_intents  # noqa: F401  (fixtures)

Q = {"project": F.P, "region": F.R}
MA_ON = {"id": "on", "kind": "model_armor_on", "gateway": {"name": "corp-out", "direction": "egress"}}
BIND_SA = {"id": "b3", "kind": "bind_gateway", "engine": F.E3, "gateway": {"name": F.EG, "direction": "egress"}}


# ====================================================================== bindability
def test_bindable_needs_agent_identity_and_date():
    sa = parse_engine({"name": "projects/1/locations/r/reasoningEngines/6878", "createTime": "2026-10-01T00:00:00Z",
                       "spec": {"identityType": "SERVICE_ACCOUNT", "effectiveIdentity": "sa@p.iam.gserviceaccount.com"}})
    assert not sa.bindable and sa.bindable_reason == REASON_IDENTITY and "AGENT_IDENTITY" in sa.bindable_reason
    old = parse_engine({"name": "e", "createTime": "2026-01-01T00:00:00Z", "spec": {"identityType": "AGENT_IDENTITY"}})
    assert not old.bindable and old.bindable_reason == REASON_DATE
    ok = parse_engine({"name": "e", "createTime": "2026-06-01T00:00:00Z", "spec": {"identityType": "AGENT_IDENTITY"}})
    assert ok.bindable and ok.bindable_reason is None


def test_inventory_and_audit_for_unbindable_engine(read_client):
    c = read_client()
    eng = {e["id"]: e for e in c.get("/api/studio/inventory", params=Q).json()["engines"]}
    assert eng["333"]["bindable"] is False and eng["333"]["bindable_reason"] == REASON_IDENTITY
    assert eng["222"]["bindable"] is True
    findings = c.get("/api/studio/audit", params=Q).json()["findings"]
    legacy = next(f for f in findings if f["title"] == "Unprotected egress: Legacy Bot")
    assert legacy["fix"] is None and "Agent Identity" in legacy["detail"]
    assert "types.IdentityType.AGENT_IDENTITY" in legacy["redeploy"] and "agent_engines.create(" in legacy["redeploy"]
    pricing = next(f for f in findings if f["title"] == "Unprotected egress: Pricing Analyst")
    assert pricing["fix"]["kind"] == "bind_gateway"


def test_render_refuses_unbindable_engine(read_client):
    r = read_client().post("/api/studio/render", json={"context": Q, "intents": [BIND_SA]}).json()
    item = r["items"][0]
    assert item["error"].startswith("Legacy Bot can't be bound") and REASON_IDENTITY in item["error"]
    assert "-X PATCH" not in r["bundle"]["gcloud"]


# ====================================================================== duplicates
def test_duplicate_keys():
    a = Intent.model_validate({**MA_ON, "id": "a"})
    b = Intent.model_validate({**MA_ON, "id": "b", "gateway": {"name": F.EG, "direction": "egress",
                                                               "extension": "x"}})      # discovered field ignored
    c = Intent.model_validate({**MA_ON, "id": "c", "gateway": {"name": "corp-in", "direction": "ingress"}})
    assert pf.duplicates([a, b, c]) == {"b": "a"}


def test_render_bundle_keeps_one_of_duplicates():
    env = RenderEnv(ctx=Context(project=F.P, region=F.R, project_number=F.N))
    ext = f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-ma"
    res = render([Intent(id="m1", kind="model_armor_on", gateway=GatewayRef(name="corp-out", extension=ext)),
                  Intent(id="m2", kind="model_armor_on", gateway=GatewayRef(name="corp-out", extension=ext))], env)
    assert res.bundle.gcloud.count("authz-policies import") == 1
    assert any("Same change as item m1" in w for w in res.items[1].warnings)


def test_apply_skips_duplicates(gcp):  # noqa: F811
    _, f = run(setup_intents() + [{**setup_intents()[0], "id": "on-again"}])
    assert f["on"]["state"] == "verified" and f["on-again"]["state"] == "skipped"
    assert sum(1 for m, u, _ in gcp.writes if "authzPolicies" in u) == 1


# ====================================================================== preflight
def test_preflight_endpoint(read_client):
    c = read_client(model_armor=False)
    r = c.post("/api/studio/preflight", json={"context": Q, "intents": [MA_ON, BIND_SA, {**MA_ON, "id": "dup"},
                                                                         {"id": "bad", "kind": "nope"}]}).json()
    st = {i["intent_id"]: i for i in r["items"]}
    assert st["on"]["status"] == "blocked" and st["on"]["fix"] == "ma_setup" and "isn't set up" in st["on"]["reason"]
    assert st["b3"]["status"] == "blocked" and st["b3"]["fix"] == "redeploy"
    assert st["dup"] == {"intent_id": "dup", "status": "duplicate", "duplicate_of": "on",
                         "reason": "Same change as on; applied once."}
    assert st["bad"]["status"] == "invalid"
    # with the setup staged in the same cart, Model Armor on is fine
    r = c.post("/api/studio/preflight", json={"context": Q, "intents": setup_intents()}).json()
    assert {i["status"] for i in r["items"]} == {"ok"}


def test_apply_enforces_preflight(gcp):  # noqa: F811
    events, f = run([MA_ON, BIND_SA])
    assert f["on"]["state"] == "failed" and f["on"]["detail"].startswith("Blocked before any change: Model Armor")
    assert f["on"]["blocked"] is True and f["on"]["fix"] == "ma_setup"
    assert f["b3"]["state"] == "failed" and f["b3"]["fix"] == "redeploy"
    assert not gcp.writes
    assert events[-1]["summary"]["blocked"] == 2


def test_blockers_respect_writable():
    env = RenderEnv(ctx=Context(project=F.P, region=F.R))
    it = Intent(id="g", kind="iam_project_grant", params={"member": F.DEP_SA})
    assert pf.blockers([it], env, {"iam_project_grant": False})["g"]["fix"] == "permission"
    assert pf.blockers([it], env, {"iam_project_grant": True}) == {}


# ====================================================================== friendly errors
def test_friendly_errors():
    raw = "HTTP 400: Reasoning Engine with agent_gateway_config must use AGENT_IDENTITY identity type."
    assert pf.friendly(raw) == REASON_IDENTITY
    assert pf.friendly("HTTP 500: boom") == "HTTP 500: boom"
    a = apply_mod.Applier(RenderEnv(ctx=Context(project=F.P, region=F.R)), None, None, log_path="/dev/null")
    a.emit("x", "failed", raw)
    ev = a.q.get()
    assert ev["detail"] == REASON_IDENTITY and ev["raw_error"] == raw
    a.emit("y", "failed", "HTTP 500: boom")
    assert "raw_error" not in a.q.get()
    assert json.dumps(ev)


def test_unbindable_matched_by_engine_id(read_client):
    alt = {**BIND_SA, "engine": f"projects/{F.P}/locations/{F.R}/reasoningEngines/333"}   # project id, not number
    r = read_client().post("/api/studio/preflight", json={"context": Q, "intents": [alt]}).json()
    assert r["items"][0]["status"] == "blocked" and r["items"][0]["fix"] == "redeploy"


def test_explicit_extension_that_does_not_exist_is_blocked(read_client):
    c = read_client(model_armor=False)
    ext = f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-ma-authz"
    on = {**MA_ON, "gateway": {**MA_ON["gateway"], "extension": ext}}
    r = c.post("/api/studio/preflight", json={"context": Q, "intents": [on]}).json()
    assert r["items"][0]["status"] == "blocked" and r["items"][0]["fix"] == "ma_setup"
    r = c.post("/api/studio/preflight", json={"context": Q, "intents": setup_intents(extension_on_intent=True)}).json()
    assert {i["status"] for i in r["items"]} == {"ok"}


def test_render_warns_for_unknown_explicit_extension(read_client):
    ext = f"projects/{F.P}/locations/{F.R}/authzExtensions/nope"
    r = read_client(model_armor=False).post("/api/studio/render", json={"context": Q, "intents": [
        {**MA_ON, "gateway": {**MA_ON["gateway"], "extension": ext}}]}).json()
    assert any(w.startswith("Model Armor isn't set up") and "nope" in w for w in r["items"][0]["warnings"])
