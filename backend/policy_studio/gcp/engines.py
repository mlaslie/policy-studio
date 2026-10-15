"""Agent Runtime engines (reasoningEngines): identity and Agent Gateway binding (read-only).

GET https://R-aiplatform.googleapis.com/v1/projects/P/locations/R/reasoningEngines
  spec.effectiveIdentity  agents.global.org-ORG.system.id.goog/resources/aiplatform/projects/N/locations/R/
                          reasoningEngines/ID  (Agent Identity)  |  a service account email (service agent)
  spec.deploymentSpec.agentGatewayConfig  {agentToAnywhereConfig: {agentGateway}, clientToAgentConfig: {agentGateway}}
  spec.deploymentSpec.pscInterfaceConfig  {networkAttachment, dnsPeeringConfigs[]}  (networking.py)
Engines created before 2026-04-29, or with a PSC interface, can't be bound to a gateway.
"""
from __future__ import annotations

import re

from ..model import Engine
from .networking import PSC_BIND_REASON, engine_psc_interface
from .rest import Rest, aiplatform

MASK = "spec.deploymentSpec.agentGatewayConfig"
KEYS = {"egress": "agentToAnywhereConfig", "ingress": "clientToAgentConfig"}
BINDABLE_SINCE = "2026-04-29"
REASON_IDENTITY = ("Created without Agent Identity: Agent Gateway needs identity_type=AGENT_IDENTITY, which can't be "
                   "changed. Redeploy the agent with Agent Identity.")
REASON_PSC = PSC_BIND_REASON
REASON_DATE = ("Created before 2026-04-29: engines that old can't be bound to Agent Gateway. Redeploy the agent (with "
               "Agent Identity).")
REDEPLOY_SNIPPET = """import vertexai
from vertexai import types

client = vertexai.Client(project="PROJECT_ID", location="REGION")
remote = client.agent_engines.create(
    agent=app,                     # your ADK app / agent object
    config={
        "identity_type": types.IdentityType.AGENT_IDENTITY,   # required for Agent Gateway; can't be changed later
        "display_name": "my-agent",
        "requirements": ["google-cloud-aiplatform[agent_engines,adk]"],
        # ... the rest of your existing deployment config
    },
)
# Then bind the new engine to the gateway (Policy Studio, Gateways step) and move grants to its new identity."""


def bind_blocker(identity: str, create_time: str, psc_interface: bool = False) -> str | None:
    """Why an engine can't be bound to Agent Gateway (None when it can). A PSC interface comes first: the agent needs
    a redeploy without it whatever its identity."""
    if psc_interface:
        return REASON_PSC
    if identity != "AGENT_IDENTITY":
        return REASON_IDENTITY
    if not create_time or create_time[:10] < BINDABLE_SINCE:
        return REASON_DATE
    return None


def gateway_config(eng: dict | None) -> dict:
    return (((eng or {}).get("spec") or {}).get("deploymentSpec") or {}).get("agentGatewayConfig") or {}


def gateways_of(eng: dict) -> dict[str, str]:
    cfg = gateway_config(eng)
    return {d: (cfg.get(k) or {}).get("agentGateway") for d, k in KEYS.items()
            if (cfg.get(k) or {}).get("agentGateway")}


def principal_of(eng: dict) -> str:
    eff = ((eng.get("spec") or {}).get("effectiveIdentity") or "").strip()
    if not eff:
        return ""
    if eff.startswith(("principal://", "principalSet://", "serviceAccount:")):
        return eff
    if "@" in eff:
        return f"serviceAccount:{eff}"
    return f"principal://{eff}"


def identity_type(eng: dict) -> str:
    t = (eng.get("spec") or {}).get("identityType")
    if t:
        return t
    p = principal_of(eng)
    if p.startswith("principal://"):
        return "AGENT_IDENTITY"
    return "SERVICE_AGENT" if "@gcp-sa-aiplatform-re." in p else "SERVICE_ACCOUNT"


def parse_engine(eng: dict) -> Engine:
    name = eng.get("name", "")
    ct = eng.get("createTime", "") or ""
    it = identity_type(eng)
    psc = engine_psc_interface(eng)
    reason = bind_blocker(it, ct, psc is not None)
    return Engine(name=name, id=name.rsplit("/", 1)[-1], display_name=eng.get("displayName") or name.rsplit("/", 1)[-1],
                  principal=principal_of(eng), identity_type=it, gateways=gateways_of(eng),
                  create_time=ct, bindable=reason is None, bindable_reason=reason, psc_interface=psc)


def list_engines(r: Rest, project: str, region: str) -> list[Engine]:
    raw = r.list_all(f"{aiplatform(region)}/projects/{project}/locations/{region}/reasoningEngines",
                     "reasoningEngines", params={"pageSize": 100})
    return [parse_engine(e) for e in raw]


def org_from_principal(principal: str) -> str | None:
    m = re.match(r"^principal://agents\.global\.org-(\d+)\.system\.id\.goog/", principal or "")
    return m.group(1) if m else None


def project_agents_principal(org_id: str, project_number: str) -> str:
    """Every Agent Runtime agent (Agent Identity) in the project."""
    return (f"principalSet://agents.global.org-{org_id}.system.id.goog/attribute.platformContainer/"
            f"aiplatform/projects/{project_number}")


def tail(resource: str) -> str:
    """'projects/X/locations/R/agentGateways/G' -> 'locations/R/agentGateways/G' (project id vs number safe)."""
    i = (resource or "").find("/locations/")
    return resource[i + 1:] if i >= 0 else resource
