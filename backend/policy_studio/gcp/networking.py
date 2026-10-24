"""Private networking, detection only (docs/PRIVATE_NETWORKING_PLAN.md §2–§4). Pure functions, no imports beyond the
standard library, so the demo can copy this file as it is.

Agent Runtime agent   spec.deploymentSpec.pscInterfaceConfig {networkAttachment, dnsPeeringConfigs[{domain,
                      targetProject, targetNetwork}]}: the agent's own way into a VPC, which skips the gateway.
Agent Gateway         agentConnectivityTemplate "projects/<NUMBER>/locations/R/agentConnectivityTemplates/T" (the
                      project *number* form, always), or the older inline networkConfig {egress: {networkAttachment},
                      dnsPeeringConfig: {domains, targetProject, targetNetwork}}.
Connectivity template egressNetworkConfig {networkAttachment, dnsPeeringConfig {domains, targetNetwork}, vpcEgress,
                      tlsConfig}, accessPath. Attachment and targetNetwork use the project *id*.
Network attachment    (optional) network -> the VPC name; subnetworks, connectionPreference, connectionEndpoints[].

Rules N1–N5 take engines / gateways as dicts or objects with the same field names (Engine / Gateway of model.py).
"""
from __future__ import annotations

import re
from typing import Any, Optional

COMPUTE = "https://compute.googleapis.com/compute/v1"
UNREADABLE = "can't read details"
TEMPLATE_PERMISSION = "networkservices.agentConnectivityTemplates.get"
ATTACHMENT_PERMISSION = "compute.networkAttachments.get"

_PROJECT_RE = re.compile(r"^projects/([^/]+)/")


def _get(o: Any, key: str, default: Any = None) -> Any:
    if o is None:
        return default
    if isinstance(o, dict):
        return o.get(key, default)
    return getattr(o, key, default)


def short(name: str) -> str:
    return (name or "").rstrip("/").rsplit("/", 1)[-1]


def resource_path(name: str) -> str:
    """'https://www.googleapis.com/compute/v1/projects/P/...' or '//compute.googleapis.com/projects/P/...' ->
    'projects/P/...'."""
    n = name or ""
    i = n.find("projects/")
    return n[i:] if i >= 0 else n


# ------------------------------------------------------------------ engines
def psc_interface_config(eng: dict | None) -> dict:
    return (((eng or {}).get("spec") or {}).get("deploymentSpec") or {}).get("pscInterfaceConfig") or {}


def engine_psc_interface(eng: dict | None, attachment: dict | None = None) -> Optional[dict[str, Any]]:
    """The engine's PSC interface (§3 Engine.psc_interface), or None. `attachment`: the network attachment, when it
    could be read, for the VPC name."""
    cfg = psc_interface_config(eng)
    if not cfg:
        return None
    peers = cfg.get("dnsPeeringConfigs") or []
    out: dict[str, Any] = {"network_attachment": cfg.get("networkAttachment", "") or "",
                           "dns_domains": [p.get("domain", "") for p in peers if p.get("domain")]}
    vpc = vpc_of_attachment(attachment) or next((short(p["targetNetwork"]) for p in peers if p.get("targetNetwork")),
                                                None)
    if vpc:
        out["vpc"] = vpc
    return out


# ------------------------------------------------------------------ attachments
def vpc_of_attachment(att: dict | None) -> Optional[str]:
    """The VPC name of a network attachment (its `network`), or None."""
    return short(att["network"]) if att and att.get("network") else None


def attachment_url(name: str) -> str:
    return f"{COMPUTE}/{resource_path(name)}"


# ------------------------------------------------------------------ gateways and templates
def template_ref(gw: dict | None) -> str:
    return (gw or {}).get("agentConnectivityTemplate", "") or ""


def resolve_project(name: str, numbers: dict[str, str]) -> str:
    """Swap a project number for its id when it is known. `numbers`: {project number: project id}. The gateway
    references its template by number; the template is shown (and read) by project id."""
    path = resource_path(name)
    m = _PROJECT_RE.match(path)
    if not m or m.group(1) not in numbers:
        return path
    return f"projects/{numbers[m.group(1)]}/{path[m.end():]}"


def template_url(name: str, base: str = "https://networkservices.googleapis.com/v1") -> str:
    return f"{base}/{resource_path(name)}"


def inline_config(gw: dict | None) -> dict:
    return (gw or {}).get("networkConfig") or {}


def attachment_of(gw: dict | None, template: dict | None = None) -> str:
    """The network attachment a gateway uses (template form needs the template)."""
    if template_ref(gw):
        return ((template or {}).get("egressNetworkConfig") or {}).get("networkAttachment", "") or ""
    return ((inline_config(gw).get("egress") or {}).get("networkAttachment", "")) or ""


def gateway_private_egress(gw: dict | None, template: dict | None = None, template_error: Optional[str] = None,
                           attachment: dict | None = None, numbers: dict[str, str] | None = None
                           ) -> Optional[dict[str, Any]]:
    """§3 Gateway.private_egress, or None (public egress only). `template`: the connectivity template the gateway
    references (None when it couldn't be read: pass `template_error`). `attachment`: the network attachment, when
    readable, for the VPC name. `numbers`: {project number: project id} to show the template by project id."""
    ref = template_ref(gw)
    if ref:
        out: dict[str, Any] = {"source": "template", "template": resolve_project(ref, numbers or {}),
                               "network_attachment": "", "dns_domains": []}
        if template is None:
            out["error"] = UNREADABLE + (f": {template_error}" if template_error else "")
            return out
        egress = template.get("egressNetworkConfig") or {}
        dns = egress.get("dnsPeeringConfig") or {}
        out["network_attachment"] = egress.get("networkAttachment", "") or ""
        out["dns_domains"] = [d for d in dns.get("domains") or [] if d]
        vpc = vpc_of_attachment(attachment) or (short(dns["targetNetwork"]) if dns.get("targetNetwork") else None)
        if vpc:
            out["vpc"] = vpc
        if egress.get("vpcEgress"):
            out["vpc_egress"] = egress["vpcEgress"]
        out["custom_trust"] = bool(egress.get("tlsConfig"))
        return out
    cfg = inline_config(gw)
    att = (cfg.get("egress") or {}).get("networkAttachment", "") or ""
    dns = cfg.get("dnsPeeringConfig") or {}
    if not att and not dns:
        return None
    out = {"source": "inline", "network_attachment": att, "dns_domains": [d for d in dns.get("domains") or [] if d]}
    vpc = vpc_of_attachment(attachment) or (short(dns["targetNetwork"]) if dns.get("targetNetwork") else None)
    if vpc:
        out["vpc"] = vpc
    return out


# ------------------------------------------------------------------ audit rules N1–N5
REDEPLOY_NO_PSC = """import vertexai
from vertexai import types

client = vertexai.Client(project="PROJECT_ID", location="REGION")
remote = client.agent_engines.create(
    agent=app,                     # your ADK app / agent object
    config={
        "identity_type": types.IdentityType.AGENT_IDENTITY,   # required for Agent Gateway; can't be changed later
        "display_name": "my-agent",
        # No "psc_interface_config": its VPC calls would skip the gateway. Reach the VPC through the egress
        # gateway's private egress (a connectivity template) instead.
        "agent_gateway_config": {"agent_to_anywhere_config": {
            "agent_gateway": "projects/PROJECT_ID/locations/REGION/agentGateways/GATEWAY_ID"}},
        # Pin google-auth 2.60.0: a known google-auth bug (Google is fixing it) makes the agent's Google API calls
        # fail with 401 behind Agent Gateway. The pin keeps Context-Aware Access token binding.
        "requirements": ["google-cloud-aiplatform[agent_engines,adk]", "google-auth==2.60.0"],
        # Fallback if you can't pin it (strongly discouraged by Google: opts out of token binding):
        # "env_vars": {"GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES": "false"},
        # ... the rest of your existing deployment config
    },
)
# Then grant the new identity roles/iap.egressor on the destinations it needs (Builder), and delete the old agent."""

TEMPLATE_STEPS = """# Two steps (a direct PATCH from no networking to a template fails today; from inline it works).
# 1. A connectivity template with the same attachment and DNS. The template takes project IDs.
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\
  "https://networkservices.googleapis.com/v1/projects/PROJECT_ID/locations/REGION/agentConnectivityTemplates?agentConnectivityTemplateId=TEMPLATE_ID" \\
  -d '{"accessPath": "AGENT_TO_ANYWHERE", "deploymentModel": "CENTRALIZED",
       "egressNetworkConfig": {
         "networkAttachment": "ATTACHMENT",
         "dnsPeeringConfig": {"domains": [DOMAINS], "targetNetwork": "projects/PROJECT_ID/global/networks/VPC"},
         "vpcEgress": "PRIVATE_RANGES_ONLY"}}'
# 2. Point the gateway at it and clear networkConfig (the mask needs both). The gateway takes the project NUMBER.
curl -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\
  "https://networkservices.googleapis.com/v1/GATEWAY?updateMask=agentConnectivityTemplate,networkConfig,labels" \\
  -d '{"agentConnectivityTemplate": "projects/PROJECT_NUMBER/locations/REGION/agentConnectivityTemplates/TEMPLATE_ID",
       "labels": {}}'   # send the gateway's current labels: a PATCH can drop them
# About 3 minutes. Policy Studio doesn't apply this; check it on a gateway without bound agents first."""


def _engine_label(e: Any) -> str:
    return _get(e, "display_name") or short(_get(e, "name", ""))


def _vpc_phrase(p: dict) -> str:
    return f"the VPC {p['vpc']}" if p.get("vpc") else "a VPC"


def rule_psc_engines(engines: list[Any]) -> list[dict[str, Any]]:
    """N1 (PSC interface, no egress gateway) and N2 (PSC interface and an egress gateway binding)."""
    out: list[dict[str, Any]] = []
    for e in engines:
        psc = _get(e, "psc_interface")
        if not psc:
            continue
        psc = psc if isinstance(psc, dict) else psc.model_dump()
        name, label = _get(e, "name", ""), _engine_label(e)
        egress = (_get(e, "gateways") or {}).get("egress")
        if not egress:
            out.append({"rule": "N1", "severity": "high", "resource": name, "redeploy": REDEPLOY_NO_PSC,
                        "title": f"Direct VPC access, bypasses the gateway: {label}",
                        "detail": (f"{label} has its own private networking (a PSC interface into "
                                   f"{_vpc_phrase(psc)}) and no egress gateway. Its calls into the VPC skip every "
                                   "check: no Agent Registry, no roles/iap.egressor grant and no gateway logs apply, so "
                                   "its grants in Policy Studio mean nothing for that traffic. Redeploy it without the "
                                   "PSC interface, with Agent Identity, bound to the egress gateway.")})
        else:
            out.append({"rule": "N2", "severity": "high", "resource": name, "redeploy": REDEPLOY_NO_PSC,
                        "title": f"Broken: PSC interface and gateway binding on {label}",
                        "detail": (f"{label} has a PSC interface and is bound to the egress gateway "
                                   f"{short(egress)}. Google rejects that combination when an agent is created; it is "
                                   "only reachable by a later update, and an agent in this state can't reach Google "
                                   "APIs at all (sessions and model calls time out). Redeploy it without the PSC "
                                   "interface.")})
    return out


def rule_gateways(gateways: list[Any]) -> list[dict[str, Any]]:
    """N3 (inline networkConfig), N4 (template unreadable), N5 (vpcEgress ALL_TRAFFIC)."""
    out: list[dict[str, Any]] = []
    for g in gateways:
        pe = _get(g, "private_egress")
        if not pe:
            continue
        pe = pe if isinstance(pe, dict) else pe.model_dump(exclude_none=True)
        name, gid = _get(g, "name", ""), _get(g, "id") or short(_get(g, "name", ""))
        if pe.get("source") == "inline":
            out.append({"rule": "N3", "severity": "info", "resource": name, "guidance": TEMPLATE_STEPS,
                        "title": f"Inline private egress on {gid}",
                        "detail": (f"Gateway {gid} reaches {_vpc_phrase(pe)} through an inline networkConfig, the "
                                   "older form. VPC Service Controls and custom trust (your own CA) need a connectivity "
                                   "template. Moving takes two updates and keeps the gateway and its bound agents.")})
        if pe.get("error"):
            out.append({"rule": "N4", "severity": "medium", "resource": name,
                        "title": f"Can't read the connectivity template of {gid}",
                        "detail": (f"Gateway {gid} uses the connectivity template {short(pe.get('template', ''))}, "
                                   "but Policy Studio can't read it, so its VPC, private domains and egress mode are "
                                   f"unknown. Ask for {TEMPLATE_PERMISSION} (in roles/networkservices.viewer) on the "
                                   "gateway's project.")})
        if pe.get("vpc_egress") == "ALL_TRAFFIC":
            out.append({"rule": "N5", "severity": "info", "resource": name,
                        "title": f"All of {gid}'s traffic goes into the VPC",
                        "detail": (f"The connectivity template of {gid} uses egress mode ALL_TRAFFIC: every call "
                                   "through the gateway, public destinations included, leaves through "
                                   f"{_vpc_phrase(pe)}, which then needs Cloud NAT to reach the internet. This is the "
                                   "mode used with VPC Service Controls.")})
    return out


def audit_rules(engines: list[Any], gateways: list[Any]) -> list[dict[str, Any]]:
    """Every N1–N5 finding as a plain dict {rule, severity, title, detail, resource, redeploy?, guidance?}."""
    return rule_psc_engines(engines) + rule_gateways(gateways)


# ------------------------------------------------------------------ preflight
PSC_BIND_REASON = ("This agent has its own private networking (PSC interface). Google rejects or breaks agents with "
                   "both; redeploy it without the PSC interface.")
