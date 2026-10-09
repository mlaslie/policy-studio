"""Model Armor templates (read-only): https://modelarmor.<region>.rep.googleapis.com/v1.

A Model Armor authz extension names its template in metadata.model_armor_settings, a JSON string:
  [{"request_template_id": "projects/P/locations/R/templates/T", "response_template_id": "..."}]
"""
from __future__ import annotations

import json
from typing import Any

from ..model import Template
from .rest import Rest, modelarmor

LEVELS = {"LOW_AND_ABOVE": "low and above", "MEDIUM_AND_ABOVE": "medium and above", "HIGH": "high"}
RAI_LABELS = {"HATE_SPEECH": "Hate speech", "HARASSMENT": "Harassment", "SEXUALLY_EXPLICIT": "Sexually explicit",
              "DANGEROUS": "Dangerous content"}


def template_ids(extension: dict | None) -> list[str]:
    """Template resource names referenced by a Model Armor authz extension (request first)."""
    md = (extension or {}).get("metadata") or {}
    raw = md.get("model_armor_settings") or md.get("modelArmorSettings")
    if not raw:
        return []
    try:
        items = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return []
    out: list[str] = []
    for it in items if isinstance(items, list) else [items]:
        for k in ("request_template_id", "response_template_id", "requestTemplateId", "responseTemplateId"):
            v = (it or {}).get(k)
            if v and v not in out:
                out.append(v)
    return out


def _enabled(s: dict | None) -> bool:
    return bool(s) and (s.get("filterEnforcement") or "ENABLED") == "ENABLED"


def parse_template(t: dict[str, Any]) -> Template:
    fc = t.get("filterConfig") or {}
    pi = fc.get("piAndJailbreakFilterSettings")
    sdp = fc.get("sdpSettings") or {}
    sdp_basic, sdp_adv = sdp.get("basicConfig"), sdp.get("advancedConfig")
    mal = fc.get("maliciousUriFilterSettings")
    rai = [{"category": f.get("filterType", ""), "level": f.get("confidenceLevel", "")}
           for f in (fc.get("raiSettings") or {}).get("raiFilters", []) or []]
    filters: dict[str, Any] = {
        "pi_jailbreak": {"enabled": _enabled(pi), **({"level": pi.get("confidenceLevel")} if pi and
                                                      pi.get("confidenceLevel") else {})},
        "sdp": {"enabled": bool(sdp_adv) or _enabled(sdp_basic),
                **({"mode": "advanced"} if sdp_adv else {"mode": "basic"} if sdp_basic else {})},
        "rai": rai,
        "malicious_uri": {"enabled": _enabled(mal)},
    }
    md = t.get("templateMetadata") or {}
    block = md.get("customPromptSafetyErrorMessage") or md.get("customLlmResponseSafetyErrorMessage")
    name = t.get("name", "")
    return Template(name=name, id=name.rsplit("/", 1)[-1], filters=filters, block_message=block,
                    summary=summarize(filters, block), raw=t)


def summarize(filters: dict[str, Any], block: str | None = None) -> list[str]:
    out: list[str] = []
    pi = filters.get("pi_jailbreak") or {}
    out.append("Prompt injection / jailbreak: " + (
        LEVELS.get(pi.get("level", ""), (pi.get("level") or "on").lower().replace("_", " ")) if pi.get("enabled")
        else "off"))
    sdp = filters.get("sdp") or {}
    out.append("Sensitive data: " + (f"{sdp.get('mode', 'basic')} (e.g. credit card, SSN)" if sdp.get("enabled")
                                     else "off"))
    rai = filters.get("rai") or []
    out.append("Responsible AI: " + (", ".join(
        f"{RAI_LABELS.get(r['category'], r['category'])} ({LEVELS.get(r['level'], r['level'].lower())})" for r in rai)
        if rai else "off"))
    out.append("Malicious URLs: " + ("on" if (filters.get("malicious_uri") or {}).get("enabled") else "off"))
    if block:
        out.append(f"Block message: {block}")
    return out


def region_of(template_name: str, default: str) -> str:
    p = (template_name or "").split("/")
    return p[3] if len(p) > 3 and p[2] == "locations" else default


def get_template(r: Rest, name: str, region: str) -> dict | None:
    return r.get(f"{modelarmor(region_of(name, region))}/{name}", ok404=True)


def list_templates(r: Rest, project: str, region: str) -> list[dict]:
    return r.list_all(f"{modelarmor(region)}/projects/{project}/locations/{region}/templates", "templates")


# ====================================================================== setup (template, extension, service agents)
# Roles a gateway's service agent needs on the template's project so the gateway can call Model Armor.
MA_ROLES = ["roles/modelarmor.calloutUser", "roles/modelarmor.user", "roles/serviceusage.serviceUsageConsumer"]
RAI_CATEGORIES = ["HATE_SPEECH", "HARASSMENT", "SEXUALLY_EXPLICIT", "DANGEROUS"]
DEFAULT_BLOCK_MESSAGE = "This request was blocked by your organization's AI safety policy."


def template_name(project: str, region: str, template: str) -> str:
    return template if template.startswith("projects/") else f"projects/{project}/locations/{region}/templates/{template}"


def template_body(filters: Any, block_message: str | None, inspect_template: str | None = None) -> dict[str, Any]:
    """REST body of a Model Armor template from the friendly choices (TemplateFilters or an equivalent dict)."""
    f = filters.model_dump() if hasattr(filters, "model_dump") else dict(filters or {})
    fc: dict[str, Any] = {}
    pi = f.get("pi_jailbreak", "MEDIUM_AND_ABOVE")
    if pi and pi != "off":
        fc["piAndJailbreakFilterSettings"] = {"filterEnforcement": "ENABLED", "confidenceLevel": pi}
    sdp = f.get("sdp", "basic")
    if sdp == "basic":
        fc["sdpSettings"] = {"basicConfig": {"filterEnforcement": "ENABLED"}}
    elif sdp == "advanced":
        fc["sdpSettings"] = {"advancedConfig": {"inspectTemplate": inspect_template or "INSPECT_TEMPLATE"}}
    if f.get("malicious_uri", True):
        fc["maliciousUriFilterSettings"] = {"filterEnforcement": "ENABLED"}
    rai = [{"filterType": c, "confidenceLevel": lv} for c, lv in (f.get("rai") or {}).items() if lv and lv != "off"]
    if rai:
        fc["raiSettings"] = {"raiFilters": rai}
    md: dict[str, Any] = {}
    if block_message:
        md.update(customPromptSafetyErrorCode=403, customPromptSafetyErrorMessage=block_message,
                  customLlmResponseSafetyErrorCode=403, customLlmResponseSafetyErrorMessage=block_message)
    md.update(logSanitizeOperations=True, logTemplateOperations=True)
    return {"filterConfig": fc, "templateMetadata": md}


def extension_body(region: str, template: str) -> dict[str, Any]:
    """REST body of a Model Armor authz extension (networkservices) that screens requests and responses with
    `template` (full resource name)."""
    return {"service": f"modelarmor.{region}.rep.googleapis.com", "failOpen": False, "timeout": "5s",
            "metadata": {"model_armor_settings": json.dumps([{"request_template_id": template,
                                                              "response_template_id": template}])}}


def normalize_member(m: str) -> str:
    m = (m or "").strip()
    if not m or ":" in m:
        return m
    return f"serviceAccount:{m}" if m.endswith("gserviceaccount.com") else f"user:{m}"


def roles_of(policy: dict | None, member: str) -> dict[str, bool]:
    """{role: True} for each Model Armor role `member` holds unconditionally in a project IAM policy."""
    member = normalize_member(member)
    have = {b.get("role") for b in (policy or {}).get("bindings") or []
            if member in (b.get("members") or []) and not b.get("condition")}
    return {r: r in have for r in MA_ROLES}


def service_agents(raw_gateways: list[dict], numbers: dict[str, str]) -> list[dict[str, Any]]:
    """The identities a gateway uses to call Model Armor.

    Every gateway with an agentGatewayCard names its service extensions service account
    (service-<N>@gcp-sa-dep.iam.gserviceaccount.com). Ingress (CLIENT_TO_AGENT) gateways also need the Agent
    Runtime service agent service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com (verified in one
    project; check yours). `numbers`: {project id: project number}.
    """
    out: dict[str, dict[str, Any]] = {}

    def add(email: str, gw: dict, source: str, note: str) -> None:
        if not email:
            return
        if email in out:
            out[email]["gateways"].append(gw.get("name", ""))
            return
        out[email] = {"email": email, "member": f"serviceAccount:{email}", "gateway": gw.get("name", ""),
                      "gateways": [gw.get("name", "")], "project": gw.get("_project", ""), "source": source,
                      "note": note}

    for g in raw_gateways:
        card = g.get("agentGatewayCard") or {}
        add(card.get("serviceExtensionsServiceAccount", ""), g, "agentGatewayCard.serviceExtensionsServiceAccount",
            "The gateway's service extensions service account (from the gateway resource).")
        if (g.get("googleManaged") or {}).get("governedAccessPath") == "CLIENT_TO_AGENT":
            num = numbers.get(g.get("_project", ""))
            if num:
                add(f"service-{num}@gcp-sa-aiplatform-re.iam.gserviceaccount.com", g, "ingress",
                    "Agent Runtime service agent used by ingress gateways (verified in one project; check yours).")
    return list(out.values())


def suggested_prefix(gateway_ids: list[str]) -> str:
    for gid in gateway_ids:
        head = (gid or "").split("-", 1)[0]
        if head and head not in ("gateway", "gw"):
            return head
    return "policy-studio"


def unique(name: str, taken: set[str]) -> str:
    if name not in taken:
        return name
    n = 2
    while f"{name}-{n}" in taken:
        n += 1
    return f"{name}-{n}"


def setup_status(*, region: str, templates: list[Template], extensions: list[dict], agents: list[dict],
                 gateway_ids: list[str]) -> dict[str, Any]:
    """The `setup` object of GET /model-armor: what Model Armor on a gateway still needs in this region."""
    missing: list[str] = []
    if not templates:
        missing.append("template")
    if not extensions:
        missing.append("extension")
    if any(v is False for a in agents for v in (a.get("roles") or {}).values()):
        missing.append("service_agent_roles")
    prefix = suggested_prefix(gateway_ids)
    tmpl_ids = {t.id for t in templates}
    ext_ids = {x["name"].rsplit("/", 1)[-1] for x in extensions}
    used = [t for x in extensions for t in x.get("templates", [])]
    return {"ready": not missing, "missing": missing, "region": region,
            "extensions": extensions, "templates": templates, "service_agents": agents,
            "roles": list(MA_ROLES),
            "suggested": {"template_id": unique(f"{prefix}-shield", tmpl_ids),          # for a new template
                          "template": used[0] if used else (templates[0].name if templates else None),  # to reuse
                          "extension_name": unique(f"{prefix}-ma-authz", ext_ids)}}
