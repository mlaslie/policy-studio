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
