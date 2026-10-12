"""Plain-English labels for IAM members, conditions, bindings and intents."""
from __future__ import annotations

import re
from typing import Mapping, Optional

from .conditions import EGRESSOR, classify
from .model import Binding, Condition, Intent

PROJECT_AGENTS_RE = re.compile(r"^principalSet://[^/]+/attribute\.platformContainer/aiplatform/projects/(\d+)$")
ENGINE_PRINCIPAL_RE = re.compile(
    r"^principal://[^/]+/resources/aiplatform/projects/(\d+)/locations/([^/]+)/reasoningEngines/([^/]+)$")

ROLE_LABELS = {
    EGRESSOR: "may send traffic to it through Agent Gateway",
    "roles/iap.httpsResourceAccessor": "may access it through IAP",
}


def engine_principal_parts(member: str) -> Optional[tuple[str, str, str]]:
    """(project number, region, engine id) of an Agent Identity principal, else None."""
    m = ENGINE_PRINCIPAL_RE.match(member or "")
    return (m.group(1), m.group(2), m.group(3)) if m else None


def member_label(member: str, engines: Optional[Mapping[str, str]] = None) -> str:
    """`engines`: {principal: engine display name}."""
    engines = engines or {}
    if member in engines:
        return f"{engines[member]} (Agent Identity)"
    m = PROJECT_AGENTS_RE.match(member or "")
    if m:
        return "All agents in project"
    parts = engine_principal_parts(member)
    if parts:
        return f"Agent Runtime engine {parts[2]} (Agent Identity)"
    if member == "allUsers":
        return "Anyone on the internet (allUsers)"
    if member == "allAuthenticatedUsers":
        return "Any signed-in Google account (allAuthenticatedUsers)"
    return member


def condition_english(cond: Optional[Condition | dict]) -> str:
    acc = classify(cond)
    if acc.mode == "all":
        return "all tools"
    if acc.mode == "read_only_hint":
        return "only read-only tools (by MCP hint)"
    if acc.mode == "tools":
        return "only tools: " + ", ".join(acc.tools or []) if acc.tools else "no tools (MCP setup calls only)"
    return "custom condition"


def access_phrase(cond: Optional[Condition | dict], kind: str = "mcp_server") -> str:
    """'full access' for unconditional grants on A2A agents / endpoints, else the condition in English."""
    if not cond:
        return "all tools" if kind == "mcp_server" else "full access"
    return condition_english(cond)


def binding_english(member_lbl: str, role: str, cond: Optional[Condition | dict], resource_label: str,
                    kind: str = "mcp_server") -> str:
    if role == EGRESSOR:
        return f"{member_lbl} → {resource_label}: {access_phrase(cond, kind)}"
    return f"{member_lbl} has {role} on {resource_label}" + (f" ({condition_english(cond)})" if cond else "")


def make_binding(role: str, member: str, cond: Optional[dict], resource_label: str, kind: str,
                 engines: Optional[Mapping[str, str]] = None) -> Binding:
    lbl = member_label(member, engines)
    c = Condition(title=cond.get("title", ""), expression=cond.get("expression", ""),
                  description=cond.get("description")) if cond else None
    return Binding(role=role, member=member, member_label=lbl, condition=c,
                   english=binding_english(lbl, role, c, resource_label, kind))


def _dest_label(intent: Intent) -> str:
    d = intent.destination
    return (d.label or d.name or d.id) if d else "the destination"


def _src_label(intent: Intent) -> str:
    s = intent.source
    return (s.label or member_label(s.principal)) if s else "the source"


def _short(name: str) -> str:
    return (name or "").rstrip("/").split("/")[-1]


def intent_english(intent: Intent) -> str:
    k = intent.kind
    if k in ("grant", "revoke"):
        dest = _dest_label(intent)
        kind = intent.destination.kind if intent.destination else "mcp_server"
        acc = intent.access
        if acc and acc.mode == "custom" and (acc.expression or "").strip():
            acc = classify({"expression": acc.expression})     # an exact existing condition: describe what it is
        mode = acc.mode if acc else "all"
        if mode == "all":
            what = f"call all tools of {dest}" if kind == "mcp_server" else f"call {dest} (full access)"
        elif mode == "read_only_hint":
            what = f"call only the read-only tools of {dest} (by MCP hint; new read-only tools are included automatically)"
        elif mode == "tools":
            tools = [t for t in (acc.tools or []) if t]
            what = (f"call only these tools of {dest}: {', '.join(tools)}" if tools
                    else f"reach {dest} for MCP setup calls only (no tools)")
        else:
            what = f"call {dest} when a custom condition holds"
        if k == "grant":
            return f"{_src_label(intent)} can {what}."
        return f"Revoke: {_src_label(intent)} can no longer {what}."
    gw = intent.gateway
    eng = _short(intent.engine or "") or "the engine"
    if k == "bind_gateway":
        return (f"Route agent {eng}'s {'outbound (egress)' if gw and gw.direction == 'egress' else 'inbound (ingress)'} "
                f"traffic through Agent Gateway {_short(gw.name) if gw else '?'}.")
    if k == "unbind_gateway":
        return (f"Stop routing agent {eng}'s {gw.direction if gw else ''} traffic through Agent Gateway "
                f"{_short(gw.name) if gw else '?'}.")
    if k == "model_armor_on":
        return f"Screen traffic on Agent Gateway {_short(gw.name) if gw else '?'} with Model Armor."
    if k == "model_armor_off":
        return f"Stop screening traffic on Agent Gateway {_short(gw.name) if gw else '?'} with Model Armor."
    if k == "set_enforcement":
        g = _short(gw.name) if gw else "?"
        return (f"Enforce IAP on gateway {g}." if intent.mode == "ENFORCE" else
                f"Put gateway {g} in dry run: nothing is blocked (calls IAP would deny pass and are logged as allowed).")
    if k == "dedicate_extension":
        g = _short(gw.name) if gw else "?"
        new = _short(intent.new_name or "") or "a new extension"
        if intent.revert:
            return f"Point {g}'s IAP policy back at {_short(intent.source_extension or '')} and delete {new}."
        return f"Give gateway {g} its own IAP extension {new}."
    p = intent.params
    delete = bool(p and p.delete)
    if k == "model_armor_template":
        tid = _short((p.template_id if p else "") or "") or "TEMPLATE_ID"
        return (f"Delete Model Armor template {tid}." if delete else
                f"Create Model Armor template {tid}: the filters Model Armor applies to prompts and responses.")
    if k == "model_armor_extension":
        name = _short((p.name if p else "") or "") or "EXTENSION"
        tmpl = _short((p.template if p else "") or "") or "TEMPLATE"
        return (f"Delete Model Armor authz extension {name}." if delete else
                f"Create Model Armor authz extension {name}, which screens with template {tmpl}.")
    if k == "iam_project_grant":
        member = member_label((p.member if p else "") or "") or "the service agent"
        roles = ", ".join((p.roles if p else None) or []) or "no roles"
        where = f" on project {p.project}" if p and p.project else ""
        return (f"Remove {roles} from {member}{where}." if delete else
                f"Let {member} call Model Armor: grant {roles}{where}.")
    return k
