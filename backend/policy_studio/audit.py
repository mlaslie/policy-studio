"""Audit: every grant in plain English, plus findings with a suggested fix Intent where one is obvious."""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from .conditions import EGRESSOR, classify
from .english import PROJECT_AGENTS_RE, engine_principal_parts
from .gcp.engines import REDEPLOY_SNIPPET
from .model import (Access, Context, Destination, Finding, Gateway, GatewayRef, Grant, Intent, Inventory,
                    McpServer, Source)

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


def _id(*parts: Any) -> str:
    return "fix-" + hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:10]


def resource_index(inv: Inventory) -> dict[str, tuple[str, str, str]]:
    """{registry resource name: (kind, id, label)}"""
    idx: dict[str, tuple[str, str, str]] = {}
    for a in inv.agents:
        idx[a.name] = ("agent", a.id, a.display_name)
    for m in inv.mcp_servers:
        idx[m.name] = ("mcp_server", m.id, m.display_name)
    for e in inv.endpoints:
        idx[e.name] = ("endpoint", e.id, e.display_name)
    return idx


def grants(inv: Inventory) -> list[Grant]:
    idx = resource_index(inv)
    out: list[Grant] = []
    for res, bindings in inv.access.items():
        kind, _, label = idx.get(res, ("registry", "", "Agent Registry (all entries)"))
        for b in bindings:
            out.append(Grant(**b.model_dump(), resource=res, resource_kind=kind, resource_label=label))
    out.sort(key=lambda g: (g.resource_kind != "registry", g.member_label.lower(), g.resource_label.lower()))
    return out


def write_tools(m: McpServer) -> list[str]:
    """Tools that may change state: destructiveHint true, or not read-only with no destructiveHint
    (the MCP default for a non-read-only tool is destructive)."""
    return [t.name for t in m.tools if not t.read_only and t.annotations.get("destructiveHint", True)]


def _source(member: str, label: str, engines_by_principal: dict[str, Any]) -> Source:
    if member in engines_by_principal:
        e = engines_by_principal[member]
        return Source(type="engine", principal=member, label=e.display_name, engine=e.name)
    if PROJECT_AGENTS_RE.match(member):
        return Source(type="project_agents", principal=member, label=label)
    return Source(type="custom", principal=member, label=label)


def revoke_intent(g: Grant, engines_by_principal: dict[str, Any]) -> Optional[Intent]:
    if g.role != EGRESSOR:
        return None
    rid = "" if g.resource_kind == "registry" else g.resource.rsplit("/", 1)[-1]
    return Intent(id=_id("revoke", g.resource, g.member, g.condition.expression if g.condition else ""),
                  kind="revoke", source=_source(g.member, g.member_label, engines_by_principal),
                  destination=Destination(kind=g.resource_kind, id=rid, name=g.resource, label=g.resource_label),
                  access=classify(g.condition))


def _project_number(inv: Inventory, ctx: Optional[Context]) -> str:
    if ctx and ctx.project_number:
        return ctx.project_number
    for e in inv.engines:
        p = e.name.split("/")
        if len(p) > 1 and p[1].isdigit():
            return p[1]
    return ""


def audit(inv: Inventory, gateways: list[Gateway], ctx: Optional[Context] = None) -> dict[str, Any]:
    gs = grants(inv)
    findings: list[Finding] = []
    by_principal = {e.principal: e for e in inv.engines if e.principal}
    region = ctx.region if ctx else ""
    number = _project_number(inv, ctx)
    egress_gws = [g for g in gateways if g.type == "egress"]

    # 1. Agents not behind an egress gateway
    for e in inv.engines:
        if e.gateways.get("egress"):
            continue
        if not e.bindable:
            findings.append(Finding(
                severity="medium", title=f"Unprotected egress: {e.display_name}",
                detail=(f"{e.display_name} is not bound to an egress gateway, and it can't be: "
                        f"{e.bindable_reason or 'it was created before 2026-04-29.'} Until it is redeployed its "
                        "outbound traffic isn't governed by Agent Gateway."),
                resource=e.name, redeploy=REDEPLOY_SNIPPET))
            continue
        fix = None
        if len(egress_gws) == 1:
            fix = Intent(id=_id("bind", e.name, egress_gws[0].name), kind="bind_gateway", engine=e.name,
                         source=Source(type="engine", principal=e.principal, label=e.display_name, engine=e.name),
                         gateway=GatewayRef(name=egress_gws[0].name, direction="egress"))
        findings.append(Finding(
            severity="high", title=f"Unprotected egress: {e.display_name}",
            detail=(f"{e.display_name} is not bound to an egress gateway, so its outbound calls (A2A, MCP, APIs) are "
                    "not governed by Agent Gateway or IAP."
                    + (" Bind it to " + egress_gws[0].id + "." if fix else
                       " Create an egress gateway in this region first." if not egress_gws else
                       " Pick one of the egress gateways to bind it to.")
                    + ("" if e.principal.startswith("principal://") else
                       " It runs as a service account, not an Agent Identity, so IAP grants can't single it out; "
                       "redeploy it with Agent Identity.")),
            resource=e.name, fix=fix))

    # 2. Unconditional access to MCP servers with write / destructive tools
    mcp_by_name = {m.name: m for m in inv.mcp_servers}
    for g in gs:
        m = mcp_by_name.get(g.resource)
        if not m or g.role != EGRESSOR or g.condition:
            continue
        writes = write_tools(m)
        if not writes:
            continue
        src = _source(g.member, g.member_label, by_principal)
        fix = Intent(id=_id("ro", g.resource, g.member), kind="grant", source=src,
                     destination=Destination(kind="mcp_server", id=m.id, name=m.name, label=m.display_name),
                     access=Access(mode="read_only_hint"))
        rev = revoke_intent(g, by_principal)
        findings.append(Finding(
            severity="high", title=f"Unconditional access to {m.display_name}",
            detail=(f"{g.member_label} may call every tool of {m.display_name}, including "
                    f"{', '.join(writes[:6])}{'…' if len(writes) > 6 else ''}. Grant read-only tools instead "
                    "(by MCP hint or by name), then revoke the unconditional grant."),
            resource=g.resource, fix=fix, fixes=[x for x in (fix, rev) if x]))

    # 3. Grants to Agent Identities whose engine no longer exists
    ids = {e.id for e in inv.engines}
    for g in gs:
        parts = engine_principal_parts(g.member)
        if not parts or (number and parts[0] != number) or (region and parts[1] != region) or parts[2] in ids:
            continue
        findings.append(Finding(
            severity="medium", title=f"Grant to a deleted agent on {g.resource_label}",
            detail=(f"Agent Runtime engine {parts[2]} no longer exists in {parts[1]}, but its Agent Identity still "
                    f"holds {g.role} on {g.resource_label}. Revoke it."),
            resource=g.resource, fix=revoke_intent(g, by_principal)))

    # 4. Public members
    for g in gs:
        if g.member in PUBLIC_MEMBERS:
            findings.append(Finding(
                severity="high", title=f"{g.member} on {g.resource_label}",
                detail=f"{g.member_label} holds {g.role} on {g.resource_label}. Grant specific principals instead.",
                resource=g.resource, fix=revoke_intent(g, by_principal)))

    # 5. Grants that aren't enforced because the agent isn't behind an egress gateway
    for g in gs:
        e = by_principal.get(g.member)
        if e and g.role == EGRESSOR and not e.gateways.get("egress"):
            findings.append(Finding(
                severity="info", title=f"Grant not enforced: {e.display_name} → {g.resource_label}",
                detail=(f"{e.display_name} holds roles/iap.egressor on {g.resource_label}, but it isn't bound to an "
                        "egress gateway, so nothing checks this grant (its egress is unrestricted)."),
                resource=g.resource))

    # 6. Gateways without Model Armor; IAP in dry run
    for gw in gateways:
        if not any(p.profile == "CONTENT_AUTHZ" for p in gw.authz_policies):
            findings.append(Finding(
                severity="info", title=f"No Model Armor on {gw.id}",
                detail=(f"{gw.type.capitalize()} gateway {gw.id} has no CONTENT_AUTHZ policy, so prompts and "
                        "responses through it aren't screened by Model Armor."),
                resource=gw.name,
                fix=Intent(id=_id("ma", gw.name), kind="model_armor_on",
                           gateway=GatewayRef(name=gw.name, direction=gw.type))))
        for p in gw.authz_policies:
            if p.provider == "iap" and p.enforcement == "DRY_RUN":
                findings.append(Finding(
                    severity="medium", title=f"IAP in dry run on {gw.id}",
                    detail=(f"The IAP authz extension {p.extension.rsplit('/', 1)[-1]} on {gw.id} runs in DRY_RUN: "
                            "denials are only logged, every request is allowed. Switch it to ENFORCE "
                            "(remove metadata.iamEnforcementMode and set failOpen: false)."),
                    resource=p.extension))
        if gw.type == "egress" and not any(p.provider == "iap" for p in gw.authz_policies):
            findings.append(Finding(
                severity="medium", title=f"No IAP authorization on {gw.id}",
                detail=(f"Egress gateway {gw.id} has no REQUEST_AUTHZ policy with the IAP extension, so "
                        "roles/iap.egressor grants are not checked on it."), resource=gw.name))

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order[f.severity])
    return {"grants": gs, "findings": findings}

