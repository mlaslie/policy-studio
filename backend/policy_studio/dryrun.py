"""Would-deny on a dry-run egress gateway: computed from the current grants, not reported by Google.

In dry run, Agent Gateway logs every call IAP would deny exactly like an allowed one (seen live, Oct 2026):
httpRequest.status 200, jsonPayload.authzPolicyInfo.result ALLOWED and every policies[].result ALLOWED;
enforcedGatewaySecurityPolicy.matchedRules is the same in every mode, and no other log has a dry-run record. So for
each allowed entry Policy Studio works out the answer itself:

  caller       the entry doesn't name it. Matched by the mTLS client certificate fingerprint learned from the
               engine's own platform calls (logs.caller_map), else the only agent bound to the gateway, else unknown.
  destination  jsonPayload.agentGatewayInfo.agentRegistryResource (an agent, MCP server or endpoint).
  grants       roles/iap.egressor bindings on the destination and on the whole Agent Registry (inventory access),
               matched by the caller's principal, the "all agents in project" principalSet, allUsers and
               allAuthenticatedUsers.
  conditions   `toolName in [...]` and the read-only-hint condition are evaluated (MCP tools/call: the tool from
               jsonPayload.agentGatewayInfo.mcpInfo.parameter; other calls carry no tool name, i.e. ''). Any other
               condition, a tool missing from the inventory, a group / domain member or an unreadable IAP policy
               gives "unknown", never would_deny.
  platform     an entry with no Agent Registry resource whose host is platform traffic (logs.is_platform: an IP
               literal such as 240.0.0.2:443, *.google.internal, *.googleapis.com) is "platform": the agent runtime's
               own calls, which no roles/iap.egressor grant names, so they're neither checked nor "unknown". Platform
               hosts that are registered (an aiplatform endpoint) are checked like any destination.
Grants above the Agent Registry (project, folder, organization) aren't read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from .conditions import EGRESSOR, classify, parse_tools
from .english import ENGINE_PRINCIPAL_RE, PROJECT_AGENTS_RE
from .gcp.engines import tail
from .model import Binding, Inventory

KIND = {"agents": "agent", "mcpServers": "mcp_server", "endpoints": "endpoint"}
EVERYONE = ("allUsers", "allAuthenticatedUsers")
_TD_RE = re.compile(r"^principal(?:Set)?://([^/]+)/")


@dataclass
class Caller:
    engine: str                # full engine name
    display_name: str
    principal: str
    how: str                   # "mtls" (client certificate matched) | "only_bound_agent"


def member_matches(member: str, principal: str) -> Optional[bool]:
    """Does `member` include `principal`? None when it can't be told here (groups, domains)."""
    if member == principal or member in EVERYONE:
        return True
    ps = PROJECT_AGENTS_RE.match(member or "")
    eng = ENGINE_PRINCIPAL_RE.match(principal or "")
    if ps and eng:
        td_m, td_p = _TD_RE.match(member), _TD_RE.match(principal)
        return ps.group(1) == eng.group(1) and bool(td_m and td_p and td_m.group(1) == td_p.group(1))
    if (member or "").startswith(("group:", "domain:")):
        return None
    return False


def condition_allows(cond: Any, entry: dict[str, Any], tools: Optional[dict[str, bool]]) -> Optional[bool]:
    """Evaluate a binding condition for one log entry. `tools`: {tool name: read-only hint} of the destination MCP
    server (None = not an MCP server / unknown). None = can't be evaluated."""
    if not cond:
        return True
    expr = cond.get("expression", "") if isinstance(cond, dict) else cond.expression
    tool = entry.get("mcp_tool") if entry.get("mcp_method") == "tools/call" else None
    if tool is None and entry.get("mcp_method") == "tools/call":
        return None                                     # a tool call without the tool name: can't tell
    if classify({"expression": expr}).mode == "read_only_hint":
        if not tool:
            return True                                 # toolName '' (setup traffic, non-MCP calls)
        if tools is None or tool not in tools:
            return None
        return tools[tool]
    names = parse_tools(expr, keep_empty=True)
    if names is not None:
        return (tool or "") in names
    return None


def _cond_text(b: Binding) -> str:
    return f" (condition: {b.condition.title or b.condition.expression})" if b.condition else ""


def check(entry: dict[str, Any], caller: Optional[Caller], inv: Optional[Inventory]) -> tuple[str, str]:
    """(would_deny | allowed | unknown | platform, reason) for an allowed entry of a dry-run egress gateway."""
    if not entry.get("registry_resource") and entry.get("platform"):
        return "platform", (f"Platform traffic ({entry.get('host')}): the agent runtime's own call, with no Agent "
                            "Registry resource, so no roles/iap.egressor grant applies. Not checked.")
    if inv is None:
        return "unknown", "The grants couldn't be read (inventory unavailable), so this can't be checked."
    if caller is None:
        return "unknown", ("The log entry doesn't name the caller, and it couldn't be matched to one agent (none or "
                           "several agents are bound to this gateway, and its client certificate wasn't recognized).")
    res = entry.get("registry_resource") or ""
    rt = tail(res)
    parts = rt.split("/")
    if len(parts) != 4 or parts[2] not in KIND:
        return "unknown", "The log entry names no Agent Registry agent, MCP server or endpoint."
    region, kind = parts[1], KIND[parts[2]]
    items = {"agent": inv.agents, "mcp_server": inv.mcp_servers, "endpoint": inv.endpoints}[kind]
    item = next((x for x in items if tail(x.name) == rt), None)
    dest = item.display_name if item else parts[3]
    who = caller.display_name
    if item is None:
        return "unknown", f"{dest} isn't in the inventory (another project's registry?), so its grants weren't read."
    keys = {tail(k): k for k in inv.access}
    err_keys = {tail(k): k for k in inv.access_errors}
    reg_t = f"locations/{region}"
    if rt in err_keys:
        return "unknown", f"{dest}'s IAP policy couldn't be read."
    tools = {t.name: bool(t.read_only) for t in item.tools} if kind == "mcp_server" else None
    levels = [("", inv.access.get(keys.get(rt, ""), []) if rt in keys else []),
              (" (registry-wide)", inv.access.get(keys.get(reg_t, ""), []) if reg_t in keys else [])]
    limited: list[str] = []
    unknown: list[str] = []
    for where, bindings in levels:
        for b in bindings:
            if b.role != EGRESSOR:
                continue
            m = member_matches(b.member, caller.principal)
            if m is False:
                continue
            if m is None:
                unknown.append(f"{b.member_label or b.member} holds roles/iap.egressor on {dest}{where}, and group or "
                               "domain membership can't be checked here")
                continue
            ok = condition_allows(b.condition, entry, tools)
            via = "" if b.member == caller.principal else f" through {b.member_label or b.member}"
            if ok:
                return "allowed", f"{who} holds roles/iap.egressor on {dest}{where}{via}{_cond_text(b)}."
            if ok is None:
                unknown.append(f"the condition on {who}'s grant{via} on {dest}{where} can't be evaluated here"
                               f"{_cond_text(b)}")
            else:
                limited.append(f"{b.condition.title or b.condition.expression}" if b.condition else "")
    if reg_t in err_keys and not unknown:
        unknown.append("the Agent Registry's own IAP policy couldn't be read")
    if unknown:
        return "unknown", unknown[0][0].upper() + unknown[0][1:] + "."
    what = f"{entry.get('mcp_tool')}" if entry.get("mcp_method") == "tools/call" and entry.get("mcp_tool") else ""
    if limited:
        return "would_deny", (f"{who}'s roles/iap.egressor grant on {dest} is limited ({'; '.join(x for x in limited if x)})"
                              + (f" and doesn't cover {what}." if what else " and doesn't cover this call."))
    return "would_deny", f"{who} holds no roles/iap.egressor grant on {dest} (or on the whole Agent Registry)."
