"""Agent Gateway request logs (read-only): Cloud Logging entries:list on the gateway_requests log.

  POST https://logging.googleapis.com/v2/entries:list  (a read; Rest.post allows it)
  filter: logName="projects/P/logs/networkservices.googleapis.com%2Fgateway_requests"
          AND resource.labels.gateway_name="GATEWAY" AND timestamp>="SINCE"

Entry format, as seen live (Oct 2026):
  jsonPayload.authzPolicyInfo        {result: ALLOWED|DENIED, policies: [{name, result}]}  (absent on some entries)
  jsonPayload.agentGatewayInfo       {agentRegistryResource, mcpInfo?: {method: "tools/call", parameter: TOOL}}
  jsonPayload.enforcedGatewaySecurityPolicy.hostname, jsonPayload.tlsSniHostname
  jsonPayload.mtls.clientCertSha256Fingerprint   the calling agent's client certificate (per engine; rotates)
  httpRequest.status                 403 when IAP denied the call
The caller's identity isn't in the entry. In dry run a call IAP would deny is logged exactly like an allowed one
(status 200, result ALLOWED, every policy ALLOWED), so the log alone can't tell them apart: dryrun.py computes it.

Classification here is what the log says: a DENIED result (or status 403) is "denied", everything else "allowed".

Caller: the fingerprint is the same on the engine's own platform calls through the gateway, whose URL names it
(.../reasoningEngines/<id>/...), so caller_map learns {fingerprint: engine id} from those (a second entries:list).

Platform traffic (seen live, Oct 2026): much of an egress gateway's log is the agent runtime's own calls, e.g. to
<region>-aiplatform.mtls.googleapis.com (sessions, memory; registered in Agent Registry as an endpoint) and to
240.0.0.2:443 (an internal platform address, no agentRegistryResource). In one hour 123 of the newest 200 entries
were aiplatform calls. parse_entry flags these `platform` (is_platform). On a dry-run gateway the newest `limit`
entries can then be mostly platform calls, so fetch(checked=True) runs a second entries:list that leaves out the
platform hosts (checked_filter) and adds what it finds, up to CHECK_CAP entries: every non-platform entry of the
window is checked unless that cap is hit (checked_truncated).
"""
from __future__ import annotations

import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote

from .rest import LOGGING, Rest

LOG_ID = "networkservices.googleapis.com%2Fgateway_requests"
MAX_LIMIT = 1000
CHECK_CAP = 1000      # entries the platform-free query of a dry-run gateway may add
MAX_PAGES = 10        # per entries:list query (a page can come back short with a nextPageToken)

# Hosts left out of the platform-free query: Agent Platform API hosts (us-east4-aiplatform.mtls.googleapis.com, ...)
# and IPv4 literals (240.0.0.2:443), with an optional port. RE2, written without backslashes (a filter string would
# need them doubled).
PLATFORM_HOST_RE = ("^([a-z0-9-]*aiplatform[a-z0-9.-]*[.]googleapis[.]com|[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)"
                    "(:[0-9]+)?$")
_PLATFORM_RE = re.compile(PLATFORM_HOST_RE)


def parse_since(since: str, now: Optional[datetime] = None) -> str:
    """'24h' / '30m' / '7d' / an RFC 3339 timestamp -> RFC 3339 UTC timestamp."""
    now = now or datetime.now(timezone.utc)
    s = (since or "24h").strip()
    m = re.fullmatch(r"(\d+)\s*([smhd])", s)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n), "h": timedelta(hours=n),
                 "d": timedelta(days=n)}[unit]
        return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"since must be like 24h, 30m, 7d or an RFC 3339 timestamp, not {since!r}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_filter(projects: list[str], gateway: str, since_ts: str) -> str:
    names = [f'logName="projects/{p}/logs/{LOG_ID}"' for p in dict.fromkeys(projects)]
    lg = names[0] if len(names) == 1 else "(" + " OR ".join(names) + ")"
    return f'{lg} AND resource.labels.gateway_name="{gateway}" AND timestamp>="{since_ts}"'


def console_url(project: str, query: str, ts: str = "") -> str:
    url = "https://console.cloud.google.com/logs/query;query=" + quote(query, safe="")
    if ts:
        url += ";cursorTimestamp=" + quote(ts, safe="")
    return url + f"?project={quote(project, safe='')}"


def _short(name: str) -> str:
    return (name or "").rstrip("/").split("/")[-1]


def classify(entry: dict[str, Any]) -> str:
    """allowed | denied, as logged (see the module docstring; would_deny is computed by dryrun.py)."""
    jp = entry.get("jsonPayload") or {}
    info = jp.get("authzPolicyInfo") or {}
    pols = [p for p in info.get("policies") or [] if isinstance(p, dict)]
    if any(str(r or "").upper() == "DENIED" for r in [info.get("result")] + [p.get("result") for p in pols]):
        return "denied"
    try:
        return "denied" if int((entry.get("httpRequest") or {}).get("status")) == 403 else "allowed"
    except (TypeError, ValueError):
        return "allowed"


def fingerprint(entry: dict[str, Any]) -> Optional[str]:
    return ((entry.get("jsonPayload") or {}).get("mtls") or {}).get("clientCertSha256Fingerprint") or None


def _bare_host(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("["):                                   # [v6]:port
        return h[1:h.find("]")] if "]" in h else h[1:]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(_bare_host(host))
        return True
    except ValueError:
        return False


def is_platform(host: str, registered: bool) -> bool:
    """The agent runtime's own traffic rather than a call the agent chose to make: an IP literal (240.0.0.0/4 is the
    platform's internal range), a *.google.internal host, or an Agent Platform API host (aiplatform*.googleapis.com,
    registered or not); with no Agent Registry resource, any *.googleapis.com host too."""
    h = _bare_host(host)
    if not h:
        return False
    if is_ip(h) or h.endswith(".google.internal") or _PLATFORM_RE.match(h):
        return True
    return not registered and h.endswith(".googleapis.com")


def checked_filter(projects: list[str], gateway: str, since_ts: str) -> str:
    """The gateway's entries minus the platform hosts PLATFORM_HOST_RE matches (entries without the field stay in)."""
    return (f'{log_filter(projects, gateway, since_ts)} AND '
            f'NOT jsonPayload.enforcedGatewaySecurityPolicy.hostname=~"{PLATFORM_HOST_RE}"')


def caller_filter(projects: list[str], gateway: str, since_ts: str, engine_ids: list[str]) -> str:
    """The engines' own platform calls through the gateway (their URL names the engine)."""
    urls = " OR ".join(f'httpRequest.requestUrl:"reasoningEngines/{e}/"' for e in engine_ids)
    return f"{log_filter(projects, gateway, since_ts)} AND ({urls})"


def caller_map(entries: list[dict[str, Any]], engine_ids: list[str]) -> dict[str, str]:
    """{client cert fingerprint: engine id} from platform entries; a fingerprint seen with more than one engine is
    dropped (ambiguous)."""
    seen: dict[str, set[str]] = {}
    for e in entries:
        fp, url = fingerprint(e), (e.get("httpRequest") or {}).get("requestUrl") or ""
        for eid in engine_ids:
            if fp and f"reasoningEngines/{eid}/" in url:
                seen.setdefault(fp, set()).add(eid)
    return {fp: next(iter(v)) for fp, v in seen.items() if len(v) == 1}


def fetch_callers(r: Rest, projects: list[str], gateway: str, since_ts: str, engine_ids: list[str]) -> dict[str, str]:
    """caller_map over the engines' platform calls since `since_ts` (one page of up to 500 entries)."""
    if not engine_ids:
        return {}
    body = {"resourceNames": [f"projects/{p}" for p in dict.fromkeys(projects)],
            "filter": caller_filter(projects, gateway, since_ts, engine_ids), "orderBy": "timestamp desc",
            "pageSize": 500}
    return caller_map((r.post(f"{LOGGING}/entries:list", json=body) or {}).get("entries") or [], engine_ids)


def parse_entry(entry: dict[str, Any], project: str, labels: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """One log entry -> {decision, status, host, mcp_tool, mcp_method, destination, registry_resource, policies,
    timestamp, method, url, console_url, insert_id, client_cert}. `labels`: {registry resource tail: display name}."""
    jp = entry.get("jsonPayload") or {}
    http = entry.get("httpRequest") or {}
    gi = jp.get("agentGatewayInfo") or {}
    mcp = gi.get("mcpInfo") or {}
    info = jp.get("authzPolicyInfo") or {}
    url = http.get("requestUrl") or ""
    host = ((jp.get("enforcedGatewaySecurityPolicy") or {}).get("hostname") or jp.get("tlsSniHostname")
            or (re.match(r"^[a-z]+://([^/:]+)", url) or [None, ""])[1] or "")
    res = gi.get("agentRegistryResource") or ""
    tail = res[res.find("/locations/") + 1:] if "/locations/" in res else res
    labels = labels or {}
    method = mcp.get("method") or ""
    tool = mcp.get("parameter") if method == "tools/call" else None
    ts = entry.get("timestamp") or ""
    q = f'insertId="{entry.get("insertId", "")}"' if entry.get("insertId") else ""
    return {
        "decision": classify(entry),
        "status": http.get("status"),
        "host": host,
        "mcp_tool": tool,
        "mcp_method": method or None,
        "registry_resource": res or None,
        "destination": labels.get(tail) or (_short(res) if res else host),
        "policies": [{"name": p.get("name", ""), "result": p.get("result", "")}
                     for p in info.get("policies") or [] if isinstance(p, dict)],
        "authz_result": info.get("result"),
        "timestamp": ts,
        "method": http.get("requestMethod"),
        "url": url,
        "insert_id": entry.get("insertId"),
        "console_url": console_url(project, q, ts) if q else None,
        "client_cert": fingerprint(entry),
        "platform": is_platform(host, bool(res)),
    }


def count(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"allowed": 0, "denied": 0, "would_deny": 0, "unknown": 0, "platform": 0}
    for e in entries:
        counts[e["decision"]] = counts.get(e["decision"], 0) + 1
    return counts


def _list(r: Rest, projects: list[str], flt: str, cap: int, fields: str = "") -> tuple[list[dict], bool]:
    """Up to `cap` entries matching `flt`, newest first, in at most MAX_PAGES pages. (entries, more were left out)
    `fields`: a partial response (the system parameter), e.g. "entries(timestamp,jsonPayload),nextPageToken"."""
    url = f"{LOGGING}/entries:list" + (f"?fields={quote(fields, safe='(),/')}" if fields else "")
    entries: list[dict] = []
    token: Optional[str] = None
    for _ in range(MAX_PAGES):
        body: dict[str, Any] = {"resourceNames": [f"projects/{p}" for p in dict.fromkeys(projects)], "filter": flt,
                                "orderBy": "timestamp desc", "pageSize": min(cap - len(entries), 1000)}
        if token:
            body["pageToken"] = token
        res = r.post(url, json=body) or {}
        entries += res.get("entries") or []
        token = res.get("nextPageToken")
        if not token or len(entries) >= cap:
            break
    return entries[:cap], bool(token) or len(entries) > cap


def fetch(r: Rest, projects: list[str], gateway: str, since: str = "24h", limit: int = 200,
          labels: Optional[dict[str, str]] = None, checked: bool = False) -> dict[str, Any]:
    """Recent request log entries of one gateway, newest first, classified as logged (allowed / denied).

    checked (a dry-run gateway, whose entries get checked against the grants): when the newest `limit` entries
    don't cover the window, a second query (checked_filter) adds the window's non-platform entries, up to CHECK_CAP,
    so a would-be-denied call isn't pushed out by platform traffic. `truncated`: some entries of the window aren't
    in `entries`; `checked_truncated`: even the non-platform ones were capped (would-deny may be incomplete)."""
    limit = max(1, min(int(limit or 200), MAX_LIMIT))
    since_ts = parse_since(since)
    flt = log_filter(projects, gateway, since_ts)
    project = projects[0]
    entries, truncated = _list(r, projects, flt, limit)
    checked_truncated = False
    extra = 0
    if checked and truncated:
        more, checked_truncated = _list(r, projects, checked_filter(projects, gateway, since_ts), CHECK_CAP)
        seen = {e.get("insertId") for e in entries}
        add = [e for e in more if e.get("insertId") not in seen]
        extra = len(add)
        entries = sorted(entries + add, key=lambda e: e.get("timestamp") or "", reverse=True)
    out = [parse_entry(e, project, labels) for e in entries]
    return {"gateway": gateway, "since": since_ts, "filter": flt, "entries": out, "counts": count(out),
            "truncated": truncated, "checked_truncated": checked_truncated, "checked_extra": extra,
            "console_url": console_url(project, flt)}
