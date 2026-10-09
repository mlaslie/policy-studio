"""Agent Gateway request logs (read-only): Cloud Logging entries:list on the gateway_requests log.

  POST https://logging.googleapis.com/v2/entries:list  (a read; Rest.post allows it)
  filter: logName="projects/P/logs/networkservices.googleapis.com%2Fgateway_requests"
          AND resource.labels.gateway_name="GATEWAY" AND timestamp>="SINCE"

Entry format, as seen live on an enforcing egress gateway (Oct 2026):
  jsonPayload.authzPolicyInfo        {result: ALLOWED|DENIED, policies: [{name, result}]}  (absent on some entries)
  jsonPayload.agentGatewayInfo       {agentRegistryResource, mcpInfo?: {method: "tools/call", parameter: TOOL}}
  jsonPayload.enforcedGatewaySecurityPolicy.hostname, jsonPayload.tlsSniHostname
  httpRequest.status                 403 when IAP denied the call
The caller's identity isn't in the entry.

Classification (tolerant; the dry-run format has NOT been seen live): a DENIED IAP result with a 2xx/3xx status is
"would_deny" (dry run: IAP said no, the request went through); DENIED with a 4xx/5xx (or no status) is "denied";
any result or policy entry that mentions DRY_RUN together with a deny is "would_deny" too; everything else is
"allowed".
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote

from .rest import LOGGING, Rest

LOG_ID = "networkservices.googleapis.com%2Fgateway_requests"
MAX_LIMIT = 1000


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


def _is_deny(v: Any) -> bool:
    return "DEN" in str(v or "").upper()


def _is_dry(v: Any) -> bool:
    return "DRY" in str(v or "").upper()


def classify(entry: dict[str, Any]) -> str:
    """allowed | denied | would_deny (see the module docstring)."""
    jp = entry.get("jsonPayload") or {}
    info = jp.get("authzPolicyInfo") or {}
    pols = [p for p in info.get("policies") or [] if isinstance(p, dict)]
    results = [info.get("result")] + [p.get("result") for p in pols]
    denied = any(_is_deny(r) for r in results)
    if not denied:
        return "allowed"
    dry_marked = any(_is_dry(r) for r in results) or any(
        _is_dry(p.get(k)) for p in pols for k in ("mode", "enforcementMode", "dryRun", "details")) or \
        _is_dry(info.get("mode")) or info.get("dryRun") is True or any(p.get("dryRun") is True for p in pols)
    status = (entry.get("httpRequest") or {}).get("status")
    try:
        code = int(status) if status is not None else None
    except (TypeError, ValueError):
        code = None
    if dry_marked or (code is not None and code < 400):
        return "would_deny"
    return "denied"


def parse_entry(entry: dict[str, Any], project: str, labels: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """One log entry -> {decision, status, host, mcp_tool, mcp_method, destination, registry_resource, policies,
    timestamp, method, url, console_url, insert_id}. `labels`: {registry resource tail: display name}."""
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
    }


def fetch(r: Rest, projects: list[str], gateway: str, since: str = "24h", limit: int = 200,
          labels: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Recent request log entries of one gateway, newest first, classified."""
    limit = max(1, min(int(limit or 200), MAX_LIMIT))
    since_ts = parse_since(since)
    flt = log_filter(projects, gateway, since_ts)
    entries: list[dict] = []
    token: Optional[str] = None
    while len(entries) < limit:
        body: dict[str, Any] = {"resourceNames": [f"projects/{p}" for p in dict.fromkeys(projects)], "filter": flt,
                                "orderBy": "timestamp desc", "pageSize": min(limit - len(entries), 1000)}
        if token:
            body["pageToken"] = token
        res = r.post(f"{LOGGING}/entries:list", json=body) or {}
        entries += res.get("entries") or []
        token = res.get("nextPageToken")
        if not token:
            break
    project = projects[0]
    out = [parse_entry(e, project, labels) for e in entries[:limit]]
    counts = {"allowed": 0, "denied": 0, "would_deny": 0}
    for e in out:
        counts[e["decision"]] += 1
    return {"gateway": gateway, "since": since_ts, "filter": flt, "entries": out, "counts": counts,
            "truncated": bool(token) or len(entries) > limit, "console_url": console_url(project, flt)}
