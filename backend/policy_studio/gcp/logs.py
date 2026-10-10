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
    }


def count(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"allowed": 0, "denied": 0, "would_deny": 0, "unknown": 0}
    for e in entries:
        counts[e["decision"]] = counts.get(e["decision"], 0) + 1
    return counts


def fetch(r: Rest, projects: list[str], gateway: str, since: str = "24h", limit: int = 200,
          labels: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Recent request log entries of one gateway, newest first, classified as logged (allowed / denied)."""
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
    return {"gateway": gateway, "since": since_ts, "filter": flt, "entries": out, "counts": count(out),
            "truncated": bool(token) or len(entries) > limit, "console_url": console_url(project, flt)}
