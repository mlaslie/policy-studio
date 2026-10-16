"""Destination paths "seen in traffic" (read-only): per registry entry, how many calls through an egress gateway went
to a private upstream address and how many to a public one, from the gateway request logs.

  POST https://logging.googleapis.com/v2/entries:list  (a read; Rest.post allows it)
  filter: logs.log_filter(...) AND httpRequest.serverIp:* AND jsonPayload.agentGatewayInfo.agentRegistryResource:*

Seen live (P0_FINDINGS.md): `httpRequest.serverIp` is the upstream IP:port the gateway connected to. Through private
egress (a connectivity template, then a PSC endpoint or a VPC IP) it is a private address such as 10.x.x.x:443; Google
API calls under PRIVATE_RANGES_ONLY show public addresses; denied requests have no serverIp. The filter fetches only
entries that have both fields, so platform calls to IP literals (no registry resource) and denials aren't read at all.

This is the only per-destination signal that is certain: it says where calls actually went, not where they could go.
A destination reached both ways ("mixed") usually has several hostnames (only some peered into the VPC) or changed DNS
inside the window.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import logs as logs_mod
from .engines import tail
from .rest import Rest

DEFAULT_WINDOW = "7d"
MAX_WINDOW = timedelta(days=30)        # Cloud Logging's default retention (_Default bucket)
CAP = 5000                             # entries read per gateway (pages of up to 1000, logs.MAX_PAGES at most)
MAX_HOSTS = 5                          # hostnames kept per destination (to explain a mixed path)
# Partial response: what aggregate() reads (about 40% fewer bytes, seen live). jsonPayload is a Struct, so its own
# subfields can't be selected (the API rejects that).
FIELDS = "entries(timestamp,httpRequest(serverIp,status),jsonPayload),nextPageToken"

# RFC 1918, shared address space (CGNAT, RFC 6598) and IPv6 unique local addresses (RFC 4193).
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                  "fc00::/7")]


def bare_ip(server_ip: str) -> str:
    """'10.1.2.3:443' / '[fd00::1]:443' / 'fd00::1' / '10.1.2.3' -> the address alone."""
    s = (server_ip or "").strip()
    if s.startswith("["):
        return s[1:s.find("]")] if "]" in s else s[1:]
    return s.rsplit(":", 1)[0] if s.count(":") == 1 else s


def classify_ip(server_ip: str) -> str:
    """private | public | unknown. private: RFC 1918, 100.64/10 or fc00::/7 (an IPv4-mapped IPv6 address counts as its
    IPv4 address). public: globally routable. unknown: empty, not an address, or neither (loopback, link-local, the
    platform's 240.0.0.0/4, multicast, documentation ranges, ...)."""
    try:
        ip = ipaddress.ip_address(bare_ip(server_ip))
    except ValueError:
        return "unknown"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip.version == n.version and ip in n for n in PRIVATE_NETS):
        return "private"
    return "public" if ip.is_global else "unknown"


def parse_window(window: str) -> timedelta:
    """'7d' / '24h' / '90m' -> a timedelta, at most MAX_WINDOW (longer windows are capped, not refused)."""
    m = re.fullmatch(r"(\d+)\s*([mhd])", (window or DEFAULT_WINDOW).strip())
    if not m or int(m.group(1)) <= 0:
        raise ValueError(f"window must be like 7d, 24h or 90m, not {window!r}")
    n, unit = int(m.group(1)), m.group(2)
    d = {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]
    return min(d, MAX_WINDOW)


def window_text(d: timedelta) -> str:
    s = int(d.total_seconds())
    return f"{s // 86400}d" if s % 86400 == 0 else f"{s // 3600}h" if s % 3600 == 0 else f"{s // 60}m"


def paths_filter(projects: list[str], gateway: str, since_ts: str) -> str:
    return (f"{logs_mod.log_filter(projects, gateway, since_ts)} AND httpRequest.serverIp:* AND "
            "jsonPayload.agentGatewayInfo.agentRegistryResource:*")


def _host(entry: dict[str, Any]) -> str:
    jp = entry.get("jsonPayload") or {}
    return ((jp.get("enforcedGatewaySecurityPolicy") or {}).get("hostname") or jp.get("tlsSniHostname") or "")


def empty_count() -> dict[str, Any]:
    return {"private": 0, "public": 0, "unknown": 0, "last_seen": None, "last_private": None, "last_public": None}


def _add(c: dict[str, Any], kind: str, ts: str) -> None:
    c[kind] += 1
    if ts and (not c["last_seen"] or ts > c["last_seen"]):
        c["last_seen"] = ts
    k = f"last_{kind}"
    if k in c and ts and (not c[k] or ts > c[k]):
        c[k] = ts


def path_of(c: dict[str, Any]) -> Optional[str]:
    """private | public | mixed, or None when no call reached a private or public address."""
    if c["private"] and c["public"]:
        return "mixed"
    return "private" if c["private"] else "public" if c["public"] else None


def aggregate(entries: list[dict[str, Any]], gateway: str) -> dict[str, dict[str, Any]]:
    """{registry resource tail (locations/R/<kind>/<id>): counts} over raw log entries of one gateway. Entries without
    a serverIp or a registry resource, and denied ones, are skipped (the filter leaves them out already)."""
    out: dict[str, dict[str, Any]] = {}
    for e in entries:
        res = ((e.get("jsonPayload") or {}).get("agentGatewayInfo") or {}).get("agentRegistryResource") or ""
        sip = (e.get("httpRequest") or {}).get("serverIp") or ""
        if not res or not sip or logs_mod.classify(e) == "denied":
            continue
        c = out.setdefault(tail(res), {**empty_count(), "hosts": [], "gateway": gateway})
        _add(c, classify_ip(sip), e.get("timestamp") or "")
        h = _host(e)
        if h and h not in c["hosts"] and len(c["hosts"]) < MAX_HOSTS:
            c["hosts"].append(h)
    return out


def merge(per_gateway: list[dict[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    """Per-gateway aggregates -> {tail: counts over every gateway, with by_gateway and path}."""
    out: dict[str, dict[str, Any]] = {}
    for agg in per_gateway:
        for key, c in agg.items():
            m = out.setdefault(key, {**empty_count(), "hosts": [], "by_gateway": {}})
            for k in ("private", "public", "unknown"):
                m[k] += c[k]
            for k in ("last_seen", "last_private", "last_public"):
                if c[k] and (not m[k] or c[k] > m[k]):
                    m[k] = c[k]
            m["hosts"] += [h for h in c["hosts"] if h not in m["hosts"]][:MAX_HOSTS - len(m["hosts"])]
            m["by_gateway"][c["gateway"]] = {k: c[k] for k in ("private", "public", "unknown", "last_seen")}
    for m in out.values():
        m["path"] = path_of(m)
    return out


def fetch(r: Rest, projects: list[str], gateway: str, window: timedelta, cap: Optional[int] = None,
          now: Optional[datetime] = None) -> dict[str, Any]:
    """One gateway's entries with a serverIp and a registry resource over the window, aggregated.
    {since, filter, scanned, truncated, destinations: {tail: counts}, console_url}"""
    since_ts = ((now or datetime.now(timezone.utc)) - window).strftime("%Y-%m-%dT%H:%M:%SZ")
    flt = paths_filter(projects, gateway, since_ts)
    entries, truncated = logs_mod._list(r, projects, flt, cap or CAP, FIELDS)
    return {"since": since_ts, "filter": flt, "scanned": len(entries), "truncated": truncated,
            "destinations": aggregate(entries, gateway), "console_url": logs_mod.console_url(projects[0], flt)}
