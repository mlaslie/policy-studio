"""Destination paths seen in traffic (gcp/paths.py, GET /destination-paths): the IP classifier, the aggregation of
gateway request log entries (private, public, denied / no serverIp, mixed, truncated) and the permission degrade."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import fakegcp as F
from policy_studio import service
from policy_studio.app import create_app
from policy_studio.gcp import paths

Q = {"project": F.P, "region": F.R}
NUM_LOC = f"projects/{F.N}/locations/{F.R}"     # log entries name registry resources by project number
CASES = json.loads((Path(__file__).parent / "fixtures" / "path_cases.json").read_text())   # shared with the mock


@pytest.fixture
def client(monkeypatch):
    def make(**kw):
        rest = F.FakeRest(**kw)
        monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
        return TestClient(create_app()), rest
    return make


def entry(server_ip="10.70.0.10:443", resource="mcpServers/agentregistry-mcp", ts="2026-10-09T14:00:00Z",
          status=200, result="ALLOWED", host="tickets.example.com", iid=None):
    """A gateway_requests entry in the shape seen live (placeholders); denied ones carry no serverIp."""
    http = {"requestMethod": "POST", "status": status, "requestUrl": f"https://{host}/mcp"}
    if server_ip:
        http["serverIp"] = server_ip
    gi = {"agentRegistryResource": f"{NUM_LOC}/{resource}"} if resource else {}
    return {"insertId": iid or f"{server_ip}-{resource}-{ts}-{status}", "timestamp": ts, "httpRequest": http,
            "jsonPayload": {"enforcedGatewaySecurityPolicy": {"hostname": host}, "agentGatewayInfo": gi,
                            "authzPolicyInfo": {"result": result, "policies": []}}}


# ====================================================================== classifier
@pytest.mark.parametrize("ip,want", CASES["ips"] + [(None, "unknown")])
def test_classify_ip(ip, want):
    assert paths.classify_ip(ip) == want


def test_window():
    assert paths.parse_window("7d") == timedelta(days=7) and paths.parse_window("90m") == timedelta(minutes=90)
    assert paths.parse_window("400d") == paths.MAX_WINDOW                       # capped, not refused
    assert paths.window_text(paths.parse_window("400d")) == "30d" and paths.window_text(timedelta(hours=36)) == "36h"
    for bad in ("soon", "0d", "7w", "2026-10-01T00:00:00Z"):
        with pytest.raises(ValueError):
            paths.parse_window(bad)
    f = paths.paths_filter([F.P], "corp-out", "2026-10-02T00:00:00Z")
    assert f.endswith(' AND httpRequest.serverIp:* AND jsonPayload.agentGatewayInfo.agentRegistryResource:*')
    assert 'resource.labels.gateway_name="corp-out"' in f


# ====================================================================== aggregation
def test_aggregate_private_public_denied_mixed():
    es = [entry("10.70.0.10:443", ts="2026-10-09T14:00:00Z"), entry("10.70.0.10:443", ts="2026-10-08T09:00:00Z"),
          entry("74.125.20.95:443", "endpoints/agentregistry-ep", ts="2026-10-09T12:00:00Z", host="api.weather.example"),
          entry(None, "agents/agentregistry-aaa", status=403, result="DENIED"),                     # denied: no serverIp
          entry("10.1.1.1:443", "agents/agentregistry-aaa", status=403, result="DENIED"),           # denied anyway
          entry("240.0.0.2:443", None),                                                             # no registry entry
          entry("10.70.0.10:443", "agents/agentregistry-rt1", ts="2026-10-07T10:00:00Z", host="a.run.app"),
          entry("34.1.2.3:443", "agents/agentregistry-rt1", ts="2026-10-09T10:00:00Z", host="b.run.app"),
          entry("240.0.0.9:443", "mcpServers/agentregistry-ro")]                                    # only unknown
    agg = paths.aggregate(es, F.EG)
    mcp = agg[f"locations/{F.R}/mcpServers/agentregistry-mcp"]
    assert (mcp["private"], mcp["public"], mcp["last_seen"]) == (2, 0, "2026-10-09T14:00:00Z")
    assert mcp["last_private"] == "2026-10-09T14:00:00Z" and mcp["last_public"] is None
    assert f"locations/{F.R}/agents/agentregistry-aaa" not in agg
    merged = paths.merge([agg])
    assert merged[f"locations/{F.R}/mcpServers/agentregistry-mcp"]["path"] == "private"
    assert merged[f"locations/{F.R}/endpoints/agentregistry-ep"]["path"] == "public"
    rt = merged[f"locations/{F.R}/agents/agentregistry-rt1"]
    assert rt["path"] == "mixed" and rt["hosts"] == ["a.run.app", "b.run.app"]
    assert (rt["last_private"], rt["last_public"]) == ("2026-10-07T10:00:00Z", "2026-10-09T10:00:00Z")
    ro = merged[f"locations/{F.R}/mcpServers/agentregistry-ro"]
    assert ro["path"] is None and ro["unknown"] == 1
    assert rt["by_gateway"] == {F.EG: {"private": 1, "public": 1, "unknown": 0, "last_seen": "2026-10-09T10:00:00Z"}}


def test_shared_cases():
    """The fixture the frontend mock's port (api/mockPaths.ts) is tested against too."""
    got = paths.merge([paths.aggregate(CASES["entries"], "gw")])
    assert {k: {f: v[f] for f in ("private", "public", "unknown", "last_seen", "path", "hosts")}
            for k, v in got.items()} == CASES["expected"]


def test_merge_across_gateways():
    a = paths.aggregate([entry("10.0.0.5:443", ts="2026-10-01T00:00:00Z")], "gw-a")
    b = paths.aggregate([entry("74.125.0.1:443", ts="2026-10-02T00:00:00Z")], "gw-b")
    m = paths.merge([a, b])[f"locations/{F.R}/mcpServers/agentregistry-mcp"]
    assert m["path"] == "mixed" and m["last_seen"] == "2026-10-02T00:00:00Z" and set(m["by_gateway"]) == {"gw-a", "gw-b"}


# ====================================================================== endpoint
def test_endpoint(client):
    c, rest = client()
    rest.log_entries = [entry("10.70.0.10:443"), entry("74.125.20.95:443", "endpoints/agentregistry-ep"),
                        entry(None, "agents/agentregistry-aaa", status=403, result="DENIED")]
    r = c.get("/api/studio/destination-paths", params={**Q, "window": "7d"}).json()
    assert r["window"] == "7d" and r["truncated"] is False and not r["errors"]
    assert set(r["destinations"]) == {F.MCP, F.EP}                         # keyed by the inventory's entry names
    assert r["destinations"][F.MCP]["path"] == "private" and r["destinations"][F.EP]["path"] == "public"
    gw, = r["gateways"]                                                    # the egress gateway only
    assert gw["gateway"] == F.EG and gw["private_egress"] is True and gw["scanned"] == 3
    req, = rest.log_requests
    url, = [u for m, u in rest.calls if u.split("?")[0].endswith("/v2/entries:list")]
    assert "?fields=entries(timestamp,httpRequest(serverIp,status),jsonPayload),nextPageToken" in url  # partial response
    assert "httpRequest.serverIp:*" in req["filter"] and 'gateway_name="corp-out"' in req["filter"]
    since = datetime.fromisoformat(req["filter"].split('timestamp>="')[1][:20].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - since) - timedelta(days=7)) < timedelta(minutes=5)
    assert c.get("/api/studio/destination-paths", params={**Q, "window": "later"}).status_code == 400
    # cached like the other reads: a second call doesn't read the logs again; refresh=1 does
    c.get("/api/studio/destination-paths", params=Q)
    assert len(rest.log_requests) == 1
    c.get("/api/studio/destination-paths", params={**Q, "refresh": 1})
    assert len(rest.log_requests) == 2


def test_truncated(client, monkeypatch):
    monkeypatch.setattr(paths, "CAP", 4)
    c, rest = client()
    rest.log_entries = [entry("10.0.0.1:443", iid=f"e{i}") for i in range(9)]
    r = c.get("/api/studio/destination-paths", params=Q).json()
    assert r["truncated"] is True and r["gateways"][0]["truncated"] is True and r["gateways"][0]["scanned"] == 4
    assert r["destinations"][F.MCP]["private"] == 4
    assert any("Only the newest 4 calls" in n for n in r["notes"])


def test_permission_degrade(client):
    """No logging.logEntries.list: the gateway gets an error and no destination is labelled; the request succeeds."""
    c, rest = client(fail={"entries:list": 403})
    rest.log_entries = [entry()]
    res = c.get("/api/studio/destination-paths", params=Q)
    assert res.status_code == 200
    r = res.json()
    assert r["destinations"] == {} and r["gateways"][0]["error"].startswith("can't read the request logs: ")
    assert "403" in r["gateways"][0]["error"] and any("corp-out" in e for e in r["errors"])
    assert any("roles/logging.viewer" in n for n in r["notes"])
