// The mock's GET /destination-paths (VITE_MOCK=1; only mock.ts imports it, so it never ships in the main bundle): a
// week of fake gateway_requests entries, aggregated the way backend gcp/paths.py does (classify_ip, aggregate, merge).
// Both sides are tested against backend/tests/fixtures/path_cases.json.
//
// Traffic sample (corp-egress reaches corp-vpc through its connectivity template, run.app. peered): Tickets MCP is
// reached privately (the PSC endpoint, 10.x), HR Directory MCP publicly, and Knowledge Base Agent both ways (its
// run.app name went through the VPC only after the DNS peering was added, three days ago: Mixed paths). Google APIs
// and the Weather API are public, as under PRIVATE_RANGES_ONLY. A gateway without private egress sees public only.
import type { DestinationPath, DestinationPathsResp } from "./types";
import type { World } from "./mockData";
import { MOCK_NUMBER } from "./mockData";

type Raw = { timestamp: string; httpRequest: { status?: number; serverIp?: string }; jsonPayload: { enforcedGatewaySecurityPolicy?: { hostname?: string }; agentGatewayInfo?: { agentRegistryResource?: string }; authzPolicyInfo?: { result?: string } } };

// ------------------------------------------------------------------ port of gcp/paths.py
const v4 = (s: string): number | null => {
  const p = s.split(".");
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((a, x) => a * 256 + Number(x), 0);
};
const in4 = (ip: number, net: string, bits: number) => Math.floor(ip / 2 ** (32 - bits)) === Math.floor(v4(net)! / 2 ** (32 - bits));
const PRIVATE4: [string, number][] = [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16], ["100.64.0.0", 10]];
// not globally routable (Python's ipaddress is_global is false): this host, loopback, link-local, documentation,
// benchmarking, IETF protocol assignments, multicast and reserved (the platform's 240.0.0.0/4)
const LOCAL4: [string, number][] = [["0.0.0.0", 8], ["127.0.0.0", 8], ["169.254.0.0", 16], ["192.0.0.0", 24], ["192.0.2.0", 24], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]];

/** "fd00::1" → its 8 groups, or null. A dotted IPv4 tail (::ffff:10.1.2.3) becomes two groups. */
function v6(s: string): number[] | null {
  let t = s.toLowerCase();
  const dot = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(t);
  if (dot) {
    const n = v4(dot[2]);
    if (n === null) return null;
    t = `${dot[1]}${Math.floor(n / 65536).toString(16)}:${(n % 65536).toString(16)}`;
  }
  const halves = t.split("::");
  if (halves.length > 2) return null;
  const part = (h: string) => (h ? h.split(":") : []);
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const all = [...head, ...Array(Math.max(0, fill)).fill("0"), ...tail];
  if (all.length !== 8 || all.some((g) => !/^[0-9a-f]{1,4}$/.test(g)) || fill < 0) return null;
  return all.map((g) => parseInt(g, 16));
}

/** '10.1.2.3:443' / '[fd00::1]:443' / 'fd00::1' → the address alone. */
export function bareIp(s: string): string {
  const x = (s ?? "").trim();
  if (x.startsWith("[")) return x.includes("]") ? x.slice(1, x.indexOf("]")) : x.slice(1);
  return (x.match(/:/g) ?? []).length === 1 ? x.slice(0, x.lastIndexOf(":")) : x;
}

/** private | public | unknown, as gcp/paths.classify_ip. */
export function classifyIp(serverIp: string | null | undefined): "private" | "public" | "unknown" {
  const s = bareIp(serverIp ?? "");
  const four = v4(s);
  const cls4 = (n: number) => (PRIVATE4.some(([a, b]) => in4(n, a, b)) ? "private" : LOCAL4.some(([a, b]) => in4(n, a, b)) || n === 2 ** 32 - 1 ? "unknown" : "public");
  if (four !== null) return cls4(four);
  const g = v6(s);
  if (!g) return "unknown";
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return cls4(g[6] * 65536 + g[7]); // IPv4-mapped
  if ((g[0] & 0xfe00) === 0xfc00) return "private"; // fc00::/7
  if (g[0] === 0x2001 && g[1] === 0x0db8) return "unknown"; // documentation
  return (g[0] & 0xe000) === 0x2000 ? "public" : "unknown"; // 2000::/3 global unicast; loopback, link-local, multicast…
}

const tailOf = (res: string) => {
  const i = res.indexOf("/locations/");
  return i >= 0 ? res.slice(i + 1) : res;
};

/** gcp/paths.aggregate + merge over one gateway's raw entries: {resource tail: counts with path}. */
export function aggregate(entries: Raw[], gateway: string): Record<string, DestinationPath> {
  const out: Record<string, DestinationPath> = {};
  for (const e of entries) {
    const res = e.jsonPayload?.agentGatewayInfo?.agentRegistryResource ?? "";
    const sip = e.httpRequest?.serverIp ?? "";
    const denied = e.jsonPayload?.authzPolicyInfo?.result === "DENIED" || e.httpRequest?.status === 403;
    if (!res || !sip || denied) continue;
    const c = (out[tailOf(res)] ??= { private: 0, public: 0, unknown: 0, last_seen: null, last_private: null, last_public: null, hosts: [], by_gateway: {}, path: null });
    const kind = classifyIp(sip);
    const ts = e.timestamp;
    c[kind]++;
    if (!c.last_seen || ts > c.last_seen) c.last_seen = ts;
    if (kind === "private" && (!c.last_private || ts > c.last_private)) c.last_private = ts;
    if (kind === "public" && (!c.last_public || ts > c.last_public)) c.last_public = ts;
    const h = e.jsonPayload?.enforcedGatewaySecurityPolicy?.hostname;
    if (h && !c.hosts.includes(h) && c.hosts.length < 5) c.hosts.push(h);
  }
  for (const c of Object.values(out)) {
    c.by_gateway = { [gateway]: { private: c.private, public: c.public, unknown: c.unknown, last_seen: c.last_seen } };
    c.path = c.private && c.public ? "mixed" : c.private ? "private" : c.public ? "public" : null;
  }
  return out;
}

// ------------------------------------------------------------------ the sample
const DAY = 86_400_000;

/** Fake entries for one egress gateway over the last week, newest first. */
function sample(w: World, priv: boolean, now: number): Raw[] {
  const byId = (coll: { name: string; id: string }[], id: string) => coll.find((x) => x.id === id)?.name;
  const inv = w.inventory;
  const res = (name: string | undefined) => name?.replace(/^projects\/[^/]+\//, `projects/${MOCK_NUMBER}/`);
  const out: Raw[] = [];
  const add = (name: string | undefined, host: string, ip: (k: number) => string, n: number, every: number, from = 0) => {
    if (!name) return;
    for (let k = 0; k < n; k++)
      out.push({
        timestamp: new Date(now - from - k * every - 37_000).toISOString(),
        httpRequest: { status: 200, serverIp: ip(k) },
        jsonPayload: { enforcedGatewaySecurityPolicy: { hostname: host }, agentGatewayInfo: { agentRegistryResource: res(name) }, authzPolicyInfo: { result: "ALLOWED" } },
      });
  };
  const psc = () => "10.40.0.10:443"; // the PSC endpoint for Google APIs in corp-vpc (run.app override)
  const google = (k: number) => `142.250.${64 + (k % 8)}.95:443`;
  add(byId(inv.mcp_servers, "tickets-mcp-6a21"), "tickets-mcp-a1b2c3-uk.a.run.app", priv ? psc : google, 42, DAY / 7, 4 * 60_000);
  add(byId(inv.mcp_servers, "hr-directory-mcp-0f3c"), "hr-directory-mcp-a1b2c3-uk.a.run.app", google, 9, (6 * DAY) / 9, 95 * 60_000);
  const kb = byId(inv.agents, "kb-agent-4c1e");
  if (priv) {
    add(kb, "kb-agent-a1b2c3-uk.a.run.app", psc, 6, DAY / 3, 4 * 3_600_000); // since the DNS peering was added
    add(kb, "kb-agent-a1b2c3-uk.a.run.app", google, 5, DAY / 2, 3 * DAY); // before
  } else add(kb, "kb-agent-a1b2c3-uk.a.run.app", google, 11, DAY / 2, 4 * 3_600_000);
  for (const h of ["aiplatform", "logging", "telemetry"]) add(byId(inv.endpoints, `${h}-googleapis`), `${h}.googleapis.com`, google, 30, DAY / 5, 2 * 60_000);
  add(byId(inv.endpoints, "weather-api"), "api.weather.example.com", () => "93.184.216.34:443", 3, 2 * DAY, 9 * 3_600_000);
  // denied calls (no serverIp) and the platform's own unregistered address: never counted
  out.push({ timestamp: new Date(now - 3_600_000).toISOString(), httpRequest: { status: 403 }, jsonPayload: { agentGatewayInfo: { agentRegistryResource: res(byId(inv.agents, "billing-agent-91d0")) }, authzPolicyInfo: { result: "DENIED" } } });
  out.push({ timestamp: new Date(now - 60_000).toISOString(), httpRequest: { status: 200, serverIp: "240.0.0.2:443" }, jsonPayload: {} });
  return out.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
}

/** Mirrors GET /destination-paths. */
export function destinationPaths(w: World, window = "7d", now = Date.now()): DestinationPathsResp {
  const m = /^(\d+)([mhd])$/.exec(window) ?? ["", "7", "d"];
  const asked = Number(m[1]) * { m: 60_000, h: 3_600_000, d: DAY }[m[2] as "m" | "h" | "d"];
  const ms = Math.min(asked, 30 * DAY); // capped like the backend
  const since = now - ms;
  const tails = new Map([...w.inventory.agents, ...w.inventory.mcp_servers, ...w.inventory.endpoints].map((x) => [tailOf(x.name), x.name]));
  const destinations: Record<string, DestinationPath> = {};
  const gateways: DestinationPathsResp["gateways"] = [];
  for (const g of w.gateways.filter((x) => x.type === "egress")) {
    const entries = sample(w, !!g.private_egress, now).filter((e) => Date.parse(e.timestamp) >= since);
    const counted = entries.filter((e) => e.httpRequest.serverIp && e.jsonPayload.agentGatewayInfo?.agentRegistryResource);
    gateways.push({ gateway: g.name, id: g.id, private_egress: !!g.private_egress, scanned: counted.length, truncated: false });
    for (const [t, c] of Object.entries(aggregate(entries, g.name))) {
      const key = tails.get(t) ?? t;
      const d = destinations[key];
      if (!d) destinations[key] = c;
      else {
        d.private += c.private;
        d.public += c.public;
        d.unknown += c.unknown;
        d.last_seen = [d.last_seen, c.last_seen].filter(Boolean).sort().pop() ?? null;
        d.last_private = [d.last_private, c.last_private].filter(Boolean).sort().pop() ?? null;
        d.last_public = [d.last_public, c.last_public].filter(Boolean).sort().pop() ?? null;
        d.hosts = [...new Set([...d.hosts, ...c.hosts])].slice(0, 5);
        Object.assign(d.by_gateway, c.by_gateway);
        d.path = d.private && d.public ? "mixed" : d.private ? "private" : d.public ? "public" : null;
      }
    }
  }
  const notes = [
    "From the gateway request logs: httpRequest.serverIp is the address the gateway connected to. Private (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) means the call went through the gateway's private egress. Only calls that were made count: denied ones have no serverIp.",
  ];
  if (Object.values(destinations).some((d) => d.path === "mixed"))
    notes.push("Mixed paths: a destination reached at both private and public addresses. It usually has several hostnames (only some resolve into the VPC) or its DNS changed inside the window.");
  return { window: asked > ms ? "30d" : `${m[1]}${m[2]}`, since: new Date(since).toISOString(), gateways, destinations, truncated: false, notes, errors: [], synced_at: new Date(now).toISOString() };
}
