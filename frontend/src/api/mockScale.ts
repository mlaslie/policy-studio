// The mock's scale region (docs/VISUALIZATION_PLAN.md §11.5–11.6): us-west1 gets about 50 Agent Runtime agents, 15 MCP
// servers, 100 API endpoints and 500 roles/iap.egressor bindings, generated from a seeded PRNG so every load (and
// every test) sees the same world. Names are plain counters (agent-017, mcp-08, svc-042), all under the context's
// project. Two egress gateways: corp-egress (dry run, on the extension it shares with corp-ingress) and west-egress
// (enforcing, its own extension). Two ingress gateways: corp-ingress with Model Armor on (screened lines) and
// partner-ingress with it off (unscreened). Used for the map's performance and layout checks (§7).
import type { Binding, Engine, Gateway, Inventory, McpTool, ModelArmorResp, Template } from "./types";
import { READ_ONLY_EXPR, ROLE, toolsExpr } from "../lib/policy";
import { NO_IDENTITY_REASON } from "../components/Redeploy";

export const SCALE_REGION = "us-west1";
/** Totals in the scale region, base mock world included (times the factor). */
export const SCALE = { engines: 50, mcp: 15, endpoints: 100, bindings: 500 } as const;

/** The page's ?scale=N (1–4, mock mode only): multiplies the totals, for the "too many lines" banner. 1 elsewhere
 *  (tests have no page). */
export function scaleFactor(search = typeof window === "undefined" ? "" : window.location.search): number {
  const n = Number(new URLSearchParams(search).get("scale"));
  return Number.isInteger(n) && n >= 1 && n <= 4 ? n : 1;
}

/** mulberry32: a small seeded PRNG (deterministic, good enough for mock data). */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pad = (n: number, w: number) => String(n).padStart(w, "0");
const TOOL_VERBS: [string, boolean, boolean][] = [
  ["list", true, false],
  ["get", true, false],
  ["search", true, false],
  ["export", true, false],
  ["create", false, false],
  ["update", false, false],
  ["delete", false, true],
  ["purge", false, true],
];

export interface ScaleParts {
  P: string;
  R: string;
  GP: string;
  reg: string;
  inventory: Pick<Inventory, "engines" | "mcp_servers" | "endpoints" | "access">;
  gateways: Gateway[];
  iapExts: { name: string; mode: "ENFORCE" | "DRY_RUN"; gateways: string[]; policies: Record<string, string> }[];
  modelArmor: ModelArmorResp;
  template: Template;
  principalOf: (region: string, engineId: string) => string;
  engineName: (id: string) => string;
  projectSet: string;
}

/** Adds the scale scenario to the base world of the region, in place (the base agents and grants stay). */
export function addScale(w: ScaleParts, factor = 1) {
  const rnd = prng(17);
  const total = { engines: SCALE.engines * factor, mcp: SCALE.mcp * factor, endpoints: SCALE.endpoints * factor, bindings: SCALE.bindings * factor };
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)];
  const { P, R, GP, inventory: inv } = w;
  const [corpEgress, corpIngress] = [w.gateways.find((g) => g.type === "egress")!, w.gateways.find((g) => g.type === "ingress")!];
  const base = `projects/${GP}/locations/${R}`;

  // ---------- gateways: a second egress (enforcing) and a second ingress (no Model Armor) ----------
  const westEgress: Gateway = {
    name: `${base}/agentGateways/west-egress`,
    id: "west-egress",
    type: "egress",
    governed_access_path: "AGENT_TO_ANYWHERE",
    registries: [`//agentregistry.googleapis.com/${w.reg}`],
    authz_policies: [],
    bound_engines: [],
    create_time: "2026-08-02T16:20:00Z",
  };
  const partnerIngress: Gateway = {
    name: `projects/${P}/locations/${R}/agentGateways/partner-ingress`,
    id: "partner-ingress",
    type: "ingress",
    governed_access_path: "CLIENT_TO_AGENT",
    registries: [`//agentregistry.googleapis.com/projects/${P}/locations/${R}`],
    authz_policies: [],
    bound_engines: [],
    create_time: "2026-08-02T16:31:00Z",
  };
  w.gateways.push(westEgress, partnerIngress);
  w.iapExts.push({ name: `${base}/authzExtensions/west-egress-iap-authz`, mode: "ENFORCE", gateways: [westEgress.name], policies: { [westEgress.name]: `${base}/authzPolicies/west-egress-iap-policy` } });

  // corp-ingress screens with Model Armor here (the screened Client-to-Agent lines); partner-ingress doesn't
  const maExt = `${base}/authzExtensions/corp-ma-authz`;
  const maPolicy = `projects/${P}/locations/${R}/authzPolicies/corp-ingress-ma-policy`;
  corpIngress.authz_policies.push({ name: maPolicy, profile: "CONTENT_AUTHZ", provider: "model_armor", extension: maExt, enforcement: "ENFORCE" });
  const ing = w.modelArmor.gateways.find((g) => g.gateway === corpIngress.name)!;
  Object.assign(ing, { enabled: true, policy: maPolicy, extension: maExt, template: w.template });
  w.modelArmor.gateways.push(
    { gateway: westEgress.name, type: "egress", enabled: false, policy: null, extension: null, template: null },
    { gateway: partnerIngress.name, type: "ingress", enabled: false, policy: null, extension: null, template: null },
  );

  // ---------- engines: agent-001 … ----------
  const engines: Engine[] = [];
  for (let k = 1; inv.engines.length + engines.length < total.engines; k++) {
    const id = `7${pad(k, 4)}${pad(Math.floor(rnd() * 1e11), 11)}`;
    const sa = k % 23 === 0; // a few deployed with a service account: they can't be bound
    const r = rnd();
    const egress = sa ? undefined : r < 0.42 ? corpEgress : r < 0.85 ? westEgress : undefined;
    const r2 = rnd();
    const ingress = sa ? undefined : r2 < 0.3 ? corpIngress : r2 < 0.5 ? partnerIngress : undefined;
    const e: Engine = {
      name: w.engineName(id),
      id,
      display_name: `agent-${pad(k, 3)}`,
      principal: sa ? `serviceAccount:agent-${pad(k, 3)}@${P}.iam.gserviceaccount.com` : w.principalOf(R, id),
      identity_type: sa ? "SERVICE_ACCOUNT" : "AGENT_IDENTITY",
      gateways: { ...(egress ? { egress: egress.name } : {}), ...(ingress ? { ingress: ingress.name } : {}) },
      create_time: `2026-0${7 + (k % 3)}-${pad(1 + (k % 28), 2)}T09:00:00Z`,
      bindable: !sa,
      ...(sa ? { bindable_reason: NO_IDENTITY_REASON } : {}),
    };
    for (const g of [egress, ingress]) if (g) g.bound_engines.push({ engine: e.name, display_name: e.display_name, direction: g.type });
    engines.push(e);
  }
  inv.engines.push(...engines);

  // ---------- destinations ----------
  const reg = (kind: string, id: string) => `${w.reg}/${kind}/${id}`;
  for (let k = 1; inv.mcp_servers.length < total.mcp; k++) {
    const id = `mcp-${pad(k, 2)}`;
    const n = 3 + Math.floor(rnd() * 5);
    const verbs = [...TOOL_VERBS];
    for (let i = verbs.length - 1; i > 0; i--) {
      const j = Math.floor(rnd() * (i + 1));
      [verbs[i], verbs[j]] = [verbs[j], verbs[i]];
    }
    verbs.length = n;
    const tools: McpTool[] = verbs.map(([v, ro, destructive]) => ({
      name: `${v}_records`,
      description: `${v[0].toUpperCase()}${v.slice(1)} records.`,
      read_only: ro,
      destructive,
      annotations: { readOnlyHint: ro, destructiveHint: destructive, idempotentHint: ro, openWorldHint: false },
    }));
    inv.mcp_servers.push({ name: reg("mcpServers", id), id, display_name: `MCP server ${pad(k, 2)}`, url: `https://${id}.example.com/mcp`, tools });
  }
  for (let k = 1; inv.endpoints.length < total.endpoints; k++) {
    const id = `svc-${pad(k, 3)}`;
    inv.endpoints.push({ name: reg("endpoints", id), id, display_name: `Service ${pad(k, 3)} API`, url: `https://${id}.example.com` });
  }
  const scaleMcp = inv.mcp_servers.filter((m) => m.id.startsWith("mcp-"));
  const scaleEps = inv.endpoints.filter((x) => x.id.startsWith("svc-"));

  // ---------- bindings, up to the total ----------
  // Dense on purpose: each lane (corp-egress, west-egress, no gateway) reaches most generated destinations, so the
  // combined view has about as many lines as these totals allow (?scale=2 doubles them, past the map's 400-line banner).
  const count = () => Object.values(inv.access).reduce((n, bs) => n + bs.length, 0);
  const add = (res: string, b: Binding) => {
    const cur = (inv.access[res] ??= []);
    if (cur.some((x) => x.member === b.member && (x.condition?.expression ?? "") === (b.condition?.expression ?? ""))) return;
    cur.push(b);
  };
  const grant = (e: Engine, d: { name: string; display_name: string }, mcp?: (typeof scaleMcp)[number]) => {
    const who = `${e.display_name} (${e.identity_type === "AGENT_IDENTITY" ? "Agent Identity" : "service account"})`;
    if (!mcp) return add(d.name, { role: ROLE, member: e.principal, member_label: who, condition: null, english: `${e.display_name} can call ${d.display_name}.` });
    const c = rnd();
    const ro = mcp.tools.filter((t) => t.read_only).map((t) => t.name);
    const condition = c < 0.45 ? null : c < 0.8 || !ro.length ? { title: "MCP read-only tools (by hint)", expression: READ_ONLY_EXPR } : { title: `MCP tools: ${ro.slice(0, 2).join(", ")}`, expression: toolsExpr(ro.slice(0, 2)) };
    add(d.name, { role: ROLE, member: e.principal, member_label: who, condition, english: `${e.display_name} can call ${condition ? "some tools" : "every tool"} of ${d.display_name}.` });
  };
  const lanes = [corpEgress.name, westEgress.name, null].map((g) => inv.engines.filter((e) => (e.gateways.egress ?? null) === g));
  for (const d of [...scaleMcp, ...scaleEps]) {
    const mcp = scaleMcp.find((m) => m.name === d.name);
    for (const lane of lanes) if (lane.length && rnd() < 0.9) grant(pick(lane), d, mcp);
  }
  // project-wide grants on a handful of endpoints, and service accounts on about half of them (pseudo callers)
  for (const x of scaleEps.filter((_, i) => i % 9 === 0))
    add(x.name, { role: ROLE, member: w.projectSet, member_label: "All agents in project (Agent Identity)", condition: null, english: `All agents in this project can call ${x.display_name}.` });
  for (const x of scaleEps.filter(() => rnd() < 0.55)) {
    const k = 1 + Math.floor(rnd() * 6);
    add(x.name, { role: ROLE, member: `serviceAccount:batch-${k}@${P}.iam.gserviceaccount.com`, member_label: `batch-${k} (service account)`, condition: null, english: `batch-${k} can call ${x.display_name}.` });
  }
  // the rest: random agents on random destinations
  while (count() < total.bindings) {
    const r = rnd();
    const mcp = r < 0.3 ? pick(scaleMcp) : undefined;
    grant(pick(inv.engines), mcp ?? pick(scaleEps), mcp);
  }
  for (const x of [...scaleMcp, ...scaleEps]) inv.access[x.name] ??= [];
}
