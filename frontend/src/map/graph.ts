// The policy map's graph: who can reach what, and why, from the state Policy Studio already reads (inventory,
// gateways, Model Armor, context). Pure, no React (docs/VISUALIZATION_PLAN.md §4.3–4.5, §6).
//
// Egress lines follow §4.4: the caller's egress gateway and its mode, the roles/iap.egressor bindings on the
// destination and on the registry (registry-wide), matched with evaluate.ts (the port of dryrun.py). Outside the
// selected-agent view an agent's own grants are combined per (gateway, destination); group, public and registry-wide
// grants are drawn once from their pseudo caller and only added to an agent's lines when it is selected.
import type { Access, Binding, ContextInfo, Ctx, EnforcementMode, Engine, Gateway, Inventory, ModelArmorResp } from "../api/types";
import { ROLE, accessFromCondition } from "../lib/policy";
import { ENGINE_PRINCIPAL_RE, EVERYONE, PROJECT_AGENTS_RE, conditionAllows, evaluateTools, isReadOnlyHint, memberMatches, parseTools } from "./evaluate";
import { CLIENT, NOGW, PSEUDO, pseudoOf } from "./ids";

export { CLIENT, NOGW, PSEUDO };

export type Direction = "egress" | "ingress";
export type PNodeKind =
  | "engine" // an Agent Runtime agent: a caller (egress) or the called agent (ingress); id = engine name
  | "principal_group" // pseudo callers: project agents principalSet, public, other principals
  | "gateway" // id = gateway full name
  | "no_gateway" // the "no gateway" lane (direct traffic)
  | "anywhere" // sink for direct egress
  | "client" // ingress pseudo callers
  | "a2a"
  | "runtime_dest"
  | "mcp"
  | "endpoint"
  | "endpoint_group" // destinations with no grants, grouped (one per section)
  | "registry";
export type Verdict =
  | "allowed" // an unconditional matching grant
  | "partial" // MCP tools grant: some tools allowed (tool breakdown attached)
  | "conditional" // condition can't be evaluated client-side (custom CEL, group member)
  | "blocked" // default deny under ENFORCE (implicit)
  | "would_deny" // default deny under DRY_RUN: passes today, logged as allowed
  | "unchecked" // gateway in the path with no IAP policy (mode null): nothing is checked
  | "dormant" // grant exists but the caller isn't behind an egress gateway: never checked
  | "direct" // no gateway: traffic goes straight out (or straight in)
  | "screened" // ingress through a gateway with Model Armor on
  | "unscreened" // ingress through a gateway with Model Armor off
  | "path"; // an agent's trunk to its gateway (no verdict of its own)
export type Via = "member" | "project_agents" | "public" | "registry_wide" | "other";
export type ResourceKind = "agent" | "mcp_server" | "endpoint" | "registry";
export type Column = "callers" | "gateways" | "dests" | "sink";
export type Tone = "neutral" | "blue" | "red" | "green" | "amber" | "orange";
/** pending: a staged change (drawn with a clock). */
export type Chip = { text: string; tone: Tone; title?: string; pending?: boolean };
export type Pending = "add" | "remove" | "change";
export type ToolSplit = { allowed: string[]; denied: string[]; unknown: string[] };

/** One binding that contributes to a line. */
export interface Reason {
  binding: Binding;
  resource: string;
  resourceKind: ResourceKind;
  resourceLabel: string;
  via: Via;
  access: Access;
}

export interface PNode {
  id: string;
  kind: PNodeKind;
  label: string;
  sub?: string;
  column: Column;
  /** Group within the column: `gw:<gateway>` / "nogw" / "pseudo" for callers; registry / a2a / runtime / mcp / api
   *  for destinations. */
  section: string;
  chips: Chip[];
  /** Engine: its gateway in this direction (null = none). Gateway / no_gateway: itself. */
  gateway?: string | null;
  bindable?: boolean;
  bindableReason?: string | null;
  identityType?: string;
  /** Destination: the registry entry kind; tools / skills for display. */
  destKind?: ResourceKind;
  tools?: { name: string; readOnly: boolean; destructive: boolean }[];
  skills?: string[];
  /** access_errors[D]: the IAP policy couldn't be read (no lines are guessed). */
  unreadable?: string;
  /** Gateway: IAP enforcement mode and Model Armor. */
  mode?: EnforcementMode | null;
  shared?: string[];
  modelArmor?: { enabled: boolean; template?: string; summary?: string[]; dryRun?: boolean } | null;
  /** The same Agent Runtime agent as an engine (caller) and a registry entry (destination). */
  sameAs?: string;
  /** Engine (egress): destinations reachable only through group, public or registry-wide grants, and the number it
   *  can't reach (default deny), both for the node's summary chips. */
  inheritedCount?: number;
  deniedCount?: number;
  /** Pseudo callers: the members drawn from this node. */
  members?: { member: string; label: string; deleted?: boolean }[];
  /** endpoint_group: the grouped destinations. */
  grouped?: string[];
  /** Lowercase label + id + sub, for search. */
  search: string;
  /** Staged-change view (diff.ts): what the cart changes on this node, and the cart intents that do it. */
  pending?: { text: string[]; removed?: boolean; intents: string[] };
}

export interface PEdge {
  id: string;
  source: string;
  target: string;
  direction: Direction;
  verdict: Verdict;
  reasons: Reason[];
  tools?: ToolSplit; // MCP only
  gateway?: string;
  mode?: EnforcementMode | null;
  modelArmor?: boolean;
  /** Model Armor's CONTENT_AUTHZ policy is in dry run: screening, not blocking. */
  modelArmorDryRun?: boolean;
  implicit?: boolean; // drawn for default deny, no binding
  inherited?: boolean; // via a principalSet, public, group or registry-wide grant (selected agent only)
  /** The caller (engine or pseudo id) of a single-caller line. */
  caller?: string;
  /** A combined line: the per-agent lines it stands for (count badge = parts.length). */
  parts?: PEdge[];
  /** Short text on the line ("read-only", "3/6 tools", "?"). */
  label?: string;
  /** Non-MCP destination with a tool condition: calls carry toolName '', which the condition allows. */
  note?: string;
  /** Staged-change view (diff.ts, §8): the line is added, removed or changed by the cart. `before` / `after` are the
   *  verdicts today and after Apply (the line itself is drawn as it will be, or as it is today when removed). */
  pending?: Pending;
  before?: Verdict;
  beforeLabel?: string;
  after?: Verdict;
  intents?: string[];
}

export interface PolicyGraph {
  direction: Direction;
  nodes: PNode[];
  /** The lines with no agent selected: trunks, combined gateway → destination lines, pseudo-caller lines. */
  edges: PEdge[];
  /** The focused caller's own lines (inherited and implicit included), when `focus` names an engine. */
  focusLines: PEdge[] | null;
  stats: { engines: number; destinations: number; bindings: number; gateways: number; unbound: number; unreadable: number };
  notes: string[];
}

export interface GraphInput {
  inventory: Inventory;
  gateways: Gateway[];
  modelArmor?: ModelArmorResp | null;
  context?: ContextInfo | null;
  /** The saved context: ge_app names the Gemini Enterprise client (ingress). */
  ctx?: Partial<Ctx> | null;
  direction: Direction;
  /** Engine id whose own lines to compute (the selected-agent view). */
  focus?: string | null;
  /** Add group / public / registry-wide grants to the focused agent's lines (default true). */
  inherited?: boolean;
}

/** Registry-wide IAM key: projects/<GP>/locations/<R>. */
export const REGISTRY_KEY_RE = /^projects\/[^/]+\/locations\/[^/]+$/;

/** Order of the destination sections, top to bottom. */
export const DEST_SECTIONS = ["registry", "a2a", "runtime", "mcp", "api"] as const;
export const SECTION_LABEL: Record<string, string> = {
  registry: "Agent Registry (all entries)",
  a2a: "A2A agents",
  runtime: "Agent Runtime agents",
  mcp: "MCP servers",
  api: "API endpoints",
  pseudo: "Other callers",
  nogw: "No gateway",
  clients: "Clients",
};

/** Best first: a combined line takes the best of its contributors. */
const RANK: Verdict[] = ["allowed", "partial", "conditional", "unchecked", "would_deny", "blocked", "dormant", "screened", "unscreened", "direct", "path"];
export const bestVerdict = (vs: Verdict[]): Verdict => vs.reduce((a, b) => (RANK.indexOf(b) < RANK.indexOf(a) ? b : a));

const short = (name: string) => name.split("/").pop() ?? name;

type Dest = { id: string; kind: ResourceKind; label: string; node: PNode; tools: Record<string, boolean> | null };

/** The verdict of a set of matching bindings on one destination (null = none of them allows anything). */
function evaluateBindings(ms: { reason: Reason; match: boolean | null }[], dest: Dest): { verdict: "allowed" | "partial" | "conditional" | null; tools?: ToolSplit; label?: string; note?: string } {
  if (!ms.length) return { verdict: null };
  const toolNames = dest.tools ? Object.keys(dest.tools) : [];
  if (dest.tools && toolNames.length) {
    // Per tool: allowed if any binding allows it, else unknown if any can't be told, else denied.
    const st = new Map<string, "allowed" | "unknown" | "denied">(toolNames.map((t) => [t, "denied"]));
    for (const { reason, match } of ms) {
      const split = match === null ? { allowed: [], denied: [], unknown: toolNames } : evaluateTools(reason.binding.condition, dest.tools);
      for (const t of split.allowed) st.set(t, "allowed");
      for (const t of split.unknown) if (st.get(t) === "denied") st.set(t, "unknown");
    }
    const tools: ToolSplit = { allowed: [], denied: [], unknown: [] };
    for (const [t, s] of st) tools[s === "allowed" ? "allowed" : s === "unknown" ? "unknown" : "denied"].push(t);
    if (!tools.denied.length && !tools.unknown.length) return { verdict: "allowed", tools };
    if (!tools.allowed.length && tools.unknown.length) return { verdict: "conditional", tools, label: "?" };
    const ro = ms.length === 1 && isReadOnlyHint(ms[0].reason.binding.condition?.expression ?? "");
    return { verdict: "partial", tools, label: ro ? "read-only" : `${tools.allowed.length}/${toolNames.length} tools` };
  }
  let unknown = false;
  let note: string | undefined;
  for (const { reason, match } of ms) {
    const ok = match === null ? null : conditionAllows(reason.binding.condition, {}, null);
    if (ok === true) {
      const expr = reason.binding.condition?.expression ?? "";
      if (expr && (isReadOnlyHint(expr) || parseTools(expr) !== null))
        note = "A tool condition on a destination that isn't an MCP server: its calls carry toolName '', which the condition allows.";
      return { verdict: "allowed", note };
    }
    if (ok === null) unknown = true;
  }
  return unknown ? { verdict: "conditional", label: "?" } : { verdict: null };
}

function viaOf(member: string, principal: string | null, registry: boolean): Via {
  if (registry) return "registry_wide";
  if (principal && member === principal) return "member";
  if (EVERYONE.includes(member)) return "public";
  if (PROJECT_AGENTS_RE.test(member)) return "project_agents";
  return "other";
}

export function buildPolicyGraph(input: GraphInput): PolicyGraph {
  return input.direction === "ingress" ? buildIngress(input) : buildEgress(input);
}

/** Model Armor on a gateway, from /model-armor. */
function maOf(input: GraphInput, gw: string): PNode["modelArmor"] {
  const m = input.modelArmor?.gateways.find((g) => g.gateway === gw);
  if (!m) return null;
  const gate = input.gateways.find((g) => g.name === gw);
  const ca = gate?.authz_policies.find((p) => p.profile === "CONTENT_AUTHZ");
  return { enabled: m.enabled, template: m.template?.id, summary: m.template?.summary, dryRun: m.enabled && ca?.enforcement === "DRY_RUN" };
}

function gatewayNode(input: GraphInput, g: Gateway): PNode {
  const ma = maOf(input, g.name);
  const mode = g.enforcement?.mode ?? null;
  const chips: Chip[] = [];
  if (g.type === "egress") {
    if (mode === "ENFORCE") chips.push({ text: "Default deny", tone: "red", title: "IAP checks every call against roles/iap.egressor grants and denies the rest." });
    else if (mode === "DRY_RUN") chips.push({ text: "Dry run: nothing is blocked", tone: "amber", title: "IAP decides, but every call passes and is logged as allowed." });
    else chips.push({ text: "No IAP policy", tone: "neutral", title: g.enforcement?.reason ?? "Nothing is checked against roles/iap.egressor grants." });
  } else {
    chips.push({ text: "In the path", tone: "blue", title: "Client-to-Agent gateways screen content; they don't check caller identity." });
    if (g.authz_policies.some((p) => p.provider === "iap" && p.profile === "REQUEST_AUTHZ"))
      chips.push({ text: "IAP policy configured", tone: "neutral", title: "Configured; Client-to-Agent doesn't check caller identity." });
  }
  if (ma?.enabled) chips.push({ text: ma.dryRun ? "Model Armor (dry run)" : "Model Armor", tone: "orange", title: ma.template ? `Template ${ma.template}` : undefined });
  if (g.enforcement?.shared_with.length) chips.push({ text: "Shared extension", tone: "neutral", title: `The IAP extension also serves ${g.enforcement.shared_with.map(short).join(", ")}: they change together.` });
  return {
    id: g.name,
    kind: "gateway",
    label: g.id,
    sub: g.type === "egress" ? "Egress · Agent-to-Anywhere" : "Ingress · Client-to-Agent",
    column: "gateways",
    section: "gateways",
    chips,
    gateway: g.name,
    mode,
    shared: g.enforcement?.shared_with ?? [],
    modelArmor: ma,
    search: `${g.id} ${g.name}`.toLowerCase(),
  };
}

function engineNode(e: Engine, gw: string | null, column: Column, agentEntry?: string): PNode {
  const chips: Chip[] = [{ text: e.identity_type === "AGENT_IDENTITY" ? "Agent Identity" : "Service account", tone: e.identity_type === "AGENT_IDENTITY" ? "neutral" : "amber" }];
  if (!gw && !e.bindable) chips.push({ text: "Can't be bound", tone: "amber", title: e.bindable_reason ?? undefined });
  return {
    id: e.name,
    kind: "engine",
    label: e.display_name || e.id,
    sub: e.id,
    column,
    section: gw ? `gw:${gw}` : "nogw",
    chips,
    gateway: gw,
    bindable: e.bindable,
    bindableReason: e.bindable_reason,
    identityType: e.identity_type,
    sameAs: agentEntry,
    search: `${e.display_name} ${e.id} ${e.name}`.toLowerCase(),
  };
}

function buildEgress(input: GraphInput): PolicyGraph {
  const { inventory: inv } = input;
  const notes: string[] = [];
  const egressGws = input.gateways.filter((g) => g.type === "egress");
  const gwByName = new Map(egressGws.map((g) => [g.name, g]));
  const projectSet = inv.project_agents_principal ?? null;
  const agentEntryOf = new Map(inv.agents.filter((a) => a.engine).map((a) => [a.engine!, a.name]));

  // ---------- callers: engines, by egress gateway ----------
  const nodes: PNode[] = [];
  const engineGw = new Map<string, string | null>();
  for (const e of inv.engines) {
    const gw = e.gateways.egress ?? null;
    engineGw.set(e.name, gw);
    const g = gw ? gwByName.get(gw) : undefined;
    if (gw && !g) notes.push(`${e.display_name} is bound to ${short(gw)}, which isn't in this region's gateway list.`);
    if (g && !g.bound_engines.some((b) => b.engine === e.name && b.direction === "egress"))
      notes.push(`${e.display_name} names ${g.id} as its egress gateway, but the gateway doesn't list it as bound.`);
    nodes.push(engineNode(e, gw, "callers", agentEntryOf.get(e.name)));
  }
  for (const g of egressGws)
    for (const b of g.bound_engines)
      if (b.direction === "egress" && engineGw.has(b.engine) && engineGw.get(b.engine) !== g.name)
        notes.push(`${g.id} lists ${b.display_name} as bound, but the agent names ${engineGw.get(b.engine) ? short(engineGw.get(b.engine)!) : "no egress gateway"}.`);
  const engineByPrincipal = new Map(inv.engines.map((e) => [e.principal, e]));

  // ---------- gateways ----------
  for (const g of egressGws) nodes.push(gatewayNode(input, g));
  for (const gw of new Set([...engineGw.values()].filter((x): x is string => !!x && !gwByName.has(x))))
    nodes.push({ id: gw, kind: "gateway", label: short(gw), sub: "Not in this region's gateway list", column: "gateways", section: "gateways", chips: [], gateway: gw, mode: null, search: gw.toLowerCase() });
  const unbound = inv.engines.filter((e) => !engineGw.get(e.name));
  nodes.push({ id: NOGW.egress, kind: "no_gateway", label: "No gateway", sub: "Traffic goes straight out", column: "gateways", section: "gateways", chips: [{ text: "Not governed", tone: "neutral" }], gateway: null, search: "no gateway" });
  nodes.push({ id: PSEUDO.anywhere, kind: "anywhere", label: "Anywhere", sub: "Any host on the internet", column: "sink", section: "sink", chips: [], search: "anywhere" });

  // ---------- destinations ----------
  const dests: Dest[] = [];
  const regKeys = [...Object.keys(inv.access), ...Object.keys(inv.access_errors ?? {})].filter((k) => REGISTRY_KEY_RE.test(k));
  const regKey = regKeys[0] ?? null;
  const addDest = (id: string, kind: ResourceKind, pk: PNodeKind, section: string, label: string, sub: string, extra: Partial<PNode>, tools: Record<string, boolean> | null) => {
    const unreadable = inv.access_errors?.[id];
    const chips: Chip[] = unreadable ? [{ text: "IAP policy couldn't be read", tone: "red", title: unreadable }] : [];
    const node: PNode = { id, kind: pk, label, sub, column: "dests", section, chips, destKind: kind, unreadable, search: `${label} ${short(id)} ${sub}`.toLowerCase(), ...extra };
    nodes.push(node);
    dests.push({ id, kind, label, node, tools });
  };
  if (regKey) addDest(regKey, "registry", "registry", "registry", "Agent Registry: all entries", "Registry-wide grants", {}, null);
  for (const a of inv.agents)
    addDest(a.name, "agent", a.kind === "a2a" ? "a2a" : "runtime_dest", a.kind === "a2a" ? "a2a" : "runtime", a.display_name, a.kind === "a2a" ? (a.url?.replace(/^https?:\/\//, "") ?? a.id) : a.id, { skills: a.skills.map((s) => s.name), sameAs: a.engine }, null);
  for (const m of inv.mcp_servers)
    addDest(m.name, "mcp_server", "mcp", "mcp", m.display_name, m.url?.replace(/^https?:\/\//, "") ?? m.id, { tools: m.tools.map((t) => ({ name: t.name, readOnly: t.read_only, destructive: t.destructive })) }, Object.fromEntries(m.tools.map((t) => [t.name, t.read_only])));
  for (const p of inv.endpoints) addDest(p.name, "endpoint", "endpoint", "api", p.display_name, p.url.replace(/^https?:\/\//, ""), {}, null);

  // Every egressor binding, as a Reason (registry-wide ones keyed by the registry).
  const reasonsOn = new Map<string, Reason[]>();
  let bindings = 0;
  for (const d of dests) {
    const rs = (inv.access[d.id] ?? []).filter((b) => b.role === ROLE).map((b): Reason => ({ binding: b, resource: d.id, resourceKind: d.kind, resourceLabel: d.label, via: d.kind === "registry" ? "registry_wide" : "member", access: accessFromCondition(b.condition?.expression) }));
    bindings += rs.length;
    reasonsOn.set(d.id, rs);
  }
  const regReasons = regKey ? (reasonsOn.get(regKey) ?? []) : [];

  // ---------- pseudo callers ----------
  const pseudo = new Map<string, PNode>();
  const pseudoNode = (id: string): PNode => {
    let n = pseudo.get(id);
    if (!n) {
      const label = id === PSEUDO.project ? "All agents in this project" : id === PSEUDO.public ? "Public" : "Other principals";
      const sub = id === PSEUDO.project ? "principalSet (Agent Identity)" : id === PSEUDO.public ? "allUsers / allAuthenticatedUsers" : "Service accounts, users, groups";
      const chips: Chip[] = id === PSEUDO.project ? [{ text: "Applies to agents created later too", tone: "amber" }] : id === PSEUDO.public ? [{ text: "Public grant", tone: "red", title: "See the Audit step's finding." }] : [];
      n = { id, kind: "principal_group", label, sub, column: "callers", section: "pseudo", chips, members: [], search: `${label} ${sub}`.toLowerCase() };
      pseudo.set(id, n);
    }
    return n;
  };

  // ---------- lines ----------
  const edges: PEdge[] = [];
  const gwMeta = (gw: string | null) => {
    const g = gw ? gwByName.get(gw) : undefined;
    const ma = gw ? maOf(input, gw) : null;
    return { gateway: gw ?? undefined, mode: g?.enforcement?.mode ?? null, modelArmor: !!ma?.enabled, modelArmorDryRun: !!ma?.dryRun };
  };
  for (const e of inv.engines) {
    const gw = engineGw.get(e.name) ?? null;
    edges.push(gw ? { id: `trunk:${e.name}`, source: e.name, target: gw, direction: "egress", verdict: "path", reasons: [], caller: e.name, ...gwMeta(gw) } : { id: `direct:${e.name}`, source: e.name, target: NOGW.egress, direction: "egress", verdict: "direct", reasons: [], caller: e.name });
  }
  if (unbound.length) edges.push({ id: "direct:nogw", source: NOGW.egress, target: PSEUDO.anywhere, direction: "egress", verdict: "direct", reasons: [] });

  /** One caller's line to one destination from the given bindings, or null. */
  const lineFor = (callerId: string, gw: string | null, d: Dest, ms: { reason: Reason; match: boolean | null }[], id: string, inherited: boolean): PEdge | null => {
    const r = evaluateBindings(ms, d);
    if (!r.verdict) return null;
    const meta = gwMeta(gw);
    const reasons = ms.map((m) => m.reason);
    return {
      id,
      source: gw ?? NOGW.egress,
      target: d.id,
      direction: "egress",
      verdict: gw ? r.verdict : "dormant",
      reasons,
      tools: r.tools,
      label: gw ? r.label : undefined,
      note: r.note,
      caller: callerId,
      inherited,
      ...meta,
    };
  };

  // Each engine's own grants (member = its principal), combined per (gateway, destination).
  const combined = new Map<string, PEdge[]>();
  for (const d of dests) {
    if (d.node.unreadable) continue;
    const own = new Map<string, Reason[]>();
    for (const r of reasonsOn.get(d.id) ?? []) {
      const e = engineByPrincipal.get(r.binding.member);
      if (e) own.set(e.name, [...(own.get(e.name) ?? []), r]);
      else {
        const p = pseudoNode(pseudoOf(r.binding.member, projectSet));
        const m = ENGINE_PRINCIPAL_RE.exec(r.binding.member);
        if (!p.members!.some((x) => x.member === r.binding.member)) p.members!.push({ member: r.binding.member, label: r.binding.member_label || r.binding.member, deleted: !!m });
      }
    }
    for (const [eng, rs] of own) {
      const gw = engineGw.get(eng) ?? null;
      const line = lineFor(eng, gw, d, rs.map((reason) => ({ reason, match: true })), `a:${eng}|${d.id}`, false);
      if (!line) continue;
      const k = `${gw ?? NOGW.egress}|${d.id}`;
      combined.set(k, [...(combined.get(k) ?? []), line]);
    }
  }
  for (const [k, parts] of combined) edges.push(combineParts(`c:${k}`, parts));

  // Pseudo callers: one line per (pseudo, destination), drawn straight to it (not through one gateway).
  for (const d of dests) {
    if (d.node.unreadable) continue;
    const by = new Map<string, Reason[]>();
    for (const r of reasonsOn.get(d.id) ?? []) {
      if (engineByPrincipal.has(r.binding.member)) continue;
      const pid = pseudoOf(r.binding.member, projectSet);
      by.set(pid, [...(by.get(pid) ?? []), { ...r, via: viaOf(r.binding.member, null, d.kind === "registry") }]);
    }
    for (const [pid, rs] of by) {
      const r = evaluateBindings(rs.map((reason) => ({ reason, match: true })), d);
      if (!r.verdict) continue;
      const members = new Set(rs.map((x) => x.binding.member)).size;
      edges.push({ id: `p:${pid}|${d.id}`, source: pid, target: d.id, direction: "egress", verdict: r.verdict, reasons: rs, tools: r.tools, label: members > 1 ? `${members} principals` : r.label, note: r.note, caller: pid });
    }
  }
  for (const p of pseudo.values()) {
    const deleted = p.members!.filter((m) => m.deleted && !engineByPrincipal.has(m.member)).length;
    if (deleted) p.chips.push({ text: deleted > 1 ? `${deleted} deleted agents` : "Deleted agent", tone: "red", title: "A reasoningEngines principal that isn't in the inventory still holds a grant." });
    if (p.id === PSEUDO.other) p.sub = `${p.members!.length} ${p.members!.length === 1 ? "principal" : "principals"}`;
    p.search += ` ${p.members!.map((m) => m.label.toLowerCase()).join(" ")}`;
    nodes.push(p);
  }

  // ---------- per-engine summary: inherited reach and default-deny count ----------
  const pairFor = (e: Engine, d: Dest, inherited: boolean): PEdge | null => {
    if (d.node.unreadable) return null;
    const gw = engineGw.get(e.name) ?? null;
    const own = (reasonsOn.get(d.id) ?? []).filter((r) => r.binding.member === e.principal);
    const pool = d.kind === "registry" ? (reasonsOn.get(d.id) ?? []) : [...(reasonsOn.get(d.id) ?? []), ...regReasons];
    const ms = (inherited ? pool : own)
      .map((r) => ({ reason: { ...r, via: viaOf(r.binding.member, e.principal, r.resourceKind === "registry") }, match: memberMatches(r.binding.member, e.principal) }))
      .filter((m) => m.match !== false);
    // Inherited: nothing on this destination names the agent itself (only group, public or registry-wide grants).
    const inh = !ms.some((m) => m.reason.binding.member === e.principal && m.reason.resource === d.id);
    return lineFor(e.name, gw, d, ms, `a:${e.name}|${d.id}`, inh);
  };
  for (const n of nodes) {
    if (n.kind !== "engine") continue;
    const e = inv.engines.find((x) => x.name === n.id)!;
    let inh = 0;
    let denied = 0;
    for (const d of dests) {
      if (d.node.unreadable) continue;
      const line = pairFor(e, d, true);
      if (line?.inherited) inh++;
      if (!line && n.gateway && d.node.sameAs !== e.name) denied++;
    }
    n.inheritedCount = inh;
    n.deniedCount = n.gateway ? denied : 0;
    if (inh) n.chips.push({ text: `+${inh} via group or registry-wide grants`, tone: "blue", title: "Reachable through a project-wide, public, group or registry-wide grant. Select the agent to see them." });
    if (denied) {
      const mode = n.gateway ? gwByName.get(n.gateway)?.enforcement?.mode : null;
      n.chips.push(mode === "DRY_RUN" ? { text: `Would be denied: ${denied}`, tone: "amber", title: "Destinations with no grant: denied by default once the gateway enforces (it's in dry run, so they pass today)." } : { text: `Denied by default: ${denied}`, tone: "red", title: "Destinations this agent holds no grant on." });
    }
    if (!n.gateway && edges.some((x) => x.parts?.some((p) => p.caller === n.id))) n.chips.push({ text: "Grants not enforced", tone: "neutral", title: "Its grants are never checked: no egress gateway in the path." });
  }

  // ---------- the focused agent's own lines ----------
  let focusLines: PEdge[] | null = null;
  const fe = input.focus ? inv.engines.find((e) => e.name === input.focus) : undefined;
  if (fe) {
    const gw = engineGw.get(fe.name) ?? null;
    const mode = gw ? (gwByName.get(gw)?.enforcement?.mode ?? null) : null;
    focusLines = edges.filter((x) => x.caller === fe.name && !x.parts);
    if (!gw) focusLines.push(...edges.filter((x) => x.id === "direct:nogw"));
    for (const d of dests) {
      if (d.node.unreadable) continue;
      const line = pairFor(fe, d, input.inherited !== false);
      if (line) focusLines.push(line);
      // no default-deny line to the agent's own registry entry (it doesn't call itself through the gateway)
      else if (gw && d.node.sameAs !== fe.name)
        focusLines.push({ id: `x:${fe.name}|${d.id}`, source: gw, target: d.id, direction: "egress", verdict: mode === "ENFORCE" ? "blocked" : mode === "DRY_RUN" ? "would_deny" : "unchecked", reasons: [], implicit: true, caller: fe.name, ...gwMeta(gw) });
    }
  }

  return {
    direction: "egress",
    nodes,
    edges,
    focusLines,
    stats: { engines: inv.engines.length, destinations: dests.length, bindings, gateways: egressGws.length, unbound: unbound.length, unreadable: Object.keys(inv.access_errors ?? {}).length },
    notes: [...new Set(notes)],
  };
}

/** A combined gateway → destination line: verdict = the best of its parts, count badge = the number of agents. */
export function combineParts(id: string, parts: PEdge[]): PEdge {
  const sorted = [...parts].sort((a, b) => (a.caller ?? "").localeCompare(b.caller ?? ""));
  const v = bestVerdict(sorted.map((p) => p.verdict));
  const first = sorted[0];
  return {
    ...first,
    id,
    verdict: v,
    reasons: sorted.flatMap((p) => p.reasons),
    tools: sorted.length === 1 ? first.tools : undefined,
    caller: sorted.length === 1 ? first.caller : undefined,
    label: sorted.length > 1 ? `${sorted.length} agents` : first.label,
    parts: sorted,
  };
}

// ---------- Client-to-Agent (§6.2, §6.3) ----------
function buildIngress(input: GraphInput): PolicyGraph {
  const { inventory: inv } = input;
  const notes: string[] = ["A Client-to-Agent gateway doesn't check caller identity: it screens content with Model Armor. Who may call an agent is decided by its Agent Runtime IAM, which Policy Studio doesn't read."];
  const nodes: PNode[] = [];
  const edges: PEdge[] = [];
  const ingressGws = input.gateways.filter((g) => g.type === "ingress");
  const gwByName = new Map(ingressGws.map((g) => [g.name, g]));

  const clients: PNode[] = [
    { id: CLIENT.any, kind: "client", label: "Any allowed caller", sub: "Allowed by the agent's Agent Runtime IAM (not read by Policy Studio)", column: "callers", section: "clients", chips: [{ text: "Identity not checked here", tone: "neutral" }], search: "any allowed caller client" },
  ];
  const ge = input.ctx?.ge_app;
  if (ge) clients.push({ id: CLIENT.ge, kind: "client", label: "Gemini Enterprise app", sub: `${ge} (from Context; registration not verified)`, column: "callers", section: "clients", chips: [], search: `gemini enterprise ${ge}`.toLowerCase() });
  nodes.push(...clients);
  for (const g of ingressGws) nodes.push(gatewayNode(input, g));
  nodes.push({ id: NOGW.ingress, kind: "no_gateway", label: "No ingress gateway", sub: "Calls reach the agent directly", column: "gateways", section: "gateways", chips: [{ text: "Not screened", tone: "neutral" }], gateway: null, search: "no ingress gateway" });

  const engines = [...inv.engines].sort((a, b) => Number(!a.gateways.ingress) - Number(!b.gateways.ingress) || a.display_name.localeCompare(b.display_name));
  const usedGw = new Set<string>();
  let direct = 0;
  for (const e of engines) {
    const gw = e.gateways.ingress ?? null;
    const g = gw ? gwByName.get(gw) : undefined;
    if (gw && !g) notes.push(`${e.display_name} is bound to ${short(gw)}, which isn't in this region's gateway list.`);
    if (g && !g.bound_engines.some((b) => b.engine === e.name && b.direction === "ingress")) notes.push(`${e.display_name} names ${g.id} as its ingress gateway, but the gateway doesn't list it as bound.`);
    // no "same agent" link here: registry entries aren't drawn in this direction
    nodes.push(engineNode(e, gw, "dests"));
    if (gw) {
      if (!gwByName.has(gw) && !nodes.some((x) => x.id === gw)) nodes.push({ id: gw, kind: "gateway", label: short(gw), sub: "Not in this region's gateway list", column: "gateways", section: "gateways", chips: [], gateway: gw, search: gw.toLowerCase() });
      usedGw.add(gw);
      const ma = maOf(input, gw);
      const v: Verdict = ma?.enabled ? "screened" : "unscreened";
      edges.push({ id: `i:${gw}|${e.name}`, source: gw, target: e.name, direction: "ingress", verdict: v, reasons: [], gateway: gw, modelArmor: !!ma?.enabled, modelArmorDryRun: !!ma?.dryRun, caller: e.name });
    } else {
      direct++;
      edges.push({ id: `i:${NOGW.ingress}|${e.name}`, source: NOGW.ingress, target: e.name, direction: "ingress", verdict: "direct", reasons: [], caller: e.name });
    }
  }
  for (const c of clients) {
    for (const gw of [...usedGw].sort()) {
      const ma = maOf(input, gw);
      const n = edges.filter((x) => x.source === gw).length;
      edges.push({ id: `i:${c.id}|${gw}`, source: c.id, target: gw, direction: "ingress", verdict: ma?.enabled ? "screened" : "unscreened", reasons: [], gateway: gw, modelArmor: !!ma?.enabled, modelArmorDryRun: !!ma?.dryRun, label: n > 1 ? `${n} agents` : undefined });
    }
    if (direct) edges.push({ id: `i:${c.id}|${NOGW.ingress}`, source: c.id, target: NOGW.ingress, direction: "ingress", verdict: "direct", reasons: [], label: direct > 1 ? `${direct} agents` : undefined });
  }
  return {
    direction: "ingress",
    nodes,
    edges,
    focusLines: null,
    stats: { engines: inv.engines.length, destinations: inv.engines.length, bindings: 0, gateways: ingressGws.length, unbound: direct, unreadable: 0 },
    notes,
  };
}
