// The policy map's graph: who can reach what, and why, from the state Policy Studio already reads (inventory,
// gateways, Model Armor, context). Pure, no React (docs/VISUALIZATION_PLAN.md §4.3–4.5, §6).
//
// Egress lines follow §4.4: the caller's egress gateway and its mode, the roles/iap.egressor bindings on the
// destination and on the registry (registry-wide), matched with evaluate.ts (the port of dryrun.py). Every line
// belongs to exactly one caller (`caller`): each agent's trunk to its gateway, then its own line to each destination
// (its own grants, the group, public and registry-wide grants it inherits, and default deny), never combined across
// agents. Group, public and registry-wide grants are also drawn once from their pseudo caller. The map draws only the
// selected callers' lines (view.ts).
//
// Default deny (implicit lines, the "Denied by default" chip) means no grant applies at all: not the agent's own, not an
// inherited one (project-wide principalSet, public, registry-wide) and not a group one that might (those are "?", never
// denied). With Inherited grants off, a destination reached only through an inherited grant gets no line (it isn't
// denied), and an MCP tool allowed only through one is set aside (ToolSplit.inherited) instead of being denied. The
// Agent Registry node stands for registry-wide grants, not a destination: never a default-deny line, never counted.
import type { Access, Binding, ContextInfo, Ctx, EnforcementMode, Engine, Gateway, Inventory, ModelArmorResp } from "../api/types";
import { ROLE, accessFromCondition } from "../lib/policy";
import { ENGINE_PRINCIPAL_RE, EVERYONE, PROJECT_AGENTS_RE, conditionAllows, evaluateTools, isReadOnlyHint, memberMatches, parseTools } from "./evaluate";
import { CLIENT, NOGW, PSEUDO, pseudoOf } from "./ids";
import { endpointLabel, isGoogleApi } from "./labels";
import { privateEgressChip, privateEgressSummary, pscChips } from "../lib/networking";

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
  | "google_apis" // Google API endpoints (*.googleapis.com), collapsed into one node (view.ts)
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
/** inherited: tools only an inherited grant allows (or might), set aside on a line drawn with Inherited grants off:
 *  neither drawn as allowed nor as denied. */
export type ToolSplit = { allowed: string[]; denied: string[]; unknown: string[]; inherited?: string[] };

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
  /** Gateway: its direction (egress = Agent-to-Anywhere, ingress = Client-to-Agent), IAP enforcement mode and Model
   *  Armor. */
  gwType?: Direction;
  mode?: EnforcementMode | null;
  shared?: string[];
  modelArmor?: { enabled: boolean; template?: string; summary?: string[]; dryRun?: boolean } | null;
  /** The same Agent Runtime agent as an engine (caller) and a registry entry (destination). */
  sameAs?: string;
  /** Engine (egress): destinations reachable only through group, public or registry-wide grants, and the number it
   *  can't reach (default deny), both for the node's summary chips. */
  inheritedCount?: number;
  deniedCount?: number;
  /** Engine (egress): destinations its own grants allow (the "N allowed" chip). */
  allowedCount?: number;
  /** Pseudo callers: the members drawn from this node. */
  members?: { member: string; label: string; deleted?: boolean }[];
  /** endpoint_group / google_apis: the grouped destinations. */
  grouped?: string[];
  /** Endpoint: the registry entry's display name and URL as registered (the label may be just the host), and whether
   *  its host is *.googleapis.com (grouped into "Google APIs" on the map). */
  displayName?: string;
  url?: string;
  googleApi?: boolean;
  /** Lowercase label + id + sub, for search. */
  search: string;
  /** Set by the view (view.ts), not the graph. MCP: the tool rows drawn when Show: Allows / Denies leaves out some (the
   *  union over the selected agents' lines into it); unset = every tool. */
  shownTools?: string[];
  /** A selected caller: its lines left out because their other end is hidden (a type filter, unchecked by hand). */
  hiddenLines?: number;
  /** Staged-change view (diff.ts): what the cart changes on this node, and the cart intents that do it. */
  /** shield: Model Armor turned on or off by the cart (drawn as a pending shield on the gateway). */
  pending?: { text: string[]; removed?: boolean; intents: string[]; shield?: { to: "on" | "off"; template?: string } };
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
  /** The caller (engine or pseudo id) the line belongs to: every line has one, except in hand-made fixtures. */
  caller?: string;
  /** A line into the "Google APIs" group: the per-endpoint lines it stands for (view.ts). */
  members?: PEdge[];
  /** Set by the view (view.ts) on an MCP line Show: Allows / Denies narrows to some tools: the tools it still shows,
   *  how many allowed and denied ones it leaves out, and the verdict over every tool. `shownTools` unset = every tool. */
  shownTools?: string[];
  hiddenTools?: { allowed: number; denied: number; inherited?: number };
  whole?: Verdict;
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
  /** Every caller's lines: trunks, each agent's own, inherited and default-deny lines, pseudo-caller lines. */
  edges: PEdge[];
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
  /** Add group / public / registry-wide grants to each agent's lines (default true). */
  inherited?: boolean;
}

/** The tooltip of an ingress gateway's IAP policy (§6.3, open question 3). */
export const IAP_INGRESS_NOTE = "Configured; Client-to-Agent doesn't check caller identity.";

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

/** Best first: a line merged into the Google APIs group takes the best of its endpoints. */
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
    // shown exactly as configured (a shared IAP extension can put one here), but it isn't an identity check
    const iap = g.authz_policies.find((p) => p.provider === "iap" && p.profile === "REQUEST_AUTHZ");
    if (iap) chips.push({ text: `IAP REQUEST_AUTHZ${iap.enforcement ? ` · ${iap.enforcement === "DRY_RUN" ? "dry run" : "enforce"}` : ""}`, tone: "neutral", title: IAP_INGRESS_NOTE });
  }
  if (ma?.enabled) chips.push({ text: ma.dryRun ? "Model Armor (dry run)" : "Model Armor", tone: "orange", title: ma.template ? `Template ${ma.template}` : undefined });
  if (g.enforcement?.shared_with.length) chips.push({ text: "Shared extension", tone: "neutral", title: `The IAP extension also serves ${g.enforcement.shared_with.map(short).join(", ")}: they change together.` });
  const pe = privateEgressChip(g.private_egress);
  if (pe) chips.push({ text: pe, tone: g.private_egress?.error ? "amber" : "blue", title: privateEgressSummary(g.private_egress) });
  return {
    id: g.name,
    kind: "gateway",
    label: g.id,
    sub: g.type === "egress" ? "Egress · Agent-to-Anywhere" : "Ingress · Client-to-Agent",
    column: "gateways",
    section: "gateways",
    chips,
    gateway: g.name,
    gwType: g.type,
    mode,
    shared: g.enforcement?.shared_with ?? [],
    modelArmor: ma,
    search: `${g.id} ${g.name}`.toLowerCase(),
  };
}

function engineNode(e: Engine, gw: string | null, column: Column, agentEntry?: string): PNode {
  const chips: Chip[] = [{ text: e.identity_type === "AGENT_IDENTITY" ? "Agent Identity" : "Service account", tone: e.identity_type === "AGENT_IDENTITY" ? "neutral" : "amber" }];
  // Egress map (callers): an agent with its own PSC interface gets the red "bypasses gateway" chip (and "Broken" when
  // it is also bound), which says why it can't be bound; elsewhere the generic chip.
  const psc = column === "callers" ? pscChips(e) : [];
  if (psc.length) chips.push(...psc.map((c) => ({ text: c.text, tone: "red" as const, title: [c.tip, !gw && e.bindable_reason].filter(Boolean).join("\n") })));
  else if (!gw && !e.bindable) chips.push({ text: "Can't be bound", tone: "amber", title: e.bindable_reason ?? undefined });
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
  for (const p of inv.endpoints) {
    const label = endpointLabel(p.display_name, p.url);
    const bare = p.url.replace(/^https?:\/\//, "");
    // the card title is the host when the display name only repeats it; the sub then shows the display name
    const sub = p.display_name && p.display_name !== label ? p.display_name : bare !== label ? bare : "";
    addDest(p.name, "endpoint", "endpoint", "api", label, sub, { displayName: p.display_name, url: p.url, googleApi: isGoogleApi(p.url) }, null);
    dests[dests.length - 1].node.search += ` ${p.display_name} ${p.url}`.toLowerCase();
  }

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
  // Each agent's lane: its trunk to its gateway, or straight out (No gateway → Anywhere) when it has none.
  for (const e of inv.engines) {
    const gw = engineGw.get(e.name) ?? null;
    if (gw) edges.push({ id: `trunk:${e.name}`, source: e.name, target: gw, direction: "egress", verdict: "path", reasons: [], caller: e.name, ...gwMeta(gw) });
    else {
      edges.push({ id: `direct:${e.name}`, source: e.name, target: NOGW.egress, direction: "egress", verdict: "direct", reasons: [], caller: e.name });
      edges.push({ id: `out:${e.name}`, source: NOGW.egress, target: PSEUDO.anywhere, direction: "egress", verdict: "direct", reasons: [], caller: e.name });
    }
  }

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

  // Pseudo callers: one line per (pseudo, destination), drawn straight to it (not through one gateway).
  for (const d of dests) {
    if (d.node.unreadable) continue;
    const by = new Map<string, Reason[]>();
    for (const r of reasonsOn.get(d.id) ?? []) {
      if (engineByPrincipal.has(r.binding.member)) continue;
      const pid = pseudoOf(r.binding.member, projectSet);
      const p = pseudoNode(pid);
      if (!p.members!.some((x) => x.member === r.binding.member)) p.members!.push({ member: r.binding.member, label: r.binding.member_label || r.binding.member, deleted: !!ENGINE_PRINCIPAL_RE.exec(r.binding.member) });
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

  // ---------- each agent's own lines, and its summary chips ----------
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
  const withInherited = input.inherited !== false;
  for (const n of nodes) {
    if (n.kind !== "engine") continue;
    const e = inv.engines.find((x) => x.name === n.id)!;
    const gw = engineGw.get(e.name) ?? null;
    const mode = gw ? (gwByName.get(gw)?.enforcement?.mode ?? null) : null;
    const deny = (d: Dest, tools?: ToolSplit): PEdge => ({
      id: `x:${e.name}|${d.id}`,
      source: gw!,
      target: d.id,
      direction: "egress",
      verdict: mode === "ENFORCE" ? "blocked" : mode === "DRY_RUN" ? "would_deny" : "unchecked",
      reasons: [],
      implicit: true,
      caller: e.name,
      ...(tools ? { tools } : {}),
      ...gwMeta(gw),
    });
    let own = 0;
    let inh = 0;
    let denied = 0;
    for (const d of dests) {
      if (d.node.unreadable) continue;
      let line = pairFor(e, d, withInherited);
      // every grant that applies, inherited ones included: what decides default deny, whatever the lines show
      const full = withInherited ? line : pairFor(e, d, true);
      // the registry node isn't a destination: its lines are drawn, but it's never denied nor counted
      const registry = d.kind === "registry";
      if (full?.inherited && !registry) inh++;
      // no default-deny line to the agent's own registry entry (it doesn't call itself through the gateway)
      const self = d.node.sameAs === e.name;
      if (!full && gw && !self && !registry) denied++;
      // Inherited grants off, MCP: tools only an inherited grant allows aren't denied. On the agent's own line they're
      // set aside; with no own grant, only the tools no grant allows are left, as a default-deny line.
      let rest: ToolSplit | undefined;
      if (!withInherited && full?.tools && gw) {
        const fd = new Set(full.tools.denied);
        if (line?.tools) {
          const set = line.tools.denied.filter((t) => !fd.has(t));
          if (set.length) line = { ...line, tools: { ...line.tools, denied: line.tools.denied.filter((t) => fd.has(t)), inherited: set } };
        } else if (!line && fd.size && !self) {
          const names = Object.keys(d.tools ?? {});
          rest = { allowed: [], denied: names.filter((t) => fd.has(t)), unknown: [], inherited: names.filter((t) => !fd.has(t)) };
        }
      }
      if (line) {
        edges.push(line);
        if (!line.inherited && !registry) own++;
      } else if (rest) edges.push({ ...deny(d, rest), label: `${rest.denied.length}/${rest.denied.length + rest.inherited!.length} tools denied` });
      // default deny only when no grant applies at all (an inherited-only destination, Inherited off: no line)
      else if (!full && gw && !self && !registry) edges.push(deny(d));
    }
    n.inheritedCount = inh;
    n.deniedCount = gw ? denied : 0;
    n.allowedCount = own;
    if (gw) n.chips.push({ text: `${own} allowed`, tone: own ? "green" : "neutral", title: "Destinations its own grants allow (fully, some tools, or under a condition). Select the agent to see them." });
    else if (own) n.chips.push({ text: `${own} ${own === 1 ? "grant" : "grants"} not enforced`, tone: "neutral", title: "Its grants are never checked: no egress gateway in the path." });
    if (inh) n.chips.push({ text: `+${inh} via group or registry-wide grants`, tone: "blue", title: "Reachable through a project-wide, public, group or registry-wide grant. Select the agent to see them." });
    if (denied)
      n.chips.push(mode === "DRY_RUN" ? { text: `Would be denied: ${denied}`, tone: "amber", title: "Destinations with no grant: denied by default once the gateway enforces (it's in dry run, so they pass today)." } : { text: `Denied by default: ${denied}`, tone: "red", title: "Destinations this agent holds no grant on." });
  }

  return {
    direction: "egress",
    nodes,
    edges,
    stats: { engines: inv.engines.length, destinations: dests.length, bindings, gateways: egressGws.length, unbound: unbound.length, unreadable: Object.keys(inv.access_errors ?? {}).length },
    notes: [...new Set(notes)],
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
      const ma = maOf(input, gw);
      const v: Verdict = ma?.enabled ? "screened" : "unscreened";
      edges.push({ id: `i:${gw}|${e.name}`, source: gw, target: e.name, direction: "ingress", verdict: v, reasons: [], gateway: gw, modelArmor: !!ma?.enabled, modelArmorDryRun: !!ma?.dryRun, caller: e.name });
    } else {
      direct++;
      edges.push({ id: `i:${NOGW.ingress}|${e.name}`, source: NOGW.ingress, target: e.name, direction: "ingress", verdict: "direct", reasons: [], caller: e.name });
    }
  }
  // Each agent's lines from every client into its lane (one per agent, never combined).
  for (const e of engines) {
    const gw = e.gateways.ingress ?? null;
    const ma = gw ? maOf(input, gw) : null;
    for (const c of clients)
      edges.push(
        gw
          ? { id: `i:${c.id}|${gw}|${e.name}`, source: c.id, target: gw, direction: "ingress", verdict: ma?.enabled ? "screened" : "unscreened", reasons: [], gateway: gw, modelArmor: !!ma?.enabled, modelArmorDryRun: !!ma?.dryRun, caller: e.name }
          : { id: `i:${c.id}|${NOGW.ingress}|${e.name}`, source: c.id, target: NOGW.ingress, direction: "ingress", verdict: "direct", reasons: [], caller: e.name },
      );
  }
  return {
    direction: "ingress",
    nodes,
    edges,
    stats: { engines: inv.engines.length, destinations: inv.engines.length, bindings: 0, gateways: ingressGws.length, unbound: direct, unreadable: 0 },
    notes,
  };
}
