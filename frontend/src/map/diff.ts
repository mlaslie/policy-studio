// The staged-change view (docs/VISUALIZATION_PLAN.md §8): the graph built from today's state and from the state after
// the cart (simulate.ts), compared line by line. Pure.
//
// Every line is one caller's. Lines are paired by id, except that an agent's default-deny line (x:<agent>|<dest>) pairs
// with its granted line (a:<agent>|<dest>), and its trunk to a gateway with its direct line (a bind or unbind, in
// either direction; Client-to-Agent: each client's line into the agent's lane too): a grant
// turns the red ✕ into a pending add, a revoke turns the green line into a pending remove ("blocked by default" after),
// a bind or unbind is a pending change that moves the agent's lane. The merged graph
// holds every line as it will be, plus the removed lines as they are today, each marked with its cart intents.
import type { Engine, Intent, Inventory } from "../api/types";
import type { Chip, PEdge, PNode, PolicyGraph, Verdict } from "./graph";
import { VERDICT_LABEL } from "./toFlow";

export interface EdgeChange {
  id: string;
  pending: "add" | "remove" | "change";
  before?: PEdge;
  after?: PEdge;
}
export interface GraphDiff {
  edges: EdgeChange[];
  /** Node id → what changes on it (lane, enforcement mode, Model Armor). */
  nodes: Map<string, string[]>;
  /** Gateway id → Model Armor turned on or off by the cart (the pending shield). */
  shields: Map<string, "on" | "off">;
}

/** The pairing key: default-deny and granted lines of one agent and destination are the same line; so are an agent's
 *  trunk and its direct line, and (Client-to-Agent) its line from a gateway and from "No ingress gateway", and each
 *  client's line into either. */
export function pairKey(e: PEdge): string {
  if (e.id.startsWith("x:")) return `a:${e.id.slice(2)}`;
  if (e.direction === "ingress" && e.caller) return e.source.startsWith("client:") ? `lane:${e.source}|${e.caller}` : `lane:${e.caller}`;
  if (e.id.startsWith("trunk:") || e.id.startsWith("direct:")) return `lane:${e.caller ?? e.source}`;
  return e.id;
}

/** A line's grants in a comparable form: member, resource and condition expression. */
const sig = (e: PEdge) =>
  e.reasons
    .map((r) => `${e.caller ?? ""}|${r.binding.member}|${r.resource}|${(r.binding.condition?.expression ?? "").replace(/\s+/g, " ").trim()}`)
    .sort()
    .join("\n");
const toolSig = (e: PEdge) => (e.tools ? `${[...e.tools.allowed].sort()}/${[...e.tools.denied].sort()}/${[...e.tools.unknown].sort()}` : "");

function compare(before: PEdge[], after: PEdge[]): EdgeChange[] {
  const b = new Map(before.map((e) => [pairKey(e), e]));
  const a = new Map(after.map((e) => [pairKey(e), e]));
  const out: EdgeChange[] = [];
  for (const [k, x] of b) {
    const y = a.get(k);
    if (!y) out.push({ id: x.id, pending: "remove", before: x });
    else if (y.implicit && !x.implicit) out.push({ id: x.id, pending: "remove", before: x, after: y });
    else if (x.implicit && !y.implicit) out.push({ id: y.id, pending: "add", before: x, after: y });
    else if (x.verdict !== y.verdict || x.source !== y.source || x.target !== y.target || (x.label ?? "") !== (y.label ?? "") || sig(x) !== sig(y) || toolSig(x) !== toolSig(y))
      out.push({ id: y.id, pending: "change", before: x, after: y });
  }
  for (const [k, y] of a) if (!b.has(k)) out.push({ id: y.id, pending: "add", after: y });
  return out;
}

export function diffGraphs(before: PolicyGraph, after: PolicyGraph): GraphDiff {
  const nodes = new Map<string, string[]>();
  const shields = new Map<string, "on" | "off">();
  const bn = new Map(before.nodes.map((n) => [n.id, n]));
  const label = (id: string | null | undefined) => (id ? (bn.get(id)?.label ?? after.nodes.find((n) => n.id === id)?.label ?? id.split("/").pop()!) : "");
  for (const n of after.nodes) {
    const o = bn.get(n.id);
    if (!o) continue;
    const t: string[] = [];
    if (n.kind === "engine" && (o.gateway ?? null) !== (n.gateway ?? null)) t.push(n.gateway ? `Binding to ${label(n.gateway)} staged` : `Unbinding from ${label(o.gateway)} staged`);
    if (n.kind === "gateway" && (o.mode ?? null) !== (n.mode ?? null)) t.push(`${modeText(o.mode)} → ${modeText(n.mode)} (staged)`);
    if (n.kind === "gateway" && !!o.modelArmor?.enabled !== !!n.modelArmor?.enabled) {
      t.push(n.modelArmor?.enabled ? "Model Armor on (staged)" : "Model Armor off (staged)");
      shields.set(n.id, n.modelArmor?.enabled ? "on" : "off");
    }
    if (t.length) nodes.set(n.id, t);
  }
  return { edges: compare(before.edges, after.edges), nodes, shields };
}

const modeText = (m: PNode["mode"]) => (m === "ENFORCE" ? "Enforce" : m === "DRY_RUN" ? "Dry run" : "No IAP policy");

/** What a removed line becomes: default deny on its gateway, when it had one (egress only). */
function afterRemoved(e: PEdge): Verdict | undefined {
  if (e.direction !== "egress" || !e.gateway || e.verdict === "path" || e.caller?.startsWith("pseudo:")) return undefined;
  return e.mode === "ENFORCE" ? "blocked" : e.mode === "DRY_RUN" ? "would_deny" : undefined;
}

/** "Today: full access → After: read-only" for a pending line. */
export function pendingText(e: PEdge): string {
  const was = e.before ? `${VERDICT_LABEL[e.before]}${e.beforeLabel ? ` (${e.beforeLabel})` : ""}` : "no line";
  if (e.pending === "remove") return `Today: ${VERDICT_LABEL[e.verdict]}${e.label ? ` (${e.label})` : ""} → After: ${e.after ? VERDICT_LABEL[e.after] : "removed"}`;
  const same = e.before === e.verdict && (e.beforeLabel ?? "") === (e.label ?? "");
  return `Today: ${was} → After: ${VERDICT_LABEL[e.verdict]}${e.label && e.label !== "?" ? ` (${e.label})` : ""}${same ? " (the grants behind it change)" : ""}`;
}

// ---------- which cart intents make a change ----------
/** Principals behind a line: its grants' members and its callers' identities. */
function principalsOf(e: PEdge | undefined, engines: Map<string, Engine>): Set<string> {
  const out = new Set<string>();
  if (!e) return out;
  for (const r of e.reasons) out.add(r.binding.member);
  const eng = e.caller ? engines.get(e.caller) : undefined;
  if (eng) out.add(eng.principal);
  return out;
}
const callersOf = (e: PEdge | undefined): Set<string> => new Set((e ? [e.caller, e.source, e.target] : []).filter((x): x is string => !!x));
/** Resources whose bindings make up a line (a registry-wide grant counts on every destination it reaches). */
const resourcesOf = (e: PEdge | undefined) => new Set(e ? [e.target, ...e.reasons.map((r) => r.resource)] : []);

export function intentsFor(c: Pick<EdgeChange, "before" | "after">, cart: Intent[], engines: Map<string, Engine>, effects: Record<string, string[]>): string[] {
  const principals = new Set([...principalsOf(c.before, engines), ...principalsOf(c.after, engines)]);
  const nodes = new Set([...callersOf(c.before), ...callersOf(c.after)]);
  const resources = new Set([...resourcesOf(c.before), ...resourcesOf(c.after)]);
  const gws = new Set([c.before?.gateway, c.after?.gateway].filter(Boolean));
  return cart
    .filter((i) => {
      if (i.kind === "grant" || i.kind === "revoke" || i.kind === "modify") return !!i.source && !!i.destination && principals.has(i.source.principal) && resources.has(i.destination.name);
      if (i.kind === "bind_gateway" || i.kind === "unbind_gateway") return !!i.engine && nodes.has(i.engine) && (i.gateway?.direction ?? "egress") === (c.after ?? c.before)?.direction;
      if (i.kind === "set_enforcement") return (effects[i.id] ?? []).some((g) => gws.has(g) || nodes.has(g));
      // Model Armor screens the line as it will be: not one that leaves the gateway (an unbind staged with it)
      if (i.kind === "model_armor_on" || i.kind === "model_armor_off") return (effects[i.id] ?? []).includes((c.after ? c.after.gateway : c.before?.gateway) ?? "");
      return false;
    })
    .map((i) => i.id);
}

/** Before and after merged into one graph for the map: every line as it will be, removed lines as they are today. */
export function mergeStaged(before: PolicyGraph, after: PolicyGraph, d: GraphDiff, cart: Intent[], inv: Inventory, effects: Record<string, string[]>): PolicyGraph {
  const engines = new Map(inv.engines.map((e) => [e.name, e]));
  const bn = new Map(before.nodes.map((n) => [n.id, n]));
  const merge = (afterEdges: PEdge[], changes: EdgeChange[]): PEdge[] => {
    const byId = new Map(changes.map((c) => [c.id, c]));
    // the default-deny line that a pending add replaces isn't drawn twice
    const replaced = new Set(changes.filter((c) => c.pending === "remove" && c.after).map((c) => c.after!.id));
    const out: PEdge[] = [];
    for (const e of afterEdges) {
      if (replaced.has(e.id)) continue;
      const c = byId.get(e.id);
      if (!c || c.pending === "remove") {
        out.push(e);
        continue;
      }
      out.push({ ...e, pending: c.pending, before: c.before?.verdict, beforeLabel: c.before?.label, intents: intentsFor(c, cart, engines, effects) });
    }
    for (const c of changes)
      if (c.pending === "remove") out.push({ ...c.before!, pending: "remove", after: c.after?.verdict ?? afterRemoved(c.before!), intents: intentsFor(c, cart, engines, effects) });
    return out;
  };
  const edges = merge(after.edges, d.edges);

  // nodes: as they will be, plus the ones only removed lines still need (marked removed)
  const afterIds = new Set(after.nodes.map((n) => n.id));
  const needed = new Set(edges.flatMap((e) => [e.source, e.target]));
  const nodes: PNode[] = after.nodes.map((n) => {
    const t = d.nodes.get(n.id);
    if (!t) return n;
    const intents = cart.filter((i) => (i.engine && i.engine === n.id) || (effects[i.id] ?? []).includes(n.id)).filter((i) => !["grant", "revoke", "modify"].includes(i.kind)).map((i) => i.id);
    const chips: Chip[] = [...n.chips, ...t.map((text): Chip => ({ text, tone: "amber", pending: true }))];
    // Model Armor on or off: a pending shield (turned off, it carries today's template, which the node no longer has)
    const to = d.shields.get(n.id);
    const shield = to ? { to, template: (to === "off" ? bn.get(n.id) : n)?.modelArmor?.template } : undefined;
    return { ...n, chips, pending: { text: t, intents, ...(shield ? { shield } : {}) } };
  });
  for (const n of before.nodes)
    if (!afterIds.has(n.id) && needed.has(n.id)) nodes.push({ ...n, chips: [...n.chips, { text: "Removed (staged)", tone: "amber", pending: true }], pending: { text: ["Its last grant is staged for removal"], removed: true, intents: [] } });
  return { ...after, nodes, edges };
}

/** The number of pending lines, not counting default-deny lines that only change with the gateway's mode (a staged
 *  enforce shows once, on the gateway). */
export const pendingCount = (g: PolicyGraph) => g.edges.filter((e) => e.pending && e.verdict !== "path" && !(e.implicit && e.pending === "change")).length;
