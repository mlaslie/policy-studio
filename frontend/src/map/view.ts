// What the map shows of a PolicyGraph (docs/VISUALIZATION_PLAN.md §5): the objects the picker leaves checked
// (picker.ts), the selected agents' lines, the Allows / Denies choice, the legend's verdict filter and the "no grants"
// groups. Pure, shared by the canvas and the table view.
//
// Lines are drawn only for the selected callers (agents, or pseudo callers), each agent's own, never combined: with no
// selection the map is nodes only. A destination (or gateway) the picker hides is still drawn, faded, while a selected
// agent has a line to it. The layout reads every shown caller's own grants instead of the drawn lines, so selecting an
// agent doesn't move the nodes.
//
// Google API endpoints (*.googleapis.com, often a platform allowlist registered as host, host.mtls and host:443) are
// collapsed into one "Google APIs (N)" node unless "Show Google API endpoints" is on. That checkbox is the group's
// only state: clicking the group (or a picker or "Show on map" match inside it) ticks it, unticking it collapses the
// group again. Lines into the collapsed group are merged per agent (and per kind: granted or default deny), with the
// best verdict and a count; the table still lists every endpoint.
import { DEST_SECTIONS, NOGW, PSEUDO, SECTION_LABEL, bestVerdict, type Chip, type Direction, type PEdge, type PNode, type PolicyGraph, type Verdict } from "./graph";

/** The map opens on Agent-to-Anywhere. */
export const DEFAULT_DIRECTION: Direction = "egress";
export type Affiliation = "all" | "gateway" | "none";
export interface MapFilters {
  /** "all" or one gateway's full name. */
  gateway: string;
  /** Group destinations with no grants into one "+N … with no grants" node per section. */
  hideEmpty: boolean;
  /** Sections whose grouped destinations are shown anyway. */
  expanded: string[];
  /** Show Google API endpoints one by one; off = one collapsed "Google APIs (N)" node. */
  googleApis: boolean;
  /** Verdicts hidden from the legend. */
  hidden: Verdict[];
  /** Add group / public / registry-wide grants to each agent's lines. */
  inherited: boolean;
  /** Show: Allows (allowed, partial, conditional, inherited and not-enforced grants) and Denies (default-deny lines). */
  allows: boolean;
  denies: boolean;
  /** Objects unchecked in the picker: hidden. */
  off: string[];
}
export const DEFAULT_FILTERS: MapFilters = {
  gateway: "all",
  hideEmpty: true,
  expanded: [],
  googleApis: false,
  hidden: [],
  inherited: true,
  allows: true,
  denies: true,
  off: [],
};
/** Default-deny lines drawn per agent, at most (then "+N more"). */
export const DENY_CAP = 60;
/** Lines past this suggest selecting fewer agents (§7). */
export const TOO_MANY_LINES = 400;

export interface MapView {
  nodes: PNode[];
  /** The lines drawn: the selected callers' own. */
  edges: PEdge[];
  /** Every shown caller's lanes and own (not inherited, not default-deny) lines: what the layout orders by. */
  layoutEdges: PEdge[];
  /** The table's rows: the drawn lines one per endpoint, or every shown caller's own lines with nothing selected. */
  rows: PEdge[];
  /** Default-deny lines left out by the cap. */
  more: number;
  /** The callers whose lines are drawn, in selection order. */
  agents: string[];
  /** Nodes the picker hides, drawn faded because a selected caller has a line to them. */
  faded: string[];
  /** Drawn lines other than lanes (for the "too many lines" banner). */
  lines: number;
}

/** The collapsed Google APIs node. */
export const GOOGLE_GROUP = "group:google-apis";

const sectionOrder = (s: string) => {
  const i = (DEST_SECTIONS as readonly string[]).indexOf(s);
  return i < 0 ? DEST_SECTIONS.length : i;
};

/** A caller whose lines can be selected: an Agent Runtime agent (either direction) or an egress pseudo caller. */
export function isSource(n: Pick<PNode, "kind" | "column">, direction: Direction): boolean {
  return direction === "egress" ? (n.kind === "engine" && n.column === "callers") || n.kind === "principal_group" : n.kind === "engine";
}

/** Lanes: an agent's trunk to its gateway, or its direct line (never filtered by Allows / Denies). */
const isLane = (e: PEdge) => e.verdict === "path" || e.verdict === "direct";

/** Whether a line passes the Allows / Denies choice and the legend. */
export function keepLine(e: PEdge, f: Pick<MapFilters, "allows" | "denies" | "hidden">): boolean {
  if (e.verdict === "path") return true;
  if (e.direction === "egress" && !isLane(e) && (e.implicit ? !f.denies : !f.allows)) return false;
  return !f.hidden.includes(e.verdict);
}

/** The view. `agents`: the selected callers (only the shown ones count). `active`: the node in the details panel (it
 *  stays on its own, outside any group). "Changes only": just the lines the cart changes (and their lanes), and their
 *  nodes; with nothing selected, the callers whose lines change. */
export function viewOf(g: PolicyGraph, f: MapFilters, agents: string[], opts: { changesOnly?: boolean; active?: string | null } = {}): MapView {
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const active = opts.active ?? null;
  const off = new Set(f.off);
  const callerCol = g.direction === "egress" ? "callers" : "dests";
  const isCaller = (n: PNode) => n.kind === "engine" || n.kind === "principal_group" || n.kind === "client";

  // ---------- nodes the picker and the gateway filter leave on ----------
  const shown = new Set<string>();
  for (const n of g.nodes) {
    if (off.has(n.id) && n.id !== active) continue;
    if (isCaller(n) && (n.column === callerCol || n.kind === "client")) {
      if (n.kind !== "engine" || f.gateway === "all" || n.gateway === f.gateway) shown.add(n.id);
    } else if (n.kind === "gateway") {
      if (f.gateway === "all" || n.id === f.gateway) shown.add(n.id);
    } else if (n.column === "dests") shown.add(n.id);
  }
  const lanes = () => {
    if (!g.nodes.some((n) => n.kind === "engine" && !n.gateway && shown.has(n.id))) return;
    shown.add(g.direction === "egress" ? NOGW.egress : NOGW.ingress);
    if (g.direction === "egress") shown.add(PSEUDO.anywhere);
  };
  lanes();
  const callerShown = (id: string | undefined) => !!id && shown.has(id) && !!byId.get(id) && isSource(byId.get(id)!, g.direction);
  // every shown caller's lanes and own lines (pseudo callers' included), before anything is forced on
  const base = g.edges.filter((e) => callerShown(e.caller) && !e.implicit && !e.inherited && shown.has(e.source) && shown.has(e.target));
  const granted = new Set(base.filter((e) => !isLane(e)).map((e) => e.target));

  // ---------- the selected callers' lines ----------
  let sel = agents.filter((id, i) => agents.indexOf(id) === i && callerShown(id));
  if (opts.changesOnly && !sel.length) sel = [...new Set(g.edges.filter((e) => e.pending && !isLane(e) && callerShown(e.caller)).map((e) => e.caller!))];
  const selSet = new Set(sel);
  let edges = g.edges.filter((e) => !!e.caller && selSet.has(e.caller) && keepLine(e, f));
  if (opts.changesOnly) {
    const callers = new Set(edges.filter((e) => e.pending).map((e) => e.caller));
    edges = edges.filter((e) => e.pending || (isLane(e) && callers.has(e.caller)));
  }
  // a hidden node a drawn line needs: drawn anyway, faded
  const faded = new Set<string>();
  for (const e of edges)
    for (const id of [e.source, e.target])
      if (!shown.has(id) && byId.has(id)) {
        shown.add(id);
        faded.add(id);
      }
  lanes();

  // Google API endpoints collapsed into one node (the one in the panel stays on its own, like the "no grants" groups).
  const gIds = new Set(
    g.direction === "egress" && !f.googleApis ? g.nodes.filter((n) => n.kind === "endpoint" && n.googleApi && shown.has(n.id) && n.id !== active).map((n) => n.id) : [],
  );
  const gNode: PNode | null = gIds.size ? googleGroupNode(g.nodes.filter((n) => gIds.has(n.id))) : null;
  const rawEdges = edges;
  if (gNode) edges = mergeIntoGroup(edges, gIds, gNode.id);
  const layoutEdges = opts.changesOnly ? edges : gNode ? mergeIntoGroup(base, gIds, gNode.id) : base;

  // Default-deny lines: at most DENY_CAP per agent, in destination order.
  let more = 0;
  const order = (e: PEdge) => {
    const n = byId.get(e.target) ?? gNode!;
    return `${String(sectionOrder(n.section)).padStart(2, "0")}|${n.label}|${n.id}`;
  };
  const drop = new Set<string>();
  for (const c of sel) {
    const denies = edges.filter((e) => e.implicit && e.caller === c);
    if (denies.length <= DENY_CAP) continue;
    denies.sort((a, b) => order(a).localeCompare(order(b)));
    for (const e of denies.slice(DENY_CAP)) drop.add(e.id);
    more += denies.length - DENY_CAP;
  }
  if (drop.size) edges = edges.filter((e) => !drop.has(e.id));

  // ---------- destinations with no grants: grouped per section ----------
  const into = new Set(edges.map((e) => e.target));
  const nodes: PNode[] = [];
  const groups = new Map<string, PNode[]>();
  for (const n of g.nodes) {
    if (!shown.has(n.id) || gIds.has(n.id)) continue;
    const empty = g.direction === "egress" && n.column === "dests" && !granted.has(n.id) && !into.has(n.id) && !n.unreadable && n.id !== active;
    if (empty && n.kind === "registry") continue; // no registry-wide grants: nothing to show
    if (empty && opts.changesOnly) continue;
    if (empty && f.hideEmpty && !f.expanded.includes(n.section)) {
      groups.set(n.section, [...(groups.get(n.section) ?? []), n]);
      continue;
    }
    nodes.push(n);
  }
  if (gNode && (!opts.changesOnly || into.has(gNode.id))) {
    // how many of its endpoints some shown caller holds a grant on
    const reached = [...gIds].filter((id) => granted.has(id)).length;
    nodes.push({ ...gNode, sub: `${reached ? `${reached} with grants · ` : "No grants · "}click to show them` });
    if ([...gIds].every((id) => faded.has(id))) faded.add(gNode.id);
  }
  for (const [section, ns] of groups) {
    const what = SECTION_LABEL[section] ?? section;
    nodes.push({
      id: `group:${section}`,
      kind: "endpoint_group",
      label: `+${ns.length} ${ns.length === 1 ? what.replace(/s$/, "") : what} with no grants`,
      sub: "Click to show them",
      column: "dests",
      section,
      chips: [],
      grouped: ns.map((n) => n.id),
      search: ns.map((n) => n.search).join(" "),
    });
  }
  // Pseudo callers with no grants at all are left out (they'd only add noise).
  const touched = new Set([...edges, ...layoutEdges].flatMap((e) => [e.source, e.target]));
  const out = opts.changesOnly
    ? nodes.filter((n) => touched.has(n.id) || n.pending || n.id === active)
    : nodes.filter((n) => n.kind !== "principal_group" || touched.has(n.id) || selSet.has(n.id) || n.id === active);

  // ---------- table rows: Client-to-Agent rows are the client lines (client, the agent's gateway, the agent) ----------
  const rows = (sel.length ? rawEdges.filter((e) => !drop.has(e.id)) : g.edges.filter((e) => callerShown(e.caller) && !e.implicit && !e.inherited && shown.has(e.target) && keepLine(e, f))).filter(
    (e) => e.verdict !== "path" && !e.id.startsWith("out:") && (e.direction === "egress" || e.source.startsWith("client:")),
  );
  const outIds = new Set(out.map((n) => n.id));
  return { nodes: out, edges, layoutEdges, rows, more, agents: sel, faded: [...faded].filter((id) => outIds.has(id)), lines: edges.filter((e) => e.verdict !== "path").length };
}

/** The table's rows (one per agent and endpoint). */
export const tableRows = (v: MapView): PEdge[] => v.rows;

/** The collapsed "Google APIs (N)" node for these endpoints. */
function googleGroupNode(ns: PNode[]): PNode {
  const unreadable = ns.filter((n) => n.unreadable).length;
  const chips: Chip[] = unreadable ? [{ text: unreadable > 1 ? `${unreadable} IAP policies couldn't be read` : "1 IAP policy couldn't be read", tone: "red" }] : [];
  const pending = ns.filter((n) => n.pending);
  return {
    id: GOOGLE_GROUP,
    kind: "google_apis",
    label: `Google APIs (${ns.length})`,
    sub: "Click to show them",
    column: "dests",
    section: "api",
    chips,
    destKind: "endpoint",
    googleApi: true,
    grouped: ns.map((n) => n.id),
    search: `google apis ${ns.map((n) => n.search).join(" ")}`,
    pending: pending.length ? { text: pending.flatMap((n) => n.pending!.text.map((t) => `${n.label}: ${t}`)), intents: [...new Set(pending.flatMap((n) => n.pending!.intents))] } : undefined,
  };
}

/** Lines into the grouped endpoints, merged into one line per (caller, source, granted or default deny) into the
 *  group: the best verdict, the endpoint count, the merged lines kept as `members`. */
export function mergeIntoGroup(edges: PEdge[], ids: Set<string>, groupId: string): PEdge[] {
  const out: PEdge[] = [];
  const by = new Map<string, PEdge[]>();
  for (const e of edges) {
    if (!ids.has(e.target)) out.push(e);
    else {
      const k = `${e.caller ?? ""}|${e.source}|${e.implicit ? "x" : "a"}`;
      by.set(k, [...(by.get(k) ?? []), e]);
    }
  }
  for (const [k, ms] of by) {
    const first = ms[0];
    const targets = new Set(ms.map((m) => m.target)).size;
    const same = <T>(f: (e: PEdge) => T) => (ms.every((m) => f(m) === f(first)) ? f(first) : undefined);
    const pendings = ms.filter((m) => m.pending);
    const intents = [...new Set(ms.flatMap((m) => m.intents ?? []))];
    out.push({
      id: `g:${k}|${groupId}`,
      source: first.source,
      target: groupId,
      direction: first.direction,
      verdict: bestVerdict(ms.map((m) => m.verdict)),
      reasons: ms.flatMap((m) => m.reasons),
      gateway: same((m) => m.gateway),
      mode: same((m) => m.mode),
      modelArmor: same((m) => m.modelArmor),
      modelArmorDryRun: same((m) => m.modelArmorDryRun),
      implicit: first.implicit,
      inherited: ms.every((m) => m.inherited) || undefined,
      caller: same((m) => m.caller),
      members: ms,
      label: `${targets} ${targets === 1 ? "API" : "APIs"}`,
      pending: pendings.length ? (pendings.length === ms.length && pendings.every((m) => m.pending === pendings[0].pending) ? pendings[0].pending : "change") : undefined,
      intents: intents.length ? intents : undefined,
      before: same((m) => m.before),
      after: same((m) => m.after),
    });
  }
  return out;
}

/** What expanding a group node changes: the Google APIs group ticks "Show Google API endpoints", a "no grants" group
 *  shows its section. */
export function expandGroup(n: Pick<PNode, "kind" | "section">, f: Pick<MapFilters, "expanded">): Partial<MapFilters> {
  return n.kind === "google_apis" ? { googleApis: true } : { expanded: [...new Set([...f.expanded, n.section])] };
}

/** The filter change that puts node `id` on the map as itself: checked in the picker, then out of the Google APIs
 *  group and, if it has no grants, its "no grants" group; {} when it's already there, null when the gateway filter
 *  hides it. */
export function revealPatch(g: PolicyGraph, f: MapFilters, agents: string[], id: string, opts: { changesOnly?: boolean; active?: string | null } = {}): Partial<MapFilters> | null {
  let patch: Partial<MapFilters> = f.off.includes(id) ? { off: f.off.filter((x) => x !== id) } : {};
  for (let i = 0; i < 3; i++) {
    const cur = { ...f, ...patch };
    const v = viewOf(g, cur, agents, opts);
    if (v.nodes.some((n) => n.id === id)) return patch;
    const grp = v.nodes.find((n) => n.grouped?.includes(id));
    if (!grp) return null;
    patch = { ...patch, ...expandGroup(grp, cur) };
  }
  return null;
}
