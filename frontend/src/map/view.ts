// What the map shows of a PolicyGraph: the toolbar filters (direction is the graph's), the selected-agent view, the
// legend's verdict filter and the "no grants" groups (docs/VISUALIZATION_PLAN.md §5). Pure, shared by the canvas and
// the table view.
//
// Google API endpoints (*.googleapis.com, often a platform allowlist registered as host, host.mtls and host:443) are
// collapsed into one "Google APIs (N)" node unless "Show Google API endpoints" is on. That checkbox is the group's
// only state: clicking the group (or a search or "Show on map" match inside it) ticks it, unticking it collapses the
// group again. Lines into the collapsed group are merged per source (and per kind: granted or default deny), with
// the best verdict and a count; the table still lists every endpoint.
import { DEST_SECTIONS, NOGW, PSEUDO, SECTION_LABEL, bestVerdict, combineParts, type Chip, type Direction, type PEdge, type PNode, type PolicyGraph, type Verdict } from "./graph";

/** The map opens on Agent-to-Anywhere. */
export const DEFAULT_DIRECTION: Direction = "egress";
export type Affiliation = "all" | "gateway" | "none";
export type DestType = "a2a" | "runtime" | "mcp" | "api";
export interface MapFilters {
  affiliation: Affiliation;
  /** "all" or one gateway's full name. */
  gateway: string;
  types: Record<DestType, boolean>;
  /** Group destinations with no lines into one "+N … with no grants" node per section. */
  hideEmpty: boolean;
  /** Sections whose grouped destinations are shown anyway. */
  expanded: string[];
  /** Show Google API endpoints one by one; off = one collapsed "Google APIs (N)" node. */
  googleApis: boolean;
  /** Verdicts hidden from the legend. */
  hidden: Verdict[];
  /** Selected agent: add group / public / registry-wide grants, and default-deny lines. */
  inherited: boolean;
  implicit: boolean;
}
export const DEFAULT_FILTERS: MapFilters = {
  affiliation: "all",
  gateway: "all",
  types: { a2a: true, runtime: true, mcp: true, api: true },
  hideEmpty: true,
  expanded: [],
  googleApis: false,
  hidden: [],
  inherited: true,
  implicit: true,
};
/** Default-deny lines drawn for the selected agent, at most (then "+N more"). */
export const IMPLICIT_CAP = 60;
/** Combined lines past this suggest narrowing the filters (§7). */
export const TOO_MANY_LINES = 400;

export interface MapView {
  nodes: PNode[];
  edges: PEdge[];
  /** Implicit lines left out by the cap. */
  more: number;
  /** The caller whose own lines are shown (selected-agent view), if any. */
  focus: string | null;
  /** Lines other than trunks (for the "too many lines" banner). */
  lines: number;
}

/** The collapsed Google APIs node. */
export const GOOGLE_GROUP = "group:google-apis";

const SECTION_TYPE: Record<string, DestType | null> = { registry: null, a2a: "a2a", runtime: "runtime", mcp: "mcp", api: "api" };
const sectionOrder = (s: string) => {
  const i = (DEST_SECTIONS as readonly string[]).indexOf(s);
  return i < 0 ? DEST_SECTIONS.length : i;
};

/** Is this caller (an engine, or a pseudo caller) shown under the affiliation and gateway filters? */
function callerShown(n: PNode, f: MapFilters): boolean {
  if (n.kind === "client") return true;
  if (n.kind === "principal_group") return f.affiliation !== "none";
  if (f.affiliation === "none") return !n.gateway;
  if (f.affiliation === "gateway" && !n.gateway) return false;
  if (f.gateway !== "all") return n.gateway === f.gateway;
  return true;
}

/** "Changes only": just the lines the cart changes (and the trunks that lead to them), and their nodes. */
export function viewOf(g: PolicyGraph, f: MapFilters, selected: string | null, opts: { changesOnly?: boolean } = {}): MapView {
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const sel = selected ? byId.get(selected) : undefined;
  const callerCol = g.direction === "egress" ? "callers" : "dests";
  const isCaller = (n: PNode) => n.kind === "engine" || n.kind === "principal_group" || n.kind === "client";

  // ---------- nodes ----------
  const shown = new Set<string>();
  for (const n of g.nodes) {
    if (isCaller(n) && (n.column === callerCol || n.kind === "client")) {
      if (callerShown(n, f) || n.id === selected) shown.add(n.id);
    } else if (n.kind === "gateway") {
      if (f.affiliation !== "none" && (f.gateway === "all" || n.id === f.gateway)) shown.add(n.id);
    } else if (n.column === "dests") {
      const t = SECTION_TYPE[n.section];
      if (t === null || t === undefined || f.types[t] || n.id === selected) shown.add(n.id);
    }
  }
  // Google API endpoints collapsed into one node (a selected one stays on its own, like the "no grants" groups).
  const gIds = new Set(
    g.direction === "egress" && !f.googleApis ? g.nodes.filter((n) => n.kind === "endpoint" && n.googleApi && shown.has(n.id) && n.id !== selected).map((n) => n.id) : [],
  );
  const gNode: PNode | null = gIds.size ? googleGroupNode(g.nodes.filter((n) => gIds.has(n.id))) : null;
  const unboundShown = g.nodes.some((n) => n.kind === "engine" && !n.gateway && shown.has(n.id));
  if (unboundShown) {
    shown.add(g.direction === "egress" ? NOGW.egress : NOGW.ingress);
    if (g.direction === "egress") shown.add(PSEUDO.anywhere);
  }

  // ---------- lines ----------
  const focus = g.direction === "egress" && sel && (sel.kind === "engine" || sel.kind === "principal_group") ? sel.id : null;
  let src: PEdge[];
  if (focus && sel?.kind === "engine" && g.focusLines) src = g.focusLines.filter((e) => f.implicit || !e.implicit);
  else if (focus) src = g.edges.filter((e) => e.caller === focus);
  else src = g.edges;

  const edges: PEdge[] = [];
  for (const e of src) {
    let x: PEdge | null = e;
    if (e.parts) {
      const parts = e.parts.filter((p) => shown.has(p.caller ?? ""));
      // the combined line's own pending mark is kept when it's recombined from the visible agents
      x = !parts.length ? null : parts.length === e.parts.length ? e : { ...combineParts(e.id, parts), pending: e.pending, before: e.before, beforeLabel: e.beforeLabel, after: e.after, intents: e.intents };
    }
    if (!x || !shown.has(x.source) || !shown.has(x.target)) continue;
    if (x.verdict !== "path" && f.hidden.includes(x.verdict)) continue;
    edges.push(x);
  }

  if (opts.changesOnly) {
    const callers = new Set(edges.filter((e) => e.pending).flatMap((e) => (e.parts ?? [e]).map((p) => p.caller ?? p.source)));
    const gws = new Set(edges.filter((e) => e.pending).map((e) => e.source));
    for (let i = edges.length - 1; i >= 0; i--) {
      const e = edges[i];
      const lane = e.verdict === "path" && callers.has(e.source) && gws.has(e.target);
      if (!e.pending && !lane) edges.splice(i, 1);
    }
  }

  // Lines into collapsed Google API endpoints: one per source (and kind) into the group.
  if (gNode) edges.splice(0, edges.length, ...mergeIntoGroup(edges, gIds, gNode.id));

  // Default-deny lines on the selected agent: capped, in destination order.
  let more = 0;
  const implicit = edges.filter((e) => e.implicit);
  if (implicit.length > IMPLICIT_CAP) {
    const order = (e: PEdge) => {
      const n = byId.get(e.target) ?? gNode!;
      return `${String(sectionOrder(n.section)).padStart(2, "0")}|${n.label}|${n.id}`;
    };
    const keep = new Set(implicit.sort((a, b) => order(a).localeCompare(order(b))).slice(0, IMPLICIT_CAP).map((e) => e.id));
    more = implicit.length - keep.size;
    for (let i = edges.length - 1; i >= 0; i--) if (edges[i].implicit && !keep.has(edges[i].id)) edges.splice(i, 1);
  }

  // ---------- destinations with no lines: grouped per section ----------
  const into = new Set(edges.map((e) => e.target));
  const nodes: PNode[] = [];
  const groups = new Map<string, PNode[]>();
  for (const n of g.nodes) {
    if (!shown.has(n.id) || gIds.has(n.id)) continue;
    const empty = g.direction === "egress" && n.column === "dests" && !into.has(n.id) && !n.unreadable && n.id !== selected;
    if (empty && n.kind === "registry") continue; // no registry-wide grants: nothing to show
    if (empty && opts.changesOnly) continue;
    if (empty && f.hideEmpty && !f.expanded.includes(n.section)) {
      groups.set(n.section, [...(groups.get(n.section) ?? []), n]);
      continue;
    }
    nodes.push(n);
  }
  if (gNode && (!opts.changesOnly || into.has(gNode.id))) {
    // how many of its endpoints have a granted line in this view
    const reached = new Set(edges.filter((e) => e.target === gNode.id && !e.implicit).flatMap((e) => (e.members ?? []).map((m) => m.target))).size;
    nodes.push({ ...gNode, sub: `${reached ? `${reached} with grants · ` : "No grants · "}click to show them` });
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
  // Pseudo callers and gateway lanes with nothing to draw are left out (they'd only add noise).
  const touched = new Set(edges.flatMap((e) => [e.source, e.target]));
  const out = opts.changesOnly
    ? nodes.filter((n) => touched.has(n.id) || n.pending || n.id === selected)
    : nodes.filter((n) => n.kind !== "principal_group" || touched.has(n.id) || n.id === selected);
  return { nodes: out, edges, more, focus, lines: edges.filter((e) => e.verdict !== "path").length };
}

/** The visible lines as table rows: a combined line gives one row per agent, a line into the Google APIs group one
 *  row per endpoint (and agent). */
export function tableRows(v: MapView): PEdge[] {
  // No gateway → Anywhere is each unbound agent's own "direct" row already.
  return v.edges
    .filter((e) => e.verdict !== "path" && e.id !== "direct:nogw")
    .flatMap((e) => e.members ?? [e])
    .flatMap((e) => e.parts ?? [e]);
}

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

/** Lines into the grouped endpoints, merged into one line per (source, granted or default deny) into the group: the
 *  best verdict, the endpoint count (and agent count), the merged lines kept as `members`. */
export function mergeIntoGroup(edges: PEdge[], ids: Set<string>, groupId: string): PEdge[] {
  const out: PEdge[] = [];
  const by = new Map<string, PEdge[]>();
  for (const e of edges) {
    if (!ids.has(e.target)) out.push(e);
    else {
      const k = `${e.source}|${e.implicit ? "x" : "a"}`;
      by.set(k, [...(by.get(k) ?? []), e]);
    }
  }
  for (const [k, ms] of by) {
    const first = ms[0];
    const targets = new Set(ms.map((m) => m.target)).size;
    const callers = new Set(ms.flatMap((m) => (m.parts ?? [m]).map((p) => p.caller ?? p.source)));
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
      label: `${targets} ${targets === 1 ? "API" : "APIs"}${callers.size > 1 && !first.source.startsWith("pseudo:") ? ` · ${callers.size} agents` : ""}`,
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
export function expandGroup(n: Pick<PNode, "kind" | "section">, f: MapFilters): Partial<MapFilters> {
  return n.kind === "google_apis" ? { googleApis: true } : { expanded: [...new Set([...f.expanded, n.section])] };
}

/** The filter change that puts node `id` on the map as itself (expanding the Google APIs group and then, if it has
 *  no grants, its "no grants" group); {} when it's already there, null when other filters hide it. */
export function revealPatch(g: PolicyGraph, f: MapFilters, selected: string | null, id: string, opts: { changesOnly?: boolean } = {}): Partial<MapFilters> | null {
  let patch: Partial<MapFilters> = {};
  for (let i = 0; i < 3; i++) {
    const cur = { ...f, ...patch };
    const v = viewOf(g, cur, selected, opts);
    if (v.nodes.some((n) => n.id === id)) return patch;
    const grp = v.nodes.find((n) => n.grouped?.includes(id));
    if (!grp) return null;
    patch = { ...patch, ...expandGroup(grp, cur) };
  }
  return null;
}
