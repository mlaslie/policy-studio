// What the map shows of a PolicyGraph: the toolbar filters (direction is the graph's), the selected-agent view, the
// legend's verdict filter and the "no grants" groups (docs/VISUALIZATION_PLAN.md §5). Pure, shared by the canvas and
// the table view.
import { DEST_SECTIONS, NOGW, PSEUDO, SECTION_LABEL, combineParts, type Direction, type PEdge, type PNode, type PolicyGraph, type Verdict } from "./graph";

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

  // Default-deny lines on the selected agent: capped, in destination order.
  let more = 0;
  const implicit = edges.filter((e) => e.implicit);
  if (implicit.length > IMPLICIT_CAP) {
    const order = (e: PEdge) => {
      const n = byId.get(e.target)!;
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
    if (!shown.has(n.id)) continue;
    const empty = g.direction === "egress" && n.column === "dests" && !into.has(n.id) && !n.unreadable && n.id !== selected;
    if (empty && n.kind === "registry") continue; // no registry-wide grants: nothing to show
    if (empty && opts.changesOnly) continue;
    if (empty && f.hideEmpty && !f.expanded.includes(n.section)) {
      groups.set(n.section, [...(groups.get(n.section) ?? []), n]);
      continue;
    }
    nodes.push(n);
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

/** The visible lines as table rows: a combined line gives one row per agent. */
export function tableRows(v: MapView): PEdge[] {
  // No gateway → Anywhere is each unbound agent's own "direct" row already.
  return v.edges.filter((e) => e.verdict !== "path" && e.id !== "direct:nogw").flatMap((e) => e.parts ?? [e]);
}
