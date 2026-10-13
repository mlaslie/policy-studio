// Auto layout for the policy map (docs/VISUALIZATION_PLAN.md §7): fixed columns by type, left to right (callers →
// gateways → destinations → Anywhere), like the demo's build.ts. Within a column: group by section, order with two
// barycenter passes (destinations by the average y of the callers that reach them, then callers by the average y of
// their destinations; ties by label, then id), and wrap a section of more than 25 nodes into sub-columns (callers
// sooner, once there are more than 25 of them).
// Deterministic: the same view gives the same positions.
import { DEST_SECTIONS, NOGW, SECTION_LABEL, type Chip, type PEdge, type PNode, type PNodeKind } from "./graph";
import { FIT, fitText, fontOf, measureText, type FitStyle, type Measure } from "./fit";
import { chipLabel } from "./labels";
import type { XY } from "./usePositions";
import type { MapView } from "./view";

export const GAP_X = 140;
export const GAP_Y = 22;
const SECTION_GAP = 34;
/** Room above a section for its title (also the title's box when resolving overlaps). */
export const HEADER_H = 26;
const SUB_GAP = 46;
/** A section with more nodes than this wraps into sub-columns. */
export const WRAP = 25;
/** Callers wrap sooner once there are more than WRAP of them (engine nodes carry several chips, so they're tall): at
 *  the §7 scale (about 50 agents) the column then stays about as tall as the destinations'. */
export const CALLER_WRAP = 10;

export const W: Record<PNodeKind, number> = {
  engine: 250,
  principal_group: 240,
  client: 250,
  gateway: 240,
  no_gateway: 240,
  anywhere: 190,
  a2a: 270,
  runtime_dest: 270,
  mcp: 290,
  endpoint: 330,
  endpoint_group: 260,
  google_apis: 330,
  registry: 260,
};

// ---------- card geometry: the room text gets inside a card (nodes.tsx fits titles and chips into it) ----------
const BORDER: Partial<Record<PNodeKind, number>> = { engine: 2, gateway: 2, no_gateway: 2, registry: 1.5 };
/** Width inside a card's padding (14px a side) and border: what its title row and chips fit into. */
export const innerW = (k: PNodeKind) => W[k] - 28 - 2 * (BORDER[k] ?? 1);
/** Room for the title and subtitle: the inner width less the icon tile (36px and a 10px gap) and, when the card shows
 *  the selected agent's verdict, its dot (10px and a 10px gap). */
export const titleRoom = (k: PNodeKind, dot = false) => innerW(k) - 46 - (dot ? 20 : 0);
/** A chip's padding (9px a side), the clock on a staged one (11px and a 4px gap), the gap between chips, and a row of
 *  chips (11.5px text at line-height 1.4, 2px padding a side) — styles.css .chip. */
const CHIP_PAD = 18;
const CLOCK = 15;
export const CHIP_GAP = 6;
export const CHIP_H = 20;
/** A chip as the card draws it: the short label (labels.ts chipLabel), shortened further if it still doesn't fit. */
export const chipShown = (c: Pick<Chip, "text" | "pending">, k: PNodeKind, measure: Measure = measureText) => fitText(chipLabel(c.text), innerW(k) - CHIP_PAD - (c.pending ? CLOCK : 0), FIT.chip, "end", measure);
const chipW = (c: Chip, k: PNodeKind, measure: Measure) => measure(chipShown(c, k, measure).text, fontOf(FIT.chip)) + CHIP_PAD + (c.pending ? CLOCK : 0);
/** A skill pill: the "SKILL" tag (9.5px bold caps, 4px padding a side, 0.4px letter spacing), a 5px gap, the name, and
 *  the pill's padding (3px and 7px) and border. */
const SKILL_FONT: FitStyle = { size: 9.5, min: 9.5, weight: 700 };
const skillTagW = (measure: Measure) => measure("SKILL", fontOf(SKILL_FONT)) + 8 + 2;
export const skillRoom = (k: PNodeKind, measure: Measure = measureText) => innerW(k) - skillTagW(measure) - 5 - 12;
const skillW = (s: string, k: PNodeKind, measure: Measure) => skillTagW(measure) + 5 + 12 + measure(fitText(s, skillRoom(k, measure), FIT.skill, "end", measure).text, fontOf(FIT.skill));

/** Rows that pills of these widths wrap into inside `width` px (flex-wrap, `gap` between them; a pill wider than the
 *  row is cut to it). */
export function wrapRows(widths: number[], width: number, gap = CHIP_GAP): number {
  let rows = 0;
  let used = width;
  for (const raw of widths) {
    const w = Math.min(width, raw);
    if (used + gap + w > width) {
      rows++;
      used = w;
    } else used += gap + w;
  }
  return rows;
}

/** A selected caller's "N lines to hidden objects" note (styles.css .node-hidden-note: 16px line, 8px above). */
export const NOTE_H = 24;

/** Estimated node height (the canvas measures the real one and lays out again). `expanded`: MCP tool rows shown (the
 *  ones Show leaves, `shownTools`, when it leaves out some).
 *  Chip rows come from the chips' measured widths, so the estimate is close before React Flow has measured the card
 *  (cards off screen aren't rendered, so aren't measured). */
export function nodeHeight(n: PNode, expanded = false, measure: Measure = measureText): number {
  const k = n.kind;
  const rows = (c: Chip[]) => wrapRows(c.map((x) => chipW(x, k, measure)), innerW(k));
  const chips = (c: Chip[]) => (c.length ? 10 + rows(c) * (CHIP_H + CHIP_GAP) - CHIP_GAP : 0);
  const note = n.hiddenLines ? NOTE_H : 0;
  switch (k) {
    case "mcp":
      return expanded ? 70 + (n.shownTools?.length ?? n.tools?.length ?? 0) * 31 + 6 + chips(n.chips) : 94 + chips(n.chips);
    case "a2a":
    case "runtime_dest": {
      const sk = n.skills ?? [];
      const pills = [...sk.slice(0, 3).map((s) => skillW(s, k, measure)), ...(sk.length > 3 ? [measure(`+${sk.length - 3}`, fontOf(FIT.skill)) + 12] : [])];
      return 66 + (sk.length ? 8 + wrapRows(pills, innerW(k), 4) * 26 - 4 : 0) + chips(n.chips);
    }
    case "engine":
      return 68 + chips(n.chips) + note;
    case "endpoint":
    case "google_apis":
      return 66 + chips(n.chips);
    case "endpoint_group":
      return 58;
    case "registry":
      return 67 + chips(n.chips);
    case "anywhere":
      return 62;
    case "client":
    case "principal_group": {
      // the description wraps (17px lines) instead of being shortened
      const lines = Math.max(1, Math.ceil(measure(n.sub ?? "", fontOf(FIT.sub)) / titleRoom(k)));
      return 64 + (lines - 1) * 17 + chips(n.chips) + note;
    }
    default:
      return 64 + chips(n.chips);
  }
}

export interface Layout {
  pos: Record<string, { x: number; y: number }>;
  size: Record<string, { w: number; h: number }>;
  /** Section titles drawn above each group of nodes. */
  headers: { id: string; label: string; x: number; y: number; w: number }[];
  /** The column of each node and section title (callers, gateways, dests, sink), for resolveOverlaps. */
  column: Record<string, string>;
}

type Col = "callers" | "gateways" | "dests" | "sink";
const colOf = (n: PNode): Col => n.column;

/** Caller sections: one per gateway (in gateway order), then "No gateway", then the pseudo callers. */
function sectionKey(n: PNode, gwOrder: Map<string, number>): string {
  if (n.column === "dests" && n.kind !== "engine") return String((DEST_SECTIONS as readonly string[]).indexOf(n.section)).padStart(2, "0");
  if (n.section.startsWith("gw:")) return `0${String(gwOrder.get(n.section.slice(3)) ?? 99).padStart(3, "0")}`;
  if (n.section === "nogw") return "1";
  return "2";
}
function sectionTitle(section: string, byId: Map<string, PNode>): string {
  if (section.startsWith("gw:")) return `Behind ${byId.get(section.slice(3))?.label ?? section.slice(3).split("/").pop()}`;
  return SECTION_LABEL[section] ?? section;
}

/** `layoutEdges` (every shown caller's own grants, MapView) when given, so the selection doesn't move nodes; else
 *  `edges`. */
export function layoutView(view: Pick<MapView, "nodes" | "edges"> & { layoutEdges?: PEdge[] }, opts: { expanded?: Set<string>; heights?: Record<string, number>; measure?: Measure } = {}): Layout {
  const { nodes } = view;
  const edges = view.layoutEdges ?? view.edges;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const est = new Map<string, number>();
  const h = (n: PNode) => {
    const m = opts.heights?.[n.id];
    if (m !== undefined) return m;
    let e = est.get(n.id);
    if (e === undefined) est.set(n.id, (e = nodeHeight(n, opts.expanded?.has(n.id), opts.measure)));
    return e;
  };
  const gws = nodes.filter((n) => n.column === "gateways").sort((a, b) => Number(a.kind === "no_gateway") - Number(b.kind === "no_gateway") || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  const gwOrder = new Map(gws.map((g, i) => [g.id, i]));

  // Logical links (caller ↔ destination), through each line's caller (and the lines merged into the Google APIs
  // group), for the barycenter passes.
  const callerIds = new Set(nodes.filter((n) => colOf(n) === "callers").map((n) => n.id));
  const destIds = new Set(nodes.filter((n) => colOf(n) === "dests").map((n) => n.id));
  const links: [string, string][] = [];
  const gwCallers = new Map<string, string[]>();
  for (const e of edges) {
    if (callerIds.has(e.source) && gwOrder.has(e.target)) gwCallers.set(e.target, [...(gwCallers.get(e.target) ?? []), e.source]);
    for (const p of e.members ?? [e]) {
      const c = callerIds.has(p.source) ? p.source : p.caller && callerIds.has(p.caller) ? p.caller : null;
      if (c && destIds.has(e.target)) links.push([c, e.target]);
      // ingress: clients reach the agents through the gateway lanes
      if (!c && destIds.has(e.target) && gwOrder.has(e.source)) for (const cc of callerIds) links.push([cc, e.target]);
    }
  }
  const adj: [Map<string, string[]>, Map<string, string[]>] = [new Map(), new Map()];
  for (const l of links)
    for (const side of [0, 1] as const) adj[side].set(l[side], [...(adj[side].get(l[side]) ?? []), l[1 - side]]);
  const nbrs = (id: string, side: 0 | 1) => adj[side].get(id) ?? [];

  // Group a column's nodes by section, in section order.
  const sectionsOf = (col: Col) => {
    const m = new Map<string, PNode[]>();
    for (const n of nodes.filter((x) => colOf(x) === col)) m.set(n.section, [...(m.get(n.section) ?? []), n]);
    return [...m.entries()].sort((a, b) => sectionKey(a[1][0], gwOrder).localeCompare(sectionKey(b[1][0], gwOrder)) || a[0].localeCompare(b[0]));
  };
  const byLabel = (a: PNode, b: PNode) => Number(a.kind === "endpoint_group") - Number(b.kind === "endpoint_group") || a.label.localeCompare(b.label) || a.id.localeCompare(b.id);

  const y: Record<string, number> = {};
  const x: Record<string, number> = {};
  const headers: Layout["headers"] = [];
  const column: Layout["column"] = {};

  /** Stack sections top to bottom (sub-columns past WRAP), centered on 0. Writes y (center) and x offsets. */
  const stack = (secs: [string, PNode[]][], col: Col, colX: number, colW: number, withHeaders: boolean, wrap = WRAP) => {
    const out: { id: string; top: number; dx: number }[] = [];
    const hdr: { section: string; top: number; w: number }[] = [];
    let top = 0;
    for (const [section, ns] of secs) {
      if (withHeaders) {
        hdr.push({ section, top, w: colW + (Math.ceil(ns.length / wrap) - 1) * (colW + SUB_GAP) });
        top += HEADER_H;
      }
      let tallest = 0;
      for (let c = 0; c * wrap < ns.length; c++) {
        let t = top;
        for (const n of ns.slice(c * wrap, (c + 1) * wrap)) {
          out.push({ id: n.id, top: t, dx: c * (colW + SUB_GAP) });
          t += h(n) + GAP_Y;
        }
        tallest = Math.max(tallest, t - top - GAP_Y);
      }
      top += tallest + SECTION_GAP;
    }
    const shift = -(top - SECTION_GAP) / 2;
    for (const o of out) {
      y[o.id] = o.top + shift + h(byId.get(o.id)!) / 2;
      x[o.id] = colX + o.dx;
    }
    for (const s of hdr) {
      headers.push({ id: `hdr:${colX}:${s.section}`, label: sectionTitle(s.section, byId), x: colX, y: s.top + shift, w: s.w });
      column[`hdr:${colX}:${s.section}`] = col;
    }
  };
  const mean = (ids: string[], fallback: number) => {
    const v = ids.map((i) => y[i]).filter((n) => n !== undefined);
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : fallback;
  };
  const order = (secs: [string, PNode[]][], side: 0 | 1) =>
    secs.map(([s, ns]): [string, PNode[]] => {
      const key = new Map(ns.map((n) => [n.id, mean(nbrs(n.id, side), y[n.id] ?? Number.POSITIVE_INFINITY)]));
      return [s, [...ns].sort((a, b) => Number(a.kind === "endpoint_group") - Number(b.kind === "endpoint_group") || key.get(a.id)! - key.get(b.id)! || byLabel(a, b))];
    });

  // ---------- columns and widths ----------
  const colW = (col: Col) => Math.max(0, ...nodes.filter((n) => colOf(n) === col).map((n) => W[n.kind]));
  let callerSecs = sectionsOf("callers").map(([s, ns]): [string, PNode[]] => [s, [...ns].sort(byLabel)]);
  let destSecs = sectionsOf("dests").map(([s, ns]): [string, PNode[]] => [s, [...ns].sort(byLabel)]);
  const cw = colW("callers") || W.engine;
  const gw = colW("gateways") || W.gateway;
  const dw = colW("dests") || W.endpoint;
  const cwrap = callerIds.size > WRAP ? CALLER_WRAP : WRAP;
  const callerCols = Math.max(1, ...callerSecs.map(([, ns]) => Math.ceil(ns.length / cwrap)));
  const callersW = callerCols * cw + (callerCols - 1) * SUB_GAP;
  const X = { callers: 0, gateways: callersW + GAP_X, dests: callersW + GAP_X + gw + GAP_X };
  const subCols = Math.max(1, ...destSecs.map(([, ns]) => Math.ceil(ns.length / WRAP)));
  const sinkX = X.dests + subCols * dw + (subCols - 1) * SUB_GAP + GAP_X;
  const headed = (secs: [string, PNode[]][]) => secs.length > 1 || secs.some(([s]) => s !== "clients");

  // ---------- two barycenter passes ----------
  stack(callerSecs, "callers", X.callers, cw, false, cwrap);
  for (let pass = 0; pass < 2; pass++) {
    destSecs = order(destSecs, 1);
    stack(destSecs, "dests", X.dests, dw, false);
    callerSecs = order(callerSecs, 0);
    stack(callerSecs, "callers", X.callers, cw, false, cwrap);
  }
  headers.length = 0;
  stack(callerSecs, "callers", X.callers, cw, headed(callerSecs), cwrap);
  stack(destSecs, "dests", X.dests, dw, true);

  // ---------- gateways: centered on the agents behind them, then pushed apart ----------
  const gwTarget = (g: PNode) => {
    const own = gwCallers.get(g.id) ?? [];
    const lanes = own.length ? own : edges.filter((e) => e.source === g.id && destIds.has(e.target)).map((e) => e.target);
    return mean(lanes, Number.POSITIVE_INFINITY);
  };
  const placed = gws.map((g) => ({ g, t: gwTarget(g) })).sort((a, b) => a.t - b.t || (gwOrder.get(a.g.id) ?? 0) - (gwOrder.get(b.g.id) ?? 0));
  const unanchored = placed.filter((p) => !Number.isFinite(p.t));
  let bottom = Number.NEGATIVE_INFINITY;
  for (const p of placed.filter((q) => Number.isFinite(q.t))) {
    const top = Math.max(p.t - h(p.g) / 2, bottom + GAP_Y * 2);
    y[p.g.id] = top + h(p.g) / 2;
    x[p.g.id] = X.gateways;
    bottom = top + h(p.g);
  }
  if (!Number.isFinite(bottom)) bottom = -GAP_Y * 2;
  for (const p of unanchored) {
    const top = bottom + GAP_Y * 2;
    y[p.g.id] = top + h(p.g) / 2;
    x[p.g.id] = X.gateways;
    bottom = top + h(p.g);
  }

  // ---------- sink ----------
  for (const n of nodes.filter((m) => colOf(m) === "sink")) {
    y[n.id] = y[NOGW.egress] ?? 0;
    x[n.id] = sinkX;
  }

  const pos: Layout["pos"] = {};
  const size: Layout["size"] = {};
  for (const n of nodes) {
    const hh = h(n);
    size[n.id] = { w: W[n.kind], h: hh };
    pos[n.id] = { x: Math.round(x[n.id] ?? 0), y: Math.round((y[n.id] ?? 0) - hh / 2) };
    column[n.id] = colOf(n);
  }
  return { pos, size, headers, column };
}

/** A node or section title for resolveOverlaps: its top-left, size, layout column, and whether it's pinned. */
export interface Box {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
  column?: string;
  pinned: boolean;
}

const hits = (a: Omit<Box, "id" | "pinned">, b: Omit<Box, "id" | "pinned">) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

/** Keep auto-placed nodes off pinned ones (docs/VISUALIZATION_PLAN.md §7). Pinned boxes never move. Within each
 *  column (`column`, else the box's x), unpinned boxes are taken top to bottom; one that hits a pinned box moves down
 *  past it plus `gap` (again, if that lands it on another pinned box), and every box after it in the column moves by
 *  the same amount, so the column keeps its order and spacing. Pure and deterministic (ties by x, then id). */
export function resolveOverlaps(boxes: Box[], gap: number): Record<string, XY> {
  const out: Record<string, XY> = {};
  const pinned = boxes.filter((b) => b.pinned).sort((a, b) => a.y - b.y || a.x - b.x || a.id.localeCompare(b.id));
  for (const b of pinned) out[b.id] = { x: b.x, y: b.y };
  const cols = new Map<string, Box[]>();
  for (const b of boxes.filter((c) => !c.pinned)) {
    const k = b.column ?? `x:${b.x}`;
    cols.set(k, [...(cols.get(k) ?? []), b]);
  }
  for (const k of [...cols.keys()].sort()) {
    let shift = 0;
    for (const b of cols.get(k)!.sort((p, q) => p.y - q.y || p.x - q.x || p.id.localeCompare(q.id))) {
      const at = { ...b, y: b.y + shift };
      // each push lands below a pinned box's bottom, so it can't hit that one again: this ends
      for (let p = pinned.find((q) => hits(at, q)); p; p = pinned.find((q) => hits(at, q))) {
        const d = p.y + p.h + gap - at.y;
        at.y += d;
        shift += d;
      }
      out[b.id] = { x: b.x, y: at.y };
    }
  }
  return out;
}

/** Where a dropped node lands: where it was dropped, or, if that's on another pinned node, the nearest free spot
 *  straight below. (Unpinned nodes under it make way through resolveOverlaps; pinned ones never move.) */
export function freeSpot(drop: Omit<Box, "pinned">, others: Box[], gap: number): XY {
  const at = { ...drop };
  const pinned = others.filter((o) => o.pinned && o.id !== drop.id);
  for (let p = pinned.find((q) => hits(at, q)); p; p = pinned.find((q) => hits(at, q))) at.y = p.y + p.h + gap;
  return { x: at.x, y: at.y };
}

/** Edges that belong to a node (incident, or that caller's line). */
export const touches = (e: PEdge, id: string): boolean => e.source === id || e.target === id || e.caller === id || !!e.members?.some((m) => touches(m, id));
