// A MapView plus its layout as React Flow nodes and edges (docs/VISUALIZATION_PLAN.md §13). Pure; the node and edge
// components (nodes.tsx, edges.tsx) only draw what is in `data`.
import type { Edge, Node } from "@xyflow/react";
import type { PEdge, PNode, PNodeKind, Verdict } from "./graph";
import { touches, type Layout } from "./layout";
import type { MapView } from "./view";

export type ToolState = "allowed" | "denied" | "unknown";
export interface MapNodeData extends Record<string, unknown> {
  node: PNode;
  /** Not part of the current selection: drawn faded. */
  dim: boolean;
  /** The search match, briefly highlighted. */
  hit: boolean;
  /** MCP: tool rows shown, colored by the selected agent's access when there is one. */
  expanded: boolean;
  toolStates?: Record<string, ToolState>;
  /** Selected-agent view: the verdict of the line into this destination. */
  ring?: Verdict;
  /** Dragged into place by the user (saved): shows a pin with Unpin. */
  pinned?: boolean;
  /** Section title nodes only. */
  title?: string;
  width?: number;
}
export interface MapEdgeData extends Record<string, unknown> {
  edge: PEdge;
  dim: boolean;
  selected: boolean;
  /** Particles along the line (the clicked line only; never under reduced motion). */
  animate: boolean;
  /** No dash animation on pending lines either. */
  reducedMotion: boolean;
}
export type MNode = Node<MapNodeData>;
export type MEdge = Edge<MapEdgeData>;

const TYPE: Record<PNodeKind, string> = {
  engine: "engine",
  principal_group: "pseudo",
  client: "pseudo",
  gateway: "gateway",
  no_gateway: "gateway",
  anywhere: "sink",
  a2a: "dest",
  runtime_dest: "dest",
  endpoint: "dest",
  registry: "dest",
  mcp: "mcp",
  endpoint_group: "group",
  google_apis: "google",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  allowed: "Allowed",
  partial: "Partly allowed (some tools)",
  conditional: "Conditional: not evaluated here",
  blocked: "Denied by default",
  would_deny: "Would be denied: passes today (dry run)",
  unchecked: "Not checked: no IAP policy",
  dormant: "Not enforced: no gateway",
  direct: "Direct (no gateway)",
  screened: "Screened by Model Armor",
  unscreened: "In the path, no screening",
  path: "Through the gateway",
};

/** The MCP servers drawn with their tool rows: the selected one, and every one the selected agent has a line to. */
export function expandedMcp(view: MapView, selected: string | null): Set<string> {
  const out = new Set<string>();
  const mcp = new Set(view.nodes.filter((n) => n.kind === "mcp").map((n) => n.id));
  if (selected && mcp.has(selected)) out.add(selected);
  if (view.focus) for (const e of view.edges) if (mcp.has(e.target)) out.add(e.target);
  return out;
}

function toolStatesOf(e: PEdge | undefined, n: PNode): Record<string, ToolState> | undefined {
  if (!e || !n.tools) return undefined;
  const all = (s: ToolState) => Object.fromEntries(n.tools!.map((t) => [t.name, s]));
  if (e.implicit || e.verdict === "blocked" || e.verdict === "would_deny") return all("denied");
  if (!e.tools) return all(e.verdict === "conditional" ? "unknown" : "allowed");
  return { ...Object.fromEntries(e.tools.allowed.map((t) => [t, "allowed" as const])), ...Object.fromEntries(e.tools.denied.map((t) => [t, "denied" as const])), ...Object.fromEntries(e.tools.unknown.map((t) => [t, "unknown" as const])) };
}

/** The node's accessible name: label, kind, where it sits, how many lines, and what's pinned or staged on it. */
export function nodeAria(n: PNode, lines?: number, pinned?: boolean): string {
  const kind: Record<PNodeKind, string> = {
    engine: "Agent Runtime agent",
    principal_group: "Callers",
    client: "Client",
    gateway: "Agent Gateway",
    no_gateway: "No gateway",
    anywhere: "Any host",
    a2a: "A2A agent",
    runtime_dest: "Agent Runtime agent (registry entry)",
    mcp: "MCP server",
    endpoint: "API endpoint",
    endpoint_group: "Grouped destinations",
    google_apis: `Google API endpoints, collapsed: press Enter to show the ${n.grouped?.length ?? 0}`,
    registry: "Agent Registry",
  };
  const where = n.kind === "engine" ? (n.gateway ? `, behind ${n.gateway.split("/").pop()}` : ", no gateway") : "";
  const count = lines === undefined || n.kind === "endpoint_group" ? "" : `, ${lines} ${lines === 1 ? "line" : "lines"}`;
  const staged = n.pending?.text.length ? `, staged: ${n.pending.text.join("; ")}` : "";
  return `${n.label}, ${kind[n.kind]}${where}${count}${n.unreadable ? ", IAP policy couldn't be read" : ""}${staged}${pinned ? ", pinned" : ""}`;
}

export const VIA_LABEL: Record<string, string> = { project_agents: "project-wide", public: "public", registry_wide: "registry-wide", other: "group or other" };

/** Inherited line: how it's inherited ("project-wide", "public", …), from its reasons. */
export function viaText(e: PEdge): string | null {
  if (!e.inherited) return null;
  const vias = [...new Set(e.reasons.map((r) => r.via).filter((v) => v !== "member"))];
  return vias.map((v) => VIA_LABEL[v] ?? v).join(" + ") || null;
}

export function edgeAria(e: PEdge, label: (id: string) => string): string {
  const from = e.caller && e.caller !== e.target ? label(e.caller) : label(e.source);
  const via = viaText(e);
  const staged = e.pending ? `, staged change: ${PENDING_WORD[e.pending]}${e.pending === "remove" && e.after ? `, then ${VERDICT_LABEL[e.after].toLowerCase()}` : e.before ? `, today ${VERDICT_LABEL[e.before].toLowerCase()}` : ""}` : "";
  return `${from} to ${label(e.target)}: ${VERDICT_LABEL[e.verdict]}${e.label ? ` (${e.label})` : ""}${via ? `, inherited via ${via} grant` : ""}${staged}`;
}

export const PENDING_WORD = { add: "will be added", remove: "will be removed", change: "will change" } as const;

export function toFlow(
  view: MapView,
  layout: Layout,
  sel: { node: string | null; edge: string | null; hit: string | null },
  expanded: Set<string>,
  reducedMotion = false,
  pinned: Set<string> = new Set(),
): { nodes: MNode[]; edges: MEdge[] } {
  const label = new Map(view.nodes.map((n) => [n.id, n.label]));
  const lit = new Set<string>();
  if (sel.node) {
    lit.add(sel.node);
    for (const e of view.edges)
      if (touches(e, sel.node)) {
        lit.add(e.source);
        lit.add(e.target);
        if (e.caller) lit.add(e.caller);
      }
  }
  const lines = new Map<string, number>();
  for (const e of view.edges) if (e.verdict !== "path") for (const id of new Set([e.source, e.target, ...(e.members ?? [e]).flatMap((m) => m.parts ?? [m]).map((p) => p.caller ?? "")])) lines.set(id, (lines.get(id) ?? 0) + 1);
  const intoBy = new Map<string, PEdge>();
  if (view.focus) for (const e of view.edges) if (e.verdict !== "path") intoBy.set(e.target, e);

  const nodes: MNode[] = view.nodes.map((n) => ({
    id: n.id,
    type: TYPE[n.kind],
    position: layout.pos[n.id],
    data: {
      node: n,
      dim: !!sel.node && !lit.has(n.id),
      hit: sel.hit === n.id,
      expanded: expanded.has(n.id),
      toolStates: view.focus ? toolStatesOf(intoBy.get(n.id), n) : undefined,
      ring: view.focus ? intoBy.get(n.id)?.verdict : undefined,
      pinned: pinned.has(n.id),
    },
    selected: sel.node === n.id,
    ariaLabel: nodeAria(n, lines.get(n.id) ?? 0, pinned.has(n.id)),
    draggable: true,
  }));
  for (const h of layout.headers)
    nodes.push({ id: h.id, type: "section", position: { x: h.x, y: h.y }, data: { node: { id: h.id, kind: "endpoint_group", label: h.label, column: "dests", section: "", chips: [], search: "" }, dim: false, hit: false, expanded: false, title: h.label, width: h.w }, draggable: false, selectable: false, focusable: false });

  // Trunks first so grant lines draw over them; every line stays under the nodes (no zIndex).
  const ordered = [...view.edges].sort((a, b) => Number(b.verdict === "path") - Number(a.verdict === "path"));
  const edges: MEdge[] = ordered.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    sourceHandle: "out",
    targetHandle: "in",
    type: "policy",
    className: [!!sel.node && !touches(e, sel.node) && "dim", sel.edge === e.id && "sel", e.implicit && "implicit", e.pending && `pending-${e.pending}`].filter(Boolean).join(" "),
    selected: sel.edge === e.id,
    ariaLabel: edgeAria(e, (id) => label.get(id) ?? id),
    data: { edge: e, dim: !!sel.node && !touches(e, sel.node), selected: sel.edge === e.id, animate: !reducedMotion && sel.edge === e.id, reducedMotion },
  }));
  return { nodes, edges };
}
