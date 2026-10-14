// A MapView plus its layout as React Flow nodes and edges (docs/VISUALIZATION_PLAN.md §13). Pure; the node and edge
// components (nodes.tsx, edges.tsx) only draw what is in `data`.
import type { Edge, Node } from "@xyflow/react";
import type { PEdge, PNode, PNodeKind, Verdict } from "./graph";
import { touches, type Layout } from "./layout";
import type { MapView } from "./view";
import type { SettlingMarks } from "./settling";

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
  /** MCP with several agents selected: each tool's state per agent, for its row's tooltip. */
  toolAgents?: Record<string, string>;
  /** One agent selected: the verdict of its line into this destination. */
  ring?: Verdict;
  /** A selected caller (its lines are drawn). */
  picked?: boolean;
  /** Dragged into place by the user (saved): shows a pin with Unpin. */
  pinned?: boolean;
  /** Section title nodes only. */
  title?: string;
  width?: number;
  /** Changed by an apply that may still be settling (map/settling.ts): the clock marker's tooltip. */
  settling?: string;
}
export interface MapEdgeData extends Record<string, unknown> {
  edge: PEdge;
  dim: boolean;
  selected: boolean;
  /** Particles along the line (the clicked line only; never under reduced motion). */
  animate: boolean;
  /** No dash animation on pending lines either. */
  reducedMotion: boolean;
  /** The agent the line belongs to (its label), its place in the selection (for hover), and whether several agents
   *  are drawn (the label then names the agent). */
  agent?: string;
  agentIdx: number;
  multi: boolean;
  /** Parallel lines of several agents: px moved at each end (0 at the agent's own node). */
  offS: number;
  offT: number;
  /** Changed by an apply that may still be settling (map/settling.ts): the clock marker's tooltip. */
  settling?: string;
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
  endpoint_group: "nogrants",
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

/** The MCP servers drawn with their tool rows: the one in the panel, and every one a selected agent has a line to. */
export function expandedMcp(view: MapView, active: string | null): Set<string> {
  const out = new Set<string>();
  const mcp = new Set(view.nodes.filter((n) => n.kind === "mcp").map((n) => n.id));
  if (active && mcp.has(active)) out.add(active);
  for (const e of view.edges) if (mcp.has(e.target)) out.add(e.target);
  return out;
}

/** The offset step between parallel lines of several selected agents (px), smaller as there are more of them. */
export const offsetStep = (n: number) => (n > 1 ? Math.min(6, 36 / (n - 1)) : 0);

/** Each tool's state on one line into an MCP server: its tool breakdown when it has one (a line Show narrows keeps it),
 *  else the line's verdict for every tool. */
export function toolStatesOf(e: PEdge | undefined, n: PNode): Record<string, ToolState> | undefined {
  if (!e || !n.tools) return undefined;
  const all = (s: ToolState) => Object.fromEntries(n.tools!.map((t) => [t.name, s]));
  if (e.tools)
    return { ...Object.fromEntries(e.tools.allowed.map((t) => [t, "allowed" as const])), ...Object.fromEntries(e.tools.denied.map((t) => [t, "denied" as const])), ...Object.fromEntries(e.tools.unknown.map((t) => [t, "unknown" as const])) };
  if (e.implicit || e.verdict === "blocked" || e.verdict === "would_deny" || e.verdict === "unchecked") return all("denied");
  return all(e.verdict === "conditional" ? "unknown" : "allowed");
}

const TOOL_WORD: Record<ToolState, string> = { allowed: "allowed", denied: "denied", unknown: "can't be told here" };

/** The node's accessible name: label, kind, where it sits, how many lines, and what's pinned or staged on it. */
export function nodeAria(n: PNode, lines?: number, pinned?: boolean, picked?: boolean): string {
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
    endpoint_group: "Grouped destinations: press Enter to show them",
    google_apis: `Google API endpoints, collapsed: press Enter to show the ${n.grouped?.length ?? 0}`,
    registry: "Agent Registry",
  };
  const where = n.kind === "engine" ? (n.gateway ? `, behind ${n.gateway.split("/").pop()}` : ", no gateway") : "";
  const count = lines === undefined || n.kind === "endpoint_group" ? "" : `, ${lines} ${lines === 1 ? "line" : "lines"}`;
  const staged = n.pending?.text.length ? `, staged: ${n.pending.text.join("; ")}` : "";
  return `${n.label}, ${kind[n.kind]}${where}${picked ? ", selected: its lines are drawn" : ""}${count}${n.hiddenLines ? `, ${n.hiddenLines} ${n.hiddenLines === 1 ? "line" : "lines"} to hidden objects` : ""}${n.unreadable ? ", IAP policy couldn't be read" : ""}${staged}${pinned ? ", pinned" : ""}`;
}

export const VIA_LABEL: Record<string, string> = { project_agents: "project-wide", public: "public", registry_wide: "registry-wide", other: "group or other" };

/** Inherited line: how it's inherited ("project-wide", "public", …), from its reasons. */
export function viaText(e: PEdge): string | null {
  if (!e.inherited) return null;
  const vias = [...new Set(e.reasons.map((r) => r.via).filter((v) => v !== "member"))];
  return vias.map((v) => VIA_LABEL[v] ?? v).join(" + ") || null;
}

/** Who a line is from: its agent (a gateway → destination line is the agent's), or the client of a Client-to-Agent
 *  line, with the agent it reaches. */
export function lineFrom(e: PEdge, label: (id: string) => string): string {
  if (isClientLine(e)) return `${label(e.source)} (to ${label(e.caller!)})`;
  return e.caller && e.caller !== e.target ? label(e.caller) : label(e.source);
}
export const isClientLine = (e: PEdge) => e.direction === "ingress" && e.source.startsWith("client:") && !!e.caller;

export function edgeAria(e: PEdge, label: (id: string) => string): string {
  const from = lineFrom(e, label);
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
  settling?: SettlingMarks,
): { nodes: MNode[]; edges: MEdge[] } {
  const settled = (text: string | undefined) => (text ? `, ${text}` : "");
  const label = new Map(view.nodes.map((n) => [n.id, n.label]));
  const agents = new Set(view.agents);
  // With agents selected, nodes off their lines are dimmed (still clickable, to add one); a line or node in the panel
  // that isn't an agent dims the selected agents' lines that don't touch it.
  const lit = new Set<string>([...view.agents, ...(sel.node ? [sel.node] : [])]);
  for (const e of view.edges) {
    lit.add(e.source);
    lit.add(e.target);
  }
  const focusOther = sel.node && !agents.has(sel.node) ? sel.node : null;
  const lines = new Map<string, number>();
  for (const e of view.edges) if (e.verdict !== "path") for (const id of new Set([e.source, e.target, e.caller ?? ""])) lines.set(id, (lines.get(id) ?? 0) + 1);
  // one agent selected: its verdict on each destination (a ring) and on each MCP tool
  const intoBy = new Map<string, PEdge>();
  if (view.agents.length === 1) for (const e of view.edges) if (e.verdict !== "path") intoBy.set(e.target, e);
  const one = view.agents.length === 1;
  // several agents: each MCP tool's state per agent (the rows' tooltips; the marks would disagree)
  const toolAgents = new Map<string, Record<string, string>>();
  const byId = new Map(view.nodes.map((n) => [n.id, n]));
  if (!one)
    for (const e of view.edges) {
      const n = byId.get(e.target);
      const st = n?.kind === "mcp" ? toolStatesOf(e, n) : undefined;
      if (!st) continue;
      const tips = toolAgents.get(n!.id) ?? {};
      for (const [t, s] of Object.entries(st)) tips[t] = [tips[t], `${label.get(e.caller ?? "") ?? e.caller}: ${TOOL_WORD[s]}`].filter(Boolean).join("\n");
      toolAgents.set(n!.id, tips);
    }

  const nodes: MNode[] = view.nodes.map((n) => ({
    id: n.id,
    type: TYPE[n.kind],
    position: layout.pos[n.id],
    data: {
      node: n,
      dim: agents.size > 0 && !lit.has(n.id),
      hit: sel.hit === n.id,
      expanded: expanded.has(n.id),
      toolStates: one ? toolStatesOf(intoBy.get(n.id), n) : undefined,
      toolAgents: toolAgents.get(n.id),
      ring: one ? intoBy.get(n.id)?.verdict : undefined,
      pinned: pinned.has(n.id),
      picked: agents.has(n.id),
      settling: settling?.nodes.get(n.id),
    },
    selected: sel.node === n.id,
    ariaLabel: nodeAria(n, lines.get(n.id) ?? 0, pinned.has(n.id), agents.has(n.id)) + settled(settling?.nodes.get(n.id)),
    draggable: true,
  }));
  for (const h of layout.headers)
    nodes.push({ id: h.id, type: "section", position: { x: h.x, y: h.y }, data: { node: { id: h.id, kind: "endpoint_group", label: h.label, column: "dests", section: "", chips: [], search: "" }, dim: false, hit: false, expanded: false, title: h.label, width: h.w }, draggable: false, selectable: false, focusable: false });

  // Parallel lines of several agents: each agent's lines move by its own offset at the shared ends (gateways,
  // destinations), so two agents' lines to one destination stay apart.
  const step = offsetStep(view.agents.length);
  const offOf = (c: string | undefined) => {
    const i = c ? view.agents.indexOf(c) : -1;
    return i < 0 ? 0 : Math.round((i - (view.agents.length - 1) / 2) * step * 10) / 10;
  };
  const multi = view.agents.length > 1;
  // Trunks first so grant lines draw over them; every line stays under the nodes (no zIndex).
  const ordered = [...view.edges].sort((a, b) => Number(b.verdict === "path") - Number(a.verdict === "path"));
  const edges: MEdge[] = ordered.map((e) => {
    const off = offOf(e.caller);
    const dim = !!focusOther && !touches(e, focusOther);
    const idx = e.caller ? view.agents.indexOf(e.caller) : -1;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      sourceHandle: "out",
      targetHandle: "in",
      type: "policy",
      className: [dim && "dim", sel.edge === e.id && "sel", e.implicit && "implicit", e.pending && `pending-${e.pending}`, idx >= 0 && `ag${idx}`].filter(Boolean).join(" "),
      selected: sel.edge === e.id,
      ariaLabel: edgeAria(e, (id) => label.get(id) ?? id) + settled(settling?.edges.get(e.id)),
      data: {
        edge: e,
        dim,
        selected: sel.edge === e.id,
        animate: !reducedMotion && sel.edge === e.id,
        reducedMotion,
        agent: e.caller ? label.get(e.caller) : undefined,
        agentIdx: idx,
        multi,
        offS: e.source === e.caller ? 0 : off,
        offT: e.target === e.caller ? 0 : off,
        settling: settling?.edges.get(e.id),
      },
    };
  });
  return { nodes, edges };
}
