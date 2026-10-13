// The Add to cart preview's small map (PreviewDialog.tsx): the staged view (map/diff.ts mergeStaged) of just this
// change, cut down to the source, its gateway (or the "No gateway" lane) and the destination. Pure.
import type { Intent } from "../api/types";
import { NOGW, type PolicyGraph } from "../map/graph";
import { pseudoOf } from "../map/ids";
import type { MapView } from "../map/view";

/** The map's graph for just this change: today's and after it, merged (the staged view), cut down to the source, its
 *  gateway (or "No gateway") and the destination, with their lines. */
export function previewGraph(g: PolicyGraph, intent: Intent, projectSet: string | null): { view: MapView; caller: string; dest: string } {
  const dest = intent.destination?.name ?? "";
  const caller = intent.source?.engine ?? pseudoOf(intent.source?.principal ?? "", projectSet);
  const src = g.nodes.find((n) => n.id === caller);
  const lane = src?.kind === "engine" ? (src.gateway ?? NOGW.egress) : null;
  const keep = new Set([caller, dest, ...(lane ? [lane] : [])]);
  const nodes = g.nodes.filter((n) => keep.has(n.id));
  const edges = g.edges.filter((e) => e.caller === caller && keep.has(e.source) && keep.has(e.target) && (e.target === dest || e.source === caller));
  return { view: { nodes, edges, layoutEdges: edges, rows: [], more: 0, agents: [caller], hiddenLines: {}, lines: edges.length }, caller, dest };
}

