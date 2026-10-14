// The map's clock markers for applies still settling (lib/settling.ts): the lines and nodes an apply changed, found from
// its applied intents. Pure and small; the list comes from the store, and a marker goes when its apply's max time
// passes (the store drops the entry).
//
// grant / revoke / modify: the caller's line into the destination (the agent's own, or its pseudo caller's for a group,
// public or other member), a line grouped into "Google APIs" included. bind / unbind: the agent's node and its lane
// (its trunk or direct line; Client-to-Agent: its lines in that direction). Enforcement and Model Armor: the gateway.
import type { PEdge, PNode } from "./graph";
import { pseudoOf } from "./ids";
import { markText, type SettleEntry, type SettleTarget } from "../lib/settling";

export type SettlingMarks = { edges: Map<string, string>; nodes: Map<string, string> };

const GRANTS = new Set(["grant", "revoke", "modify"]);
const LANE = new Set(["bind_gateway", "unbind_gateway"]);
const GATEWAY = new Set(["set_enforcement", "model_armor_on", "model_armor_off", "dedicate_extension"]);

/** Does this applied intent change this line? */
export function lineMatches(t: SettleTarget, e: PEdge, projectSet: string | null = null): boolean {
  if (GRANTS.has(t.kind)) {
    if (!t.source || !t.destination || e.verdict === "path") return false;
    const caller = t.source.engine ?? pseudoOf(t.source.principal, projectSet);
    if (e.caller !== caller && e.source !== caller) return false;
    const d = t.destination.name;
    return e.target === d || !!e.members?.some((m) => m.target === d) || e.reasons.some((r) => r.resource === d);
  }
  if (LANE.has(t.kind)) {
    if (!t.engine || e.caller !== t.engine || e.direction !== (t.gateway?.direction ?? "egress")) return false;
    return e.direction === "ingress" || e.id.startsWith("trunk:") || e.id.startsWith("direct:");
  }
  return false;
}

/** Does this applied intent change this node? */
export function nodeMatches(t: SettleTarget, n: PNode): boolean {
  if (LANE.has(t.kind)) return !!t.engine && n.id === t.engine;
  if (GATEWAY.has(t.kind)) return !!t.gateway && n.id === t.gateway.name;
  return false;
}

/** Each marked line and node with its tooltip (the newest apply's, when several changed it). `entries`: the settling
 *  list for this project, its max times not yet passed. */
export function settlingMarks(edges: PEdge[], nodes: PNode[], entries: SettleEntry[], projectSet: string | null = null): SettlingMarks {
  const out: SettlingMarks = { edges: new Map(), nodes: new Map() };
  if (!entries.length) return out;
  // oldest first, so the newest apply's text wins
  for (const s of [...entries].sort((a, b) => a.appliedAt - b.appliedAt)) {
    const text = markText(s);
    for (const t of s.targets) {
      const line = t.tools?.length ? `${text} Tools: ${t.tools.join(", ")}.` : text;
      for (const e of edges) if (lineMatches(t, e, projectSet)) out.edges.set(e.id, line);
      for (const n of nodes) if (nodeMatches(t, n)) out.nodes.set(n.id, text);
    }
  }
  return out;
}
