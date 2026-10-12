// "Show on map" (docs/VISUALIZATION_PLAN.md §2): what the map focuses on when it's opened from another step, and how
// the map finds that line again. Pure and small: the other steps import it without pulling in the map chunk.
import type { Direction, Gateway, Grant, Intent, Inventory } from "../api/types";
import { pseudoOf } from "./ids";

/** A node to select (an engine selects the agent's own lines) and, optionally, the destination of the line to open. */
export interface MapFocus {
  direction?: Direction;
  node?: string;
  target?: string;
}

/** The line of a grant: from its agent (or the pseudo caller of a group, public or other member) to its resource. */
export function focusForGrant(g: Pick<Grant, "member" | "resource">, inv: Inventory | null | undefined): MapFocus {
  const eng = inv?.engines.find((e) => e.principal === g.member);
  return { direction: "egress", node: eng?.name ?? pseudoOf(g.member, inv?.project_agents_principal ?? null), target: g.resource };
}

/** The line or node a cart item changes. null = nothing the map draws (Model Armor templates, roles, ...). */
export function focusForIntent(i: Intent, inv: Inventory | null | undefined): MapFocus | null {
  if ((i.kind === "grant" || i.kind === "revoke" || i.kind === "modify") && i.source && i.destination)
    return i.source.engine ? { direction: "egress", node: i.source.engine, target: i.destination.name } : focusForGrant({ member: i.source.principal, resource: i.destination.name }, inv);
  if ((i.kind === "bind_gateway" || i.kind === "unbind_gateway") && i.engine) return { direction: i.gateway?.direction ?? "egress", node: i.engine };
  if ((i.kind === "set_enforcement" || i.kind === "model_armor_on" || i.kind === "model_armor_off") && i.gateway?.name) return { direction: i.gateway.direction, node: i.gateway.name };
  return null;
}

export const focusForGateway = (g: Pick<Gateway, "name" | "type">): MapFocus => ({ direction: g.type, node: g.name });

/** Kinds that have a "Show on map" link in Review and the cart. */
export const ON_MAP = new Set<Intent["kind"]>(["grant", "revoke", "modify", "bind_gateway", "unbind_gateway", "set_enforcement", "model_armor_on", "model_armor_off"]);

/** The line a focus names among the visible lines: the selected caller's line to the target (a granted line before
 *  a default-deny one), else any line into the target from that caller or its combined line. */
export function findFocusEdge<E extends { id: string; source: string; target: string; caller?: string; implicit?: boolean; verdict: string; parts?: { caller?: string }[] }>(
  edges: E[],
  f: MapFocus,
): E | null {
  if (!f.target) return null;
  const into = edges.filter((e) => e.target === f.target && e.verdict !== "path");
  const own = into.filter((e) => e.caller === f.node || e.source === f.node || e.parts?.some((p) => p.caller === f.node));
  return own.find((e) => !e.implicit) ?? own[0] ?? null;
}
