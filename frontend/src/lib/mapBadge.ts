// The Policy map step's badge (docs/VISUALIZATION_PLAN.md §2): the staged changes the map shows, while the cart isn't
// empty. It lives in the first-load bundle, so it can't build the graph (map/*, a lazy chunk with React Flow): it
// counts the cart items of the kinds the staged-change view draws (map/simulate.ts) instead of the pending lines.
import type { Intent, IntentKind } from "../api/types";
import { plural } from "./util";

/** Intent kinds that change what the map draws: grants and lanes, enforcement mode, Model Armor on or off. */
export const MAP_KINDS: ReadonlySet<IntentKind> = new Set<IntentKind>(["grant", "revoke", "modify", "bind_gateway", "unbind_gateway", "set_enforcement", "model_armor_on", "model_armor_off"]);

export const mapPendingCount = (cart: Intent[]): number => cart.filter((i) => MAP_KINDS.has(i.kind)).length;

/** The badge, or null when nothing in the cart shows on the map. */
export function mapBadge(cart: Intent[]): { text: string; tone: string; title: string } | null {
  const n = mapPendingCount(cart);
  return n ? { text: `${n}`, tone: "amber", title: `${plural(n, "staged change")} on the map` } : null;
}
