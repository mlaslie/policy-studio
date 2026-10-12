// The cart applied to a copy of the state the map is drawn from (docs/VISUALIZATION_PLAN.md §8): the "after" side of
// the staged-change view. Pure; nothing is written anywhere. Grants, revokes and modifies match bindings on the
// condition **expression** (whitespace-insensitive), as the backend's remove_binding / same_condition does, so the
// preview and Apply agree on which binding a revoke removes. Review's /diff and /preflight stay the authority.
import type { Binding, Gateway, Intent, Inventory, ModelArmorResp } from "../api/types";
import { ROLE, conditionFor, intentEnglish, shortName } from "../lib/policy";

export interface MapState {
  inventory: Inventory;
  gateways: Gateway[];
  modelArmor?: ModelArmorResp | null;
}
export interface Simulated extends MapState {
  /** Intent id → the map node ids it changes (engines, gateways, destinations), for the pending marks. */
  effects: Record<string, string[]>;
  /** Intents that don't change what the map draws (Model Armor templates, service agent roles, ...). */
  ignored: string[];
}

const normExpr = (c: Binding["condition"] | undefined) => (c?.expression ?? "").replace(/\s+/g, " ").trim();
export const sameCondition = (a: Binding["condition"] | undefined, b: Binding["condition"] | undefined) => normExpr(a) === normExpr(b);

/** One binding of member on these bindings, swapped from one condition to another (or added / removed). */
function withBinding(cur: Binding[], i: Intent, member: string, cond: Binding["condition"]): Binding[] {
  if (cur.some((b) => b.member === member && b.role === ROLE && sameCondition(b.condition, cond))) return cur;
  return [...cur, { role: ROLE, member, member_label: i.source?.label ?? member, condition: cond, english: intentEnglish({ ...i, kind: "grant", access: i.access }) }];
}
const without = (cur: Binding[], member: string, cond: Binding["condition"]) => cur.filter((b) => !(b.member === member && b.role === ROLE && sameCondition(b.condition, cond)));

export function simulate(state: MapState, cart: Intent[]): Simulated {
  const s: MapState = structuredClone({ inventory: state.inventory, gateways: state.gateways, modelArmor: state.modelArmor ?? null });
  const effects: Record<string, string[]> = {};
  const ignored: string[] = [];
  for (const i of cart) {
    const touched = apply(s, i);
    if (touched) effects[i.id] = touched;
    else ignored.push(i.id);
  }
  return { ...s, effects, ignored };
}

/** Apply one intent in place; returns the node ids it changes, or null when the map doesn't draw it. */
function apply(s: MapState, i: Intent): string[] | null {
  const inv = s.inventory;
  switch (i.kind) {
    case "grant":
    case "revoke":
    case "modify": {
      const res = i.destination?.name ?? "";
      const member = i.source?.principal ?? "";
      if (!res || !member) return null;
      const cur = inv.access[res] ?? [];
      if (i.kind === "grant") inv.access[res] = withBinding(cur, i, member, conditionFor(i.access));
      // no access = the unconditional binding; otherwise only the binding with exactly this expression
      else if (i.kind === "revoke") inv.access[res] = without(cur, member, conditionFor(i.access));
      else {
        // one read-modify-write: the binding with exactly access_from is replaced (nothing happens if it's gone)
        const from = conditionFor(i.access_from);
        const to = conditionFor(i.access);
        if (sameCondition(from, to) || !cur.some((b) => b.member === member && b.role === ROLE && sameCondition(b.condition, from))) return [res];
        inv.access[res] = withBinding(without(cur, member, from), i, member, to);
      }
      return [res, ...(i.source?.engine ? [i.source.engine] : [])];
    }
    case "bind_gateway":
    case "unbind_gateway": {
      const dir = i.gateway?.direction ?? "egress";
      const e = inv.engines.find((x) => x.name === i.engine);
      if (!e) return null;
      const was = e.gateways[dir];
      for (const g of s.gateways) g.bound_engines = g.bound_engines.filter((b) => !(b.engine === e.name && b.direction === dir));
      if (i.kind === "bind_gateway" && i.gateway?.name) {
        e.gateways[dir] = i.gateway.name;
        s.gateways.find((g) => g.name === i.gateway!.name)?.bound_engines.push({ engine: e.name, display_name: e.display_name, direction: dir });
      } else delete e.gateways[dir];
      return [e.name, ...(was ? [was] : []), ...(i.gateway?.name ? [i.gateway.name] : [])];
    }
    case "set_enforcement": {
      const gw = s.gateways.find((g) => g.name === i.gateway?.name);
      const ext = shortName(i.extension ?? gw?.enforcement?.extension ?? "");
      // shared: every gateway on the extension changes together; dedicated: only this one
      const hit = i.scope === "dedicated" ? (gw ? [gw] : []) : s.gateways.filter((g) => g.enforcement && ext && shortName(g.enforcement.extension) === ext);
      if (!hit.length || !i.mode) return null;
      for (const g of hit) if (g.enforcement) g.enforcement.mode = i.mode;
      return hit.map((g) => g.name);
    }
    case "model_armor_on":
    case "model_armor_off": {
      const m = s.modelArmor?.gateways.find((g) => g.gateway === i.gateway?.name);
      if (!m) return null;
      m.enabled = i.kind === "model_armor_on";
      if (m.enabled && !m.template) m.template = s.modelArmor?.templates[0] ?? null;
      return [m.gateway];
    }
    default:
      return null;
  }
}
