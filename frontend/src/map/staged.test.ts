// The staged-change view (docs/VISUALIZATION_PLAN.md §8, §14): simulate.ts applies each intent kind to a copy of the
// state (grants and revokes matched on the condition expression), diff.ts turns before / after into pending add,
// remove and change, with the cart intents behind each.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Ctx, Intent } from "../api/types";
import { READ_ONLY_EXPR, ROLE } from "../lib/policy";
import { NOGW, buildPolicyGraph, type Direction, type PEdge } from "./graph";
import { diffGraphs, mergeStaged, pairKey, pendingCount } from "./diff";
import { simulate, type MapState } from "./simulate";
import { DEFAULT_FILTERS, viewOf } from "./view";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const w0 = buildWorld(CTX);
const inv = w0.inventory;
const state: MapState = { inventory: inv, gateways: w0.gateways, modelArmor: w0.modelArmor };
const eng = (name: string) => inv.engines.find((e) => e.display_name === name)!;
const dest = (name: string) => [...inv.agents, ...inv.mcp_servers, ...inv.endpoints].find((d) => d.display_name === name)!;
const EGRESS = w0.gateways.find((g) => g.type === "egress")!;
const INGRESS = w0.gateways.find((g) => g.type === "ingress")!;
const hd = eng("Helpdesk Agent");
const travel = eng("Travel Planner");
const hr = eng("HR Assistant");
const tickets = dest("Tickets MCP");
const hrd = dest("HR Directory MCP");
const src = (e = hd) => ({ type: "engine" as const, principal: e.principal, label: e.display_name, engine: e.name });
const dst = (d: { id: string; name: string; display_name: string }, kind: "mcp_server" | "agent" | "endpoint" = "mcp_server") => ({ kind, id: d.id, name: d.name, label: d.display_name });

/** Before, after and the merged graph for a cart. */
function staged(cart: Intent[], direction: Direction = "egress") {
  const sim = simulate(state, cart);
  const input = { direction, ctx: CTX };
  const before = buildPolicyGraph({ ...input, inventory: inv, gateways: w0.gateways, modelArmor: w0.modelArmor });
  const after = buildPolicyGraph({ ...input, inventory: sim.inventory, gateways: sim.gateways, modelArmor: sim.modelArmor });
  const d = diffGraphs(before, after);
  return { sim, before, after, d, merged: mergeStaged(before, after, d, cart, inv, sim.effects) };
}
const line = (ls: PEdge[], caller: string, target: string) => ls.find((l) => l.caller === caller && l.target === target);

describe("simulate", () => {
  it("never touches the state it's given", () => {
    const before = JSON.stringify(state);
    simulate(state, [{ id: "g", kind: "grant", source: src(), destination: dst(hrd), access: { mode: "all" } }, { id: "b", kind: "bind_gateway", engine: travel.name, gateway: { name: EGRESS.name, direction: "egress" } }]);
    expect(JSON.stringify(state)).toBe(before);
  });

  it("grant adds a binding once (an exact duplicate is a no-op)", () => {
    const g: Intent = { id: "g", kind: "grant", source: src(), destination: dst(hrd), access: { mode: "read_only_hint" } };
    const s = simulate(state, [g, { ...g, id: "g2" }]);
    const mine = s.inventory.access[hrd.name].filter((b) => b.member === hd.principal);
    expect(mine).toEqual([expect.objectContaining({ role: ROLE, condition: expect.objectContaining({ expression: READ_ONLY_EXPR }) })]);
    expect(s.effects.g).toContain(hrd.name);
  });

  it("revoke matches the condition expression (whitespace aside), not the title", () => {
    const spaced = READ_ONLY_EXPR.replace(" || ", "   ||\n ");
    const ok = simulate(state, [{ id: "r", kind: "revoke", source: src(), destination: dst(tickets), access: { mode: "custom", expression: spaced, title: "another title" } }]);
    expect(ok.inventory.access[tickets.name].some((b) => b.member === hd.principal)).toBe(false);
    const other = simulate(state, [{ id: "r", kind: "revoke", source: src(), destination: dst(tickets), access: { mode: "all" } }]);
    expect(other.inventory.access[tickets.name].some((b) => b.member === hd.principal)).toBe(true);
  });

  it("modify swaps exactly the access_from binding; a missing one changes nothing", () => {
    const m: Intent = { id: "m", kind: "modify", source: src(), destination: dst(tickets), access_from: { mode: "custom", expression: READ_ONLY_EXPR }, access: { mode: "tools", tools: ["get_ticket"] } };
    const s = simulate(state, [m]);
    const mine = s.inventory.access[tickets.name].filter((b) => b.member === hd.principal);
    expect(mine).toHaveLength(1);
    expect(mine[0].condition?.expression).toContain("'get_ticket'");
    const gone = simulate(state, [{ ...m, access_from: { mode: "all" } }]);
    expect(gone.inventory.access[tickets.name]).toEqual(inv.access[tickets.name]);
  });

  it("bind / unbind move the engine and the gateway's bound list", () => {
    const b = simulate(state, [{ id: "b", kind: "bind_gateway", engine: travel.name, gateway: { name: EGRESS.name, direction: "egress" } }]);
    expect(b.inventory.engines.find((e) => e.name === travel.name)!.gateways.egress).toBe(EGRESS.name);
    expect(b.gateways.find((g) => g.name === EGRESS.name)!.bound_engines.some((x) => x.engine === travel.name && x.direction === "egress")).toBe(true);
    const u = simulate(state, [{ id: "u", kind: "unbind_gateway", engine: hd.name, gateway: { name: EGRESS.name, direction: "egress" } }]);
    expect(u.inventory.engines.find((e) => e.name === hd.name)!.gateways.egress).toBeUndefined();
    expect(u.gateways.find((g) => g.name === EGRESS.name)!.bound_engines.some((x) => x.engine === hd.name && x.direction === "egress")).toBe(false);
  });

  it("set_enforcement: shared changes every gateway on the extension, dedicated only the one", () => {
    const ext = EGRESS.enforcement!.extension;
    const shared = simulate(state, [{ id: "e", kind: "set_enforcement", gateway: { name: EGRESS.name, direction: "egress" }, extension: ext, mode: "ENFORCE", scope: "shared" }]);
    expect(shared.gateways.filter((g) => g.enforcement).map((g) => g.enforcement!.mode)).toEqual(["ENFORCE", "ENFORCE"]);
    expect(shared.effects.e.sort()).toEqual([EGRESS.name, INGRESS.name].sort());
    const ded = simulate(state, [{ id: "e", kind: "set_enforcement", gateway: { name: EGRESS.name, direction: "egress" }, extension: ext, mode: "ENFORCE", scope: "dedicated" }]);
    expect(ded.gateways.find((g) => g.name === INGRESS.name)!.enforcement!.mode).toBe("DRY_RUN");
  });

  it("Model Armor on / off set enabled; kinds the map doesn't draw are ignored", () => {
    const s = simulate(state, [
      { id: "on", kind: "model_armor_on", gateway: { name: INGRESS.name, direction: "ingress" } },
      { id: "off", kind: "model_armor_off", gateway: { name: EGRESS.name, direction: "egress" } },
      { id: "t", kind: "model_armor_template", params: { template_id: "x" } },
    ]);
    expect(s.modelArmor!.gateways.find((g) => g.gateway === INGRESS.name)!.enabled).toBe(true);
    expect(s.modelArmor!.gateways.find((g) => g.gateway === EGRESS.name)!.enabled).toBe(false);
    expect(s.ignored).toEqual(["t"]);
  });
});

describe("diff: pending add, remove and change for each kind", () => {
  it("grant: the default-deny line becomes a pending add (drawn once)", () => {
    const g: Intent = { id: "g", kind: "grant", source: src(), destination: dst(hrd), access: { mode: "read_only_hint" } };
    const { merged } = staged([g]);
    const ls = merged.edges.filter((l) => l.caller === hd.name && l.target === hrd.name);
    expect(ls).toHaveLength(1);
    expect(ls[0]).toMatchObject({ id: `a:${hd.name}|${hrd.name}`, pending: "add", before: "would_deny", verdict: "partial", intents: ["g"] });
    // HR Assistant's own line to it is untouched
    expect(line(merged.edges, hr.name, hrd.name)?.pending).toBeUndefined();
  });

  it("revoke: a pending remove that will be denied by default (dry run: would be denied)", () => {
    const r: Intent = { id: "r", kind: "revoke", source: src(), destination: dst(tickets), access: { mode: "custom", expression: READ_ONLY_EXPR } };
    const { merged, after } = staged([r]);
    const l = line(merged.edges, hd.name, tickets.name)!;
    expect(l).toMatchObject({ pending: "remove", verdict: "partial", after: "would_deny", intents: ["r"] });
    expect(line(after.edges, hd.name, tickets.name)?.implicit).toBe(true);
    // the default-deny line it becomes isn't drawn as well
    expect(merged.edges.filter((x) => x.target === tickets.name && x.caller === hd.name)).toHaveLength(1);
  });

  it("modify: one pending change, today's verdict kept for the text", () => {
    const m: Intent = { id: "m", kind: "modify", source: src(), destination: dst(tickets), access_from: { mode: "custom", expression: READ_ONLY_EXPR }, access: { mode: "tools", tools: ["get_ticket"] } };
    const l = line(staged([m]).merged.edges, hd.name, tickets.name)!;
    expect(l).toMatchObject({ pending: "change", before: "partial", beforeLabel: "read-only", verdict: "partial", intents: ["m"] });
    expect(l.label).not.toBe("read-only");
  });

  it("bind: the agent changes lane; its dormant lines move behind the gateway", () => {
    const b: Intent = { id: "b", kind: "bind_gateway", engine: travel.name, gateway: { name: EGRESS.name, direction: "egress" } };
    const { merged, d } = staged([b]);
    expect(d.nodes.get(travel.name)).toEqual(["Binding to corp-egress staged"]);
    expect(merged.nodes.find((n) => n.id === travel.name)!.pending).toEqual({ text: ["Binding to corp-egress staged"], intents: ["b"] });
    const lane = merged.edges.find((e) => e.id === `trunk:${travel.name}`)!;
    expect(lane).toMatchObject({ pending: "change", before: "direct", verdict: "path", intents: ["b"] });
    const cal = dest("Calendar Agent").name;
    // its own line moves from No gateway (dormant) to the gateway; its straight-out lane goes
    expect(line(merged.edges, travel.name, cal)).toMatchObject({ id: `a:${travel.name}|${cal}`, pending: "change", before: "dormant", source: EGRESS.name, intents: ["b"] });
    expect(merged.edges.find((e) => e.id === `out:${travel.name}`)).toMatchObject({ pending: "remove", verdict: "direct" });
    // and it gains default-deny lines (pending adds)
    expect(merged.edges.some((e) => e.caller === travel.name && e.implicit && e.pending === "add")).toBe(true);
    expect(pairKey(merged.edges.find((e) => e.id === `trunk:${travel.name}`)!)).toBe(`lane:${travel.name}`);
  });

  it("unbind: the agent leaves the gateway lane", () => {
    const u: Intent = { id: "u", kind: "unbind_gateway", engine: hd.name, gateway: { name: EGRESS.name, direction: "egress" } };
    const { merged, d } = staged([u]);
    expect(d.nodes.get(hd.name)).toEqual(["Unbinding from corp-egress staged"]);
    expect(merged.edges.find((e) => e.id === `direct:${hd.name}`)).toMatchObject({ pending: "change", before: "path", verdict: "direct", intents: ["u"] });
  });

  it("set_enforcement: would-deny lines become blocked; the gateway shows the staged mode", () => {
    const e: Intent = { id: "e", kind: "set_enforcement", gateway: { name: EGRESS.name, direction: "egress" }, extension: EGRESS.enforcement!.extension, mode: "ENFORCE", scope: "shared" };
    const { merged } = staged([e]);
    expect(line(merged.edges, hd.name, hrd.name)).toMatchObject({ pending: "change", before: "would_deny", verdict: "blocked", intents: ["e"] });
    expect(merged.nodes.find((n) => n.id === EGRESS.name)!.pending?.text).toEqual(["Dry run → Enforce (staged)"]);
    // an allowed line only changes its mode: not marked
    expect(line(merged.edges, hd.name, dest("Knowledge Base Agent").name)?.pending).toBeUndefined();
    // the count shows it once (on the gateway), not once per default-deny line
    expect(pendingCount(merged)).toBe(0);
  });

  it("Model Armor on (ingress): unscreened lines become screened; off shows on the gateway", () => {
    const on: Intent = { id: "on", kind: "model_armor_on", gateway: { name: INGRESS.name, direction: "ingress" } };
    const { merged } = staged([on], "ingress");
    expect(merged.edges.find((x) => x.id === `i:${INGRESS.name}|${hd.name}`)).toMatchObject({ pending: "change", before: "unscreened", verdict: "screened", intents: ["on"] });
    expect(merged.nodes.find((n) => n.id === INGRESS.name)!.pending).toEqual({ text: ["Model Armor on (staged)"], intents: ["on"], shield: { to: "on", template: "corp-agent-shield" } });
    const off: Intent = { id: "off", kind: "model_armor_off", gateway: { name: EGRESS.name, direction: "egress" } };
    expect(staged([off]).merged.nodes.find((n) => n.id === EGRESS.name)!.pending?.text).toEqual(["Model Armor off (staged)"]);
  });

});

describe("diff: Client-to-Agent (§6.3)", () => {
  /** us-east4 with Model Armor on for corp-ingress today. */
  const screenedState = (): MapState => {
    const s = structuredClone(state);
    const m = s.modelArmor!.gateways.find((g) => g.gateway === INGRESS.name)!;
    m.enabled = true;
    m.template = s.modelArmor!.templates[0];
    return s;
  };
  const stagedFrom = (st: MapState, cart: Intent[]) => {
    const sim = simulate(st, cart);
    const before = buildPolicyGraph({ inventory: st.inventory, gateways: st.gateways, modelArmor: st.modelArmor, direction: "ingress", ctx: CTX });
    const after = buildPolicyGraph({ inventory: sim.inventory, gateways: sim.gateways, modelArmor: sim.modelArmor, direction: "ingress", ctx: CTX });
    return mergeStaged(before, after, diffGraphs(before, after), cart, st.inventory, sim.effects);
  };

  it("Model Armor off: screened lines become unscreened; the gateway keeps a pending shield with today's template", () => {
    const off: Intent = { id: "off", kind: "model_armor_off", gateway: { name: INGRESS.name, direction: "ingress" } };
    const merged = stagedFrom(screenedState(), [off]);
    expect(merged.edges.find((x) => x.id === `i:${INGRESS.name}|${hd.name}`)).toMatchObject({ pending: "change", before: "screened", verdict: "unscreened", intents: ["off"] });
    expect(merged.edges.find((x) => x.id === `i:client:any|${INGRESS.name}|${hd.name}`)).toMatchObject({ pending: "change", before: "screened", verdict: "unscreened", intents: ["off"] });
    const gw = merged.nodes.find((n) => n.id === INGRESS.name)!;
    expect(gw.modelArmor?.enabled).toBe(false);
    expect(gw.pending).toEqual({ text: ["Model Armor off (staged)"], intents: ["off"], shield: { to: "off", template: "corp-agent-shield" } });
  });

  it("bind for ingress: the agent's direct line moves into the gateway lane (one pending change)", () => {
    const b: Intent = { id: "b", kind: "bind_gateway", engine: travel.name, gateway: { name: INGRESS.name, direction: "ingress" } };
    const { merged } = staged([b], "ingress");
    const mine = merged.edges.filter((e) => e.caller === travel.name);
    // its line from the gateway, and the client's line into its lane: one pending change each
    expect(mine).toHaveLength(2);
    expect(mine.find((e) => e.source === INGRESS.name)).toMatchObject({ id: `i:${INGRESS.name}|${travel.name}`, pending: "change", before: "direct", verdict: "unscreened", intents: ["b"] });
    expect(mine.find((e) => e.source === "client:any")).toMatchObject({ id: `i:client:any|${INGRESS.name}|${travel.name}`, pending: "change", before: "direct", verdict: "unscreened", intents: ["b"] });
    expect(merged.nodes.find((n) => n.id === travel.name)!.pending).toEqual({ text: ["Binding to corp-ingress staged"], intents: ["b"] });
    // no other agent's lines change
    expect(merged.edges.some((e) => e.pending && e.caller !== travel.name)).toBe(false);
  });

  it("unbind for ingress: the agent leaves the lane; screened today, direct after", () => {
    const u: Intent = { id: "u", kind: "unbind_gateway", engine: hd.name, gateway: { name: INGRESS.name, direction: "ingress" } };
    const merged = stagedFrom(screenedState(), [u]);
    expect(merged.edges.filter((e) => e.caller === hd.name && e.source === NOGW.ingress)).toEqual([expect.objectContaining({ id: `i:${NOGW.ingress}|${hd.name}`, pending: "change", before: "screened", verdict: "direct", intents: ["u"] })]);
    expect(merged.edges.find((e) => e.caller === hd.name && e.source === "client:any")).toMatchObject({ target: NOGW.ingress, pending: "change", intents: ["u"] });
    expect(merged.nodes.find((n) => n.id === hd.name)!.pending?.text).toEqual(["Unbinding from corp-ingress staged"]);
    // with Model Armor off staged too, the unbind alone is behind the agent's line (it leaves the gateway)
    const off: Intent = { id: "off", kind: "model_armor_off", gateway: { name: INGRESS.name, direction: "ingress" } };
    const both = stagedFrom(screenedState(), [off, u]);
    expect(both.edges.filter((e) => e.caller === hd.name).map((e) => e.intents)).toEqual([["u"], ["u"]]);
    expect(both.edges.find((e) => e.caller === hr.name && e.source === INGRESS.name)).toMatchObject({ pending: "change", verdict: "unscreened", intents: ["off"] });
    // an egress unbind of the same agent doesn't touch this view
    const ue: Intent = { id: "ue", kind: "unbind_gateway", engine: hd.name, gateway: { name: EGRESS.name, direction: "egress" } };
    expect(staged([ue], "ingress").merged.edges.some((e) => e.pending)).toBe(false);
  });
});

describe("diff: views", () => {
  it("Changes only: just the pending lines, the trunks to them, and their nodes (with no selection, of the agents they change)", () => {
    const g: Intent = { id: "g", kind: "grant", source: src(), destination: dst(hrd), access: { mode: "read_only_hint" } };
    const merged = staged([g]).merged;
    const v = viewOf(merged, DEFAULT_FILTERS, [], { changesOnly: true });
    expect(v.agents).toEqual([hd.name]);
    expect(v.edges.filter((e) => e.verdict !== "path").every((e) => e.pending)).toBe(true);
    expect(v.edges.some((e) => e.id === `trunk:${hd.name}`)).toBe(true);
    expect(new Set(v.nodes.map((n) => n.id))).toEqual(new Set(v.edges.flatMap((e) => [e.source, e.target])));
    // another agent selected: only its changes (none)
    expect(viewOf(merged, DEFAULT_FILTERS, [hr.name], { changesOnly: true }).edges).toEqual([]);
    expect(pendingCount(merged)).toBe(1);
  });
});
