// What the policy panel stages (§9), saved positions (§7) and "Show on map" focus (§2), over the mock world.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Ctx, Engine } from "../api/types";
import { READ_ONLY_EXPR, intentKey } from "../lib/policy";
import { CLIENT, NOGW, PSEUDO, buildPolicyGraph, type PEdge } from "./graph";
import { allowFor, bindFor, ingressInfo, limitToAgent, modifyFor, reachedBy, revokeFor, sameAccess } from "./actions";
import { simulate } from "./simulate";
import { loadPins, placeNodes, posKey, savePins, type PinStore } from "./usePositions";
import { findFocusEdge, focusForGateway, focusForGrant, focusForIntent } from "./focus";
import { DEFAULT_FILTERS, viewOf } from "./view";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const w0 = buildWorld(CTX);
const inv = w0.inventory;
const byP = new Map<string, Engine>(inv.engines.map((e) => [e.principal, e]));
const eng = (name: string) => inv.engines.find((e) => e.display_name === name)!;
const dest = (name: string) => [...inv.agents, ...inv.mcp_servers, ...inv.endpoints].find((d) => d.display_name === name)!;
const hd = eng("Helpdesk Agent");
const hr = eng("HR Assistant");
const tickets = dest("Tickets MCP");
const graph = (w = w0) => buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "egress" });
const line = (ls: PEdge[], caller: string, target: string) => ls.find((l) => l.caller === caller && l.target === target)!;

describe("panel actions: revoke and change access", () => {
  const r = line(graph().edges, hd.name, tickets.name).reasons[0];

  it("Revoke carries the binding's exact condition", () => {
    const i = revokeFor(r, byP);
    expect(i).toMatchObject({ kind: "revoke", source: { type: "engine", principal: hd.principal, engine: hd.name }, destination: { kind: "mcp_server", id: tickets.id, name: tickets.name } });
    expect(i.access).toEqual({ mode: "custom", expression: r.binding.condition!.expression, title: r.binding.condition!.title });
    // and the simulated cart removes exactly that binding
    expect(simulate({ inventory: inv, gateways: w0.gateways }, [i]).inventory.access[tickets.name].some((b) => b.member === hd.principal)).toBe(false);
  });

  it("Change access is one modify from the exact condition; the current access isn't a change", () => {
    const m = modifyFor(r, byP, { mode: "tools", tools: ["get_ticket"] });
    expect(m.kind).toBe("modify");
    expect(m.access_from).toEqual({ mode: "custom", expression: r.binding.condition!.expression, title: r.binding.condition!.title });
    expect(m.access).toEqual({ mode: "tools", tools: ["get_ticket"] });
    expect(sameAccess(r, { mode: "read_only_hint" })).toBe(true);
    expect(sameAccess(r, { mode: "all" })).toBe(false);
    expect(intentKey(m)).not.toBe(intentKey(revokeFor(r, byP)));
  });

  it("an unconditional grant: revoke without a condition, modify from mode all", () => {
    const kb = line(graph().edges, hd.name, dest("Knowledge Base Agent").name).reasons.find((x) => x.binding.member === hd.principal)!;
    expect(revokeFor(kb, byP).access).toEqual({ mode: "all" });
    expect(modifyFor(kb, byP, { mode: "read_only_hint" }).access_from).toEqual({ mode: "all" });
  });
});

describe("Limit to this agent instead", () => {
  const vertex = dest("Vertex AI API");
  const r = line(graph().edges, hd.name, vertex.name).reasons.find((x) => x.via === "project_agents")!;

  it("is a grant for this agent with the same access plus the revoke of the group binding", () => {
    const [grant, revoke] = limitToAgent(r, hd, byP);
    expect(grant).toMatchObject({ kind: "grant", source: { type: "engine", principal: hd.principal, label: "Helpdesk Agent", engine: hd.name }, destination: { kind: "endpoint", name: vertex.name }, access: { mode: "all" } });
    expect(revoke).toMatchObject({ kind: "revoke", source: { type: "project_agents", principal: r.binding.member }, destination: { name: vertex.name }, access: { mode: "all" } });
    expect(reachedBy(r.binding.member, inv.engines).length).toBeGreaterThan(1);
  });

  it("applied: this agent keeps the access, the others lose it", () => {
    const sim = simulate({ inventory: inv, gateways: w0.gateways, modelArmor: w0.modelArmor }, limitToAgent(r, hd, byP));
    const w = { ...w0, inventory: sim.inventory, gateways: sim.gateways };
    expect(line(graph(w).edges, hd.name, vertex.name)).toMatchObject({ verdict: "allowed", inherited: false });
    expect(line(graph(w).edges, hr.name, vertex.name)).toMatchObject({ implicit: true });
  });

  it("keeps a condition: a read-only group grant stays read-only for the agent", () => {
    const ro = { ...r, binding: { ...r.binding, condition: { title: "ro", expression: READ_ONLY_EXPR } }, resourceKind: "mcp_server" as const, resource: tickets.name };
    expect(limitToAgent(ro, hd, byP)[0].access).toEqual({ mode: "read_only_hint" });
    expect(limitToAgent(ro, hd, byP)[1].access).toEqual({ mode: "custom", expression: READ_ONLY_EXPR, title: "ro" });
  });
});

describe("Allow… and Bind", () => {
  it("Allow… stages a grant from the agent to the destination node", () => {
    const n = graph().nodes.find((x) => x.id === dest("HR Directory MCP").name)!;
    expect(allowFor(hd, n, { mode: "read_only_hint" })).toMatchObject({ kind: "grant", source: { engine: hd.name }, destination: { kind: "mcp_server", id: n.id.split("/").pop(), name: n.id, label: "HR Directory MCP" }, access: { mode: "read_only_hint" } });
  });

  it("Bind stages bind_gateway on egress", () => {
    const t = eng("Travel Planner");
    const g = w0.gateways.find((x) => x.type === "egress")!;
    expect(bindFor(t, g)).toMatchObject({ kind: "bind_gateway", engine: t.name, engine_label: "Travel Planner", gateway: { name: g.name, direction: "egress" } });
  });
});

describe("Client-to-Agent line actions (§6.3)", () => {
  const INGRESS = w0.gateways.find((g) => g.type === "ingress")!;
  // as /model-armor sends it: the region's Model Armor extensions alongside the gateways
  const maResp = (w = w0) => ({ ...w.modelArmor, extensions: w.maExtensions });
  const ing = (w = w0) => buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "ingress" });
  const lineId = (id: string, w = w0) => ing(w).edges.find((e) => e.id === id)!;
  const travel = eng("Travel Planner");
  const psc = eng("simple-agent-with-psc");
  const ops = eng("Ops Copilot");

  it("an unscreened line: Model Armor on, Unbind for its agent, the IAP policy as configured", () => {
    const info = ingressInfo(lineId(`i:${INGRESS.name}|${hd.name}`), inv, w0.gateways, maResp());
    expect(info.gateway?.name).toBe(INGRESS.name);
    expect(info.ma?.enabled).toBe(false);
    expect(info.maAction).toMatchObject({ kind: "on", intent: { kind: "model_armor_on", gateway: { name: INGRESS.name, direction: "ingress" } } });
    expect(info.bound.map((b) => b.unbind)).toEqual([expect.objectContaining({ kind: "unbind_gateway", engine: hd.name, engine_label: "Helpdesk Agent", gateway: { name: INGRESS.name, direction: "ingress" } })]);
    expect(info.unbound).toEqual([]);
    expect(info.iap).toMatchObject({ provider: "iap", profile: "REQUEST_AUTHZ", enforcement: "DRY_RUN" });
  });

  it("a screened line: Model Armor off (a destructive kind)", () => {
    const w = buildWorld(CTX);
    const m = w.modelArmor.gateways.find((g) => g.gateway === INGRESS.name)!;
    m.enabled = true;
    m.template = w.modelArmor.templates[0];
    const e = lineId(`i:${INGRESS.name}|${hd.name}`, w);
    expect(e.verdict).toBe("screened");
    const info = ingressInfo(e, w.inventory, w.gateways, maResp(w));
    expect(info.maAction).toMatchObject({ kind: "off", intent: { kind: "model_armor_off", gateway: { name: INGRESS.name, direction: "ingress" } } });
    expect(info.ma?.template?.summary?.length).toBeGreaterThan(0);
  });

  it("a client's line into an agent's lane: that agent; a lane-wide line (no agent) lists every agent in it", () => {
    const own = lineId(`i:${CLIENT.any}|${INGRESS.name}|${hd.name}`);
    expect(ingressInfo(own, inv, w0.gateways, maResp()).bound.map((b) => b.engine.display_name)).toEqual(["Helpdesk Agent"]);
    const lane = { ...own, id: "lane", caller: undefined };
    expect(ingressInfo(lane, inv, w0.gateways, maResp()).bound.map((b) => b.engine.display_name).sort()).toEqual(["HR Assistant", "Helpdesk Agent"]);
  });

  it("no ingress gateway: Bind for each agent (the unbindable one with its reason), no Model Armor action", () => {
    const lane = { ...lineId(`i:${CLIENT.any}|${NOGW.ingress}|${travel.name}`), id: "lane", caller: undefined };
    const info = ingressInfo(lane, inv, w0.gateways, maResp());
    expect(info.gateway).toBeNull();
    expect(info.maAction).toBeNull();
    expect(info.unbound.map((u) => [u.engine.name, u.why === null])).toEqual([
      [travel.name, true],
      [psc.name, false],
      [ops.name, false],
    ]);
    expect(bindFor(travel, INGRESS, "ingress")).toMatchObject({ kind: "bind_gateway", engine: travel.name, gateway: { name: INGRESS.name, direction: "ingress" } });
    // one agent's own direct line: just that agent
    expect(ingressInfo(lineId(`i:${NOGW.ingress}|${travel.name}`), inv, w0.gateways, maResp()).unbound.map((u) => u.engine.name)).toEqual([travel.name]);
  });

  it("no Model Armor extension in the region (us-central1): Set up Model Armor instead of Turn on", () => {
    const w = buildWorld({ ...CTX, region: "us-central1" });
    const gw = w.gateways.find((g) => g.type === "ingress")!;
    const helpdesk = w.inventory.engines.find((e) => e.display_name === "Helpdesk Agent")!;
    const info = ingressInfo(lineId(`i:${CLIENT.any}|${gw.name}|${helpdesk.name}`, w), w.inventory, w.gateways, maResp(w));
    expect(info.maAction).toEqual({ kind: "setup" });
    expect(info.iap).toBeNull();
  });
});

describe("saved positions", () => {
  const fake = (init: Record<string, string> = {}) => {
    const m = new Map(Object.entries(init));
    const s: PinStore & { m: Map<string, string> } = { m, getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) };
    return s;
  };
  const key = posKey("my-demo-project", "us-east4", "egress");

  it("is keyed per project, region and direction", () => {
    expect(key).toBe("studio.map.v1:my-demo-project:us-east4:egress");
    expect(posKey("my-demo-project", "us-east4", "ingress")).not.toBe(key);
  });

  it("pinned nodes stay put; the rest take the auto layout", () => {
    const auto = { a: { x: 0, y: 0 }, b: { x: 10, y: 10 } };
    expect(placeNodes(auto, { a: { x: 500, y: 40 } })).toEqual({ a: { x: 500, y: 40 }, b: { x: 10, y: 10 } });
    // a pin for a node that isn't drawn now (filtered out) is kept, not drawn
    expect(placeNodes({ b: auto.b }, { a: { x: 1, y: 1 } })).toEqual({ b: auto.b });
  });

  it("unknown ids (and junk) are dropped on load, and the key is rewritten", () => {
    const s = fake({ [key]: JSON.stringify({ a: { x: 1, y: 2 }, gone: { x: 3, y: 4 }, bad: { x: "?" } }) });
    expect(loadPins(s, key, (id) => id === "a" || id === "bad")).toEqual({ a: { x: 1, y: 2 } });
    expect(JSON.parse(s.m.get(key)!)).toEqual({ a: { x: 1, y: 2 } });
    expect(loadPins(fake({ [key]: "not json" }), key, () => true)).toEqual({});
    expect(loadPins(null, key, () => true)).toEqual({});
  });

  it("reset clears the key; storage errors are swallowed", () => {
    const s = fake();
    savePins(s, key, { a: { x: 1, y: 2 } });
    expect(s.m.has(key)).toBe(true);
    savePins(s, key, {});
    expect(s.m.has(key)).toBe(false);
    const broken: PinStore = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("full"); }, removeItem: () => undefined };
    expect(() => savePins(broken, key, { a: { x: 1, y: 1 } })).not.toThrow();
    expect(loadPins(broken, key, () => true)).toEqual({});
  });
});

describe("Show on map focus", () => {
  it("a grant of an agent focuses the agent and its line to the resource", () => {
    const g = w0.audit().grants.find((x) => x.member === hd.principal && x.resource === tickets.name)!;
    const f = focusForGrant(g, inv);
    expect(f).toEqual({ direction: "egress", node: hd.name, target: tickets.name });
    const v = viewOf(graph(), DEFAULT_FILTERS, [hd.name]);
    expect(findFocusEdge(v.edges, f)).toMatchObject({ id: `a:${hd.name}|${tickets.name}`, caller: hd.name });
  });

  it("a group or public grant focuses its pseudo caller's line", () => {
    const g = w0.audit().grants.find((x) => x.member === "allAuthenticatedUsers")!;
    const f = focusForGrant(g, inv);
    expect(f.node).toBe(PSEUDO.public);
    const v = viewOf(graph(), DEFAULT_FILTERS, [f.node!]);
    expect(findFocusEdge(v.edges, f)?.id).toBe(`p:${PSEUDO.public}|${g.resource}`);
  });

  it("a default-deny line is found when there's no grant (the granted line first)", () => {
    const hrd = dest("HR Directory MCP").name;
    const v = viewOf(graph(), DEFAULT_FILTERS, [hd.name]);
    expect(findFocusEdge(v.edges, { node: hd.name, target: hrd })).toMatchObject({ implicit: true });
  });

  it("cart items: grants by caller and destination, binds by engine and direction, gateway changes by gateway", () => {
    const ingress = w0.gateways.find((g) => g.type === "ingress")!;
    expect(focusForIntent({ id: "r", kind: "revoke", source: { type: "engine", principal: hd.principal, label: "", engine: hd.name }, destination: { kind: "mcp_server", id: tickets.id, name: tickets.name, label: "" } }, inv)).toEqual({ direction: "egress", node: hd.name, target: tickets.name });
    expect(focusForIntent({ id: "b", kind: "bind_gateway", engine: hd.name, gateway: { name: ingress.name, direction: "ingress" } }, inv)).toEqual({ direction: "ingress", node: hd.name });
    expect(focusForIntent({ id: "m", kind: "model_armor_on", gateway: { name: ingress.name, direction: "ingress" } }, inv)).toEqual({ direction: "ingress", node: ingress.name });
    expect(focusForIntent({ id: "t", kind: "model_armor_template" }, inv)).toBeNull();
    expect(focusForGateway(ingress)).toEqual({ direction: "ingress", node: ingress.name });
  });
});
