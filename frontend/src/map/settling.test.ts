// The map's clock markers for applies still settling (map/settling.ts): which lines and nodes an applied intent
// changed, on the mock world's graph after the change, and the tooltip each one gets.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Ctx, Intent } from "../api/types";
import { markText, settleEntry } from "../lib/settling";
import { buildPolicyGraph, type Direction } from "./graph";
import { simulate } from "./simulate";
import { lineMatches, nodeMatches, settlingMarks } from "./settling";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const w0 = buildWorld(CTX);
const inv = w0.inventory;
const eng = (name: string) => inv.engines.find((e) => e.display_name === name)!;
const dest = (name: string) => [...inv.agents, ...inv.mcp_servers, ...inv.endpoints].find((d) => d.display_name === name)!;
const EGRESS = w0.gateways.find((g) => g.type === "egress")!;
const hd = eng("Helpdesk Agent");
const travel = eng("Travel Planner");
const hrd = dest("HR Directory MCP");
const T0 = Date.UTC(2026, 9, 14, 15, 31, 0);

const grant: Intent = { id: "g", kind: "grant", source: { type: "engine", principal: hd.principal, label: hd.display_name, engine: hd.name }, destination: { kind: "mcp_server", id: hrd.id, name: hrd.name, label: hrd.display_name }, access: { mode: "tools", tools: ["lookup_employee"] } };
const bind: Intent = { id: "b", kind: "bind_gateway", engine: travel.name, gateway: { name: EGRESS.name, direction: "egress" } };
const enforce: Intent = { id: "e", kind: "set_enforcement", gateway: { name: EGRESS.name, direction: "egress" }, extension: EGRESS.enforcement!.extension, mode: "ENFORCE", scope: "dedicated" };

/** The graph once the intents are applied (as the map draws it after Sync). */
function after(intents: Intent[], direction: Direction = "egress") {
  const s = simulate({ inventory: inv, gateways: w0.gateways, modelArmor: w0.modelArmor }, intents);
  return buildPolicyGraph({ inventory: s.inventory, gateways: s.gateways, modelArmor: s.modelArmor, ctx: CTX, direction });
}
const applied = (intents: Intent[], endedAt = T0) => settleEntry({ id: `run-${endedAt}`, project: CTX.project, region: CTX.region, startedAt: endedAt - 1000, endedAt, done: true, items: intents.map((intent) => ({ intent, state: "verified" as const, undo: [] })) })!;

describe("settling marks on the map", () => {
  it("a grant marks the agent's line into the destination, nothing else", () => {
    const g = after([grant]);
    const e = applied([grant]);
    const m = settlingMarks(g.edges, g.nodes, [e]);
    expect([...m.edges.keys()]).toEqual([`a:${hd.name}|${hrd.name}`]);
    expect(m.edges.get(`a:${hd.name}|${hrd.name}`)).toBe(`${markText(e)} Tools: lookup_employee.`);
    expect(m.nodes.size).toBe(0);
  });

  it("a bind marks the agent's node and its lane (trunk), not its grant lines", () => {
    const g = after([bind]);
    const m = settlingMarks(g.edges, g.nodes, [applied([bind])]);
    expect([...m.nodes.keys()]).toEqual([travel.name]);
    expect([...m.edges.keys()]).toEqual([`trunk:${travel.name}`]);
  });

  it("grant + bind in one apply: both, with one tooltip", () => {
    const g = after([grant, bind]);
    const e = applied([grant, bind]);
    const m = settlingMarks(g.edges, g.nodes, [e]);
    expect(new Set(m.edges.keys())).toEqual(new Set([`a:${hd.name}|${hrd.name}`, `trunk:${travel.name}`]));
    expect(m.nodes.get(travel.name)).toBe(markText(e));
  });

  it("an enforcement change marks the gateway node", () => {
    const g = after([enforce]);
    const m = settlingMarks(g.edges, g.nodes, [applied([enforce])]);
    expect([...m.nodes.keys()]).toEqual([EGRESS.name]);
    expect(m.edges.size).toBe(0);
  });

  it("a revoke still marks the line (now a default-deny line)", () => {
    const revoke: Intent = { ...grant, id: "r", kind: "revoke" };
    const g = after([grant]);
    const deny = g.edges.find((x) => x.caller === hd.name && x.target === hrd.name)!;
    expect(lineMatches(applied([revoke]).targets[0], { ...deny, id: `x:${hd.name}|${hrd.name}`, implicit: true, reasons: [] })).toBe(true);
  });

  it("the newest apply's text wins on a line both changed; another direction's lines aren't matched", () => {
    const old = applied([grant], T0 - 60_000);
    const fresh = applied([grant], T0);
    const g = after([grant]);
    expect(settlingMarks(g.edges, g.nodes, [fresh, old]).edges.get(`a:${hd.name}|${hrd.name}`)).toContain(markText(fresh));
    const ing = after([bind], "ingress");
    // an egress bind doesn't touch the agent's Client-to-Agent lines
    expect(settlingMarks(ing.edges, ing.nodes, [applied([bind])]).edges.size).toBe(0);
  });

  it("matching by hand: another agent, destination or engine doesn't match", () => {
    const t = applied([grant]).targets[0];
    const base = { id: "a:x|y", source: EGRESS.name, direction: "egress" as const, verdict: "allowed" as const, reasons: [] };
    expect(lineMatches(t, { ...base, caller: hd.name, target: hrd.name })).toBe(true);
    expect(lineMatches(t, { ...base, caller: travel.name, target: hrd.name })).toBe(false);
    expect(lineMatches(t, { ...base, caller: hd.name, target: "other" })).toBe(false);
    // a line grouped into "Google APIs" that holds the destination
    expect(lineMatches(t, { ...base, caller: hd.name, target: "group:google", members: [{ ...base, caller: hd.name, target: hrd.name }] })).toBe(true);
    // a trunk is never a grant's line
    expect(lineMatches(t, { ...base, caller: hd.name, target: hrd.name, verdict: "path" })).toBe(false);
    const b = applied([bind]).targets[0];
    expect(nodeMatches(b, { id: travel.name } as never)).toBe(true);
    expect(nodeMatches(b, { id: hd.name } as never)).toBe(false);
  });

  it("a member that isn't an engine is matched through its pseudo caller", () => {
    const pub: Intent = { ...grant, source: { type: "custom", principal: "allUsers", label: "Everyone" } };
    const t = applied([pub]).targets[0];
    expect(lineMatches(t, { id: "p:pseudo:public|d", source: "pseudo:public", caller: "pseudo:public", target: hrd.name, direction: "egress", verdict: "allowed", reasons: [] })).toBe(true);
  });

  it("nothing settling: no marks", () => {
    const g = after([]);
    const m = settlingMarks(g.edges, g.nodes, []);
    expect(m.edges.size + m.nodes.size).toBe(0);
  });
});
