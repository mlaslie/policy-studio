// The scale scenario (docs/VISUALIZATION_PLAN.md §7, §11.5–11.6): the mock's us-west1 region, generated from a seeded
// PRNG. Its size, its gateways, and the §7 budget: the graph (every agent's own lines) builds in under 50 ms; with no
// agent selected the map has no lines, one selected agent stays under the 400-line banner, every agent goes past it.
import { afterEach, describe, expect, it, vi } from "vitest";
import { MOCK_NUMBER, buildWorld } from "../api/mockData";
import { SCALE, scaleFactor } from "../api/mockScale";
import type { Ctx } from "../api/types";
import { buildPolicyGraph, type Direction } from "./graph";
import { layoutView } from "./layout";
import { DEFAULT_FILTERS, DENY_CAP, TOO_MANY_LINES, viewOf } from "./view";

const CTX: Ctx = { project: "my-demo-project", region: "us-west1" };
const w = buildWorld(CTX);
const inv = w.inventory;
const build = (direction: Direction, world = w) => buildPolicyGraph({ inventory: world.inventory, gateways: world.gateways, modelArmor: world.modelArmor, direction });
const bindings = (x = inv) => Object.values(x.access).reduce((n, bs) => n + bs.length, 0);
/** The fastest of a few runs (the first warms up the JIT). */
function timed<T>(f: () => T, runs = 5): { ms: number; out: T } {
  let best = Infinity;
  let out!: T;
  for (let i = 0; i < runs; i++) {
    const t = performance.now();
    out = f();
    best = Math.min(best, performance.now() - t);
  }
  return { ms: best, out };
}

afterEach(() => vi.unstubAllGlobals());

describe("us-west1: the scale scenario", () => {
  it("has about 50 agents, 15 MCP servers, 100 endpoints and 500 grants, named agent-017 and so on", () => {
    expect(inv.engines).toHaveLength(SCALE.engines);
    expect(inv.mcp_servers).toHaveLength(SCALE.mcp);
    expect(inv.endpoints).toHaveLength(SCALE.endpoints);
    expect(bindings()).toBe(SCALE.bindings);
    expect(inv.engines.some((e) => e.display_name === "agent-017")).toBe(true);
    // everything under the context's project (engines by its number, as Agent Runtime names them)
    for (const e of inv.engines) expect(e.name.startsWith(`projects/${MOCK_NUMBER}/locations/us-west1/`)).toBe(true);
    for (const d of [...inv.agents, ...inv.mcp_servers, ...inv.endpoints]) expect(d.name.startsWith("projects/my-demo-project/locations/us-west1/")).toBe(true);
    for (const g of w.gateways) expect(g.name.startsWith("projects/my-demo-project/locations/us-west1/")).toBe(true);
  });

  it("is the same world on every build (seeded)", () => {
    expect(JSON.stringify(buildWorld(CTX).inventory)).toBe(JSON.stringify(inv));
  });

  it("has two egress gateways, one in dry run; corp-ingress screens with Model Armor, partner-ingress doesn't", () => {
    const egress = w.gateways.filter((g) => g.type === "egress");
    expect(egress.map((g) => [g.id, g.enforcement?.mode])).toEqual([
      ["corp-egress", "DRY_RUN"],
      ["west-egress", "ENFORCE"],
    ]);
    expect(egress.every((g) => g.bound_engines.length > 10)).toBe(true);
    const g = build("ingress");
    const verdicts = new Set(g.edges.map((e) => e.verdict));
    expect([...verdicts].sort()).toEqual(["direct", "screened", "unscreened"]);
    expect(g.nodes.find((n) => n.label === "corp-ingress")?.modelArmor).toMatchObject({ enabled: true, template: "corp-agent-shield" });
  });

  it("other regions are unchanged", () => {
    expect(buildWorld({ ...CTX, region: "us-east4" }).inventory.engines).toHaveLength(5);
  });
});

describe("us-west1: the §7 budget", () => {
  it("builds the graph in under 50 ms; view and layout in under 50 ms more", () => {
    const g = timed(() => build("egress"));
    expect(g.ms).toBeLessThan(50);
    const v = timed(() => {
      const view = viewOf(g.out, DEFAULT_FILTERS, []);
      return { view, layout: layoutView(view) };
    });
    expect(v.ms).toBeLessThan(50);
    expect(Object.keys(v.out.layout.pos)).toHaveLength(v.out.view.nodes.length);
    // one agent selected (agent-017) too
    const agent = inv.engines.find((e) => e.display_name === "agent-017")!;
    const one = timed(() => {
      const view = viewOf(g.out, DEFAULT_FILTERS, [agent.name]);
      return { view, layout: layoutView(view) };
    });
    expect(one.ms).toBeLessThan(50);
    expect(one.out.view.agents).toEqual([agent.name]);
  });

  it("lines only for the selected agents: none by default, one agent under the banner, every agent past it", () => {
    const g = build("egress");
    expect(viewOf(g, DEFAULT_FILTERS, []).lines).toBe(0);
    const behind = inv.engines.filter((e) => e.gateways.egress);
    const one = viewOf(g, DEFAULT_FILTERS, [behind[0].name]);
    expect(one.lines).toBeGreaterThan(0);
    expect(one.lines).toBeLessThanOrEqual(TOO_MANY_LINES);
    const all = viewOf(g, DEFAULT_FILTERS, inv.engines.map((e) => e.name));
    expect(all.lines).toBeGreaterThan(TOO_MANY_LINES);
    // Allows only: much fewer
    expect(viewOf(g, { ...DEFAULT_FILTERS, denies: false }, inv.engines.map((e) => e.name)).lines).toBeLessThan(all.lines / 2);
  });

  it("wraps the callers into sub-columns, so the map is about as tall as its destination column", () => {
    const v = viewOf(build("egress"), DEFAULT_FILTERS, []);
    const { pos, size } = layoutView(v);
    const span = (ids: string[]) => Math.max(...ids.map((id) => pos[id].y + size[id].h)) - Math.min(...ids.map((id) => pos[id].y));
    const callers = v.nodes.filter((n) => n.column === "callers").map((n) => n.id);
    const dests = v.nodes.filter((n) => n.column === "dests").map((n) => n.id);
    expect(new Set(callers.map((id) => pos[id].x)).size).toBeGreaterThan(1);
    expect(span(callers)).toBeLessThan(span(dests) * 1.25);
    // gateways stay to the right of every caller
    const gw = v.nodes.filter((n) => n.kind === "gateway").map((n) => pos[n.id].x);
    expect(Math.min(...gw)).toBeGreaterThan(Math.max(...callers.map((id) => pos[id].x + size[id].w)));
  });

  it("caps each selected agent's default-deny lines", () => {
    const behind = inv.engines.filter((e) => e.display_name.startsWith("agent-") && e.gateways.egress).slice(0, 2);
    const v = viewOf(build("egress"), { ...DEFAULT_FILTERS, googleApis: true }, behind.map((e) => e.name));
    for (const e of behind) expect(v.edges.filter((x) => x.implicit && x.caller === e.name)).toHaveLength(DENY_CAP);
    expect(v.more).toBeGreaterThan(0);
  });

  it("?scale=2 doubles it, past the banner; one gateway brings it back under", () => {
    expect(scaleFactor("?scale=2")).toBe(2);
    expect(scaleFactor("?scale=9")).toBe(1);
    expect(scaleFactor("")).toBe(1);
    vi.stubGlobal("window", { location: { search: "?scale=2" } });
    const big = buildWorld(CTX);
    expect(big.inventory.engines).toHaveLength(2 * SCALE.engines);
    expect(bindings(big.inventory)).toBe(2 * SCALE.bindings);
    const g = timed(() => build("egress", big), 3);
    expect(g.ms).toBeLessThan(100);
    expect(viewOf(g.out, DEFAULT_FILTERS, []).lines).toBe(0);
    expect(viewOf(g.out, DEFAULT_FILTERS, [big.inventory.engines.find((e) => e.gateways.egress)!.name]).lines).toBeLessThanOrEqual(TOO_MANY_LINES);
  });
});
