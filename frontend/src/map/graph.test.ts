// buildPolicyGraph over the mock world (docs/VISUALIZATION_PLAN.md §4.4, §6.3, §14): one check per egress case, the
// selected-agent view, the filters and the layout.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Binding, Ctx, Gateway } from "../api/types";
import { ROLE } from "../lib/policy";
import { CLIENT, NOGW, PSEUDO, buildPolicyGraph, type Direction, type GraphInput, type PEdge } from "./graph";
import { DEFAULT_DIRECTION, DEFAULT_FILTERS, IMPLICIT_CAP, tableRows, viewOf, type MapFilters } from "./view";
import { WRAP, layoutView } from "./layout";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const world = (ctx: Ctx = CTX) => buildWorld(ctx); // a fresh world each call
const input = (w: ReturnType<typeof world>, direction: Direction = "egress", extra: Partial<GraphInput> = {}): GraphInput => ({
  inventory: w.inventory,
  gateways: w.gateways,
  modelArmor: w.modelArmor,
  direction,
  ...extra,
});

const w0 = world();
const inv = w0.inventory;
const eng = (name: string) => inv.engines.find((e) => e.display_name === name)!;
const dest = (name: string) => [...inv.agents, ...inv.mcp_servers, ...inv.endpoints].find((d) => d.display_name === name)!;
const EGRESS = w0.gateways.find((g) => g.type === "egress")!.name;
const INGRESS = w0.gateways.find((g) => g.type === "ingress")!.name;
const REG = Object.keys(inv.access).find((k) => /^projects\/[^/]+\/locations\/[^/]+$/.test(k))!;
const edge = (es: PEdge[], id: string) => es.find((e) => e.id === id);
const filters = (f: Partial<MapFilters> = {}): MapFilters => ({ ...DEFAULT_FILTERS, ...f });

describe("egress verdicts (§4.4), us-east4: corp-egress in dry run", () => {
  const g = buildPolicyGraph(input(w0));
  const combined = (d: string) => edge(g.edges, `c:${EGRESS}|${dest(d).name}`);

  it("an unconditional grant: allowed, through the agent's gateway, with Model Armor", () => {
    const e = combined("Knowledge Base Agent")!;
    expect(e).toMatchObject({ verdict: "allowed", source: EGRESS, mode: "DRY_RUN", modelArmor: true });
    expect(e.parts!.map((p) => p.caller)).toEqual([eng("Helpdesk Agent").name]);
    expect(edge(g.edges, `trunk:${eng("Helpdesk Agent").name}`)).toMatchObject({ verdict: "path", target: EGRESS });
  });

  it("MCP read-only hint and a tools list: partial, combined into one line with a count", () => {
    const e = combined("Tickets MCP")!;
    expect(e.verdict).toBe("partial");
    expect(e.label).toBe("2 agents");
    const hd = e.parts!.find((p) => p.caller === eng("Helpdesk Agent").name)!;
    expect(hd).toMatchObject({ verdict: "partial", label: "read-only" });
    expect(hd.tools!.allowed.sort()).toEqual(["get_ticket", "list_tickets", "search_tickets"]);
    const hr = e.parts!.find((p) => p.caller === eng("HR Assistant").name)!;
    expect(hr).toMatchObject({ verdict: "partial", label: "2/6 tools" });
    expect(hr.tools!.allowed.sort()).toEqual(["create_ticket", "get_ticket"]);
  });

  it("an unconditional grant on an MCP server: allowed (every tool)", () => {
    expect(combined("HR Directory MCP")!.verdict).toBe("allowed");
  });

  it("a custom CEL condition: conditional", () => {
    const e = combined("Billing Agent")!;
    expect(e).toMatchObject({ verdict: "conditional", label: "?" });
  });

  it("an agent with no egress gateway: its grants are dormant, its traffic direct", () => {
    const travel = eng("Travel Planner").name;
    const e = edge(g.edges, `c:${NOGW.egress}|${dest("Calendar Agent").name}`)!;
    expect(e).toMatchObject({ verdict: "dormant", source: NOGW.egress });
    expect(e.parts!.map((p) => p.caller)).toEqual([travel]);
    expect(edge(g.edges, `direct:${travel}`)).toMatchObject({ verdict: "direct", target: NOGW.egress });
    expect(edge(g.edges, "direct:nogw")).toMatchObject({ verdict: "direct", target: PSEUDO.anywhere });
  });

  it("an agent that can't be bound: direct, flagged", () => {
    const psc = g.nodes.find((n) => n.id === eng("simple-agent-with-psc").name)!;
    expect(psc.gateway).toBeNull();
    expect(psc.chips.map((c) => c.text)).toContain("Can't be bound");
    expect(edge(g.edges, `direct:${psc.id}`)?.verdict).toBe("direct");
  });

  it("project-wide principalSet grants: drawn once from All agents in this project", () => {
    for (const d of ["Vertex AI API", "Cloud Logging API", "Telemetry API"])
      expect(edge(g.edges, `p:${PSEUDO.project}|${dest(d).name}`)).toMatchObject({ verdict: "allowed", source: PSEUDO.project });
  });

  it("allAuthenticatedUsers: drawn from Public, flagged red", () => {
    expect(edge(g.edges, `p:${PSEUDO.public}|${dest("Calendar Agent").name}`)?.verdict).toBe("allowed");
    expect(g.nodes.find((n) => n.id === PSEUDO.public)!.chips.some((c) => c.tone === "red")).toBe(true);
  });

  it("a deleted agent, a group and a service account: Other principals, with a deleted-agent chip", () => {
    expect(edge(g.edges, `p:${PSEUDO.other}|${dest("Billing Agent").name}`)?.verdict).toBe("allowed");
    expect(edge(g.edges, `p:${PSEUDO.other}|${dest("Knowledge Base Agent").name}`)?.reasons[0].binding.member).toMatch(/^group:/);
    const other = g.nodes.find((n) => n.id === PSEUDO.other)!;
    expect(other.chips.map((c) => c.text)).toContain("Deleted agent");
    expect(other.members!.length).toBe(3);
  });

  it("a registry-wide grant: drawn once to the Agent Registry node", () => {
    const e = edge(g.edges, `p:${PSEUDO.other}|${REG}`)!;
    expect(e.verdict).toBe("allowed");
    expect(e.reasons[0]).toMatchObject({ resourceKind: "registry", via: "registry_wide" });
    expect(g.nodes.find((n) => n.id === REG)?.kind).toBe("registry");
  });

  it("an unreadable IAP policy: a flagged node and no lines guessed", () => {
    const sql = dest("Cloud SQL Admin API").name;
    expect(g.nodes.find((n) => n.id === sql)?.unreadable).toBeTruthy();
    expect(g.edges.filter((e) => e.target === sql)).toEqual([]);
  });

  it("engine summary chips: inherited reach and would-be-denied count", () => {
    const hd = g.nodes.find((n) => n.id === eng("Helpdesk Agent").name)!;
    expect(hd.inheritedCount).toBe(4); // three project-wide endpoints and the public Calendar Agent
    expect(hd.chips.some((c) => c.text.startsWith("Would be denied:"))).toBe(true);
  });
});

describe("selected agent: inherited and implicit lines", () => {
  const hd = eng("Helpdesk Agent");
  const hr = eng("HR Assistant");
  const focus = (w: ReturnType<typeof world>, e: string, extra: Partial<GraphInput> = {}) => buildPolicyGraph(input(w, "egress", { focus: e, ...extra })).focusLines!;
  const line = (ls: PEdge[], e: string, d: string) => ls.find((l) => l.caller === e && l.target === d);

  it("adds project-wide and public grants as inherited, own grants as not", () => {
    const ls = focus(w0, hd.name);
    expect(line(ls, hd.name, dest("Calendar Agent").name)).toMatchObject({ verdict: "allowed", inherited: true });
    expect(line(ls, hd.name, dest("Vertex AI API").name)).toMatchObject({ verdict: "allowed", inherited: true });
    expect(line(ls, hd.name, dest("Knowledge Base Agent").name)).toMatchObject({ verdict: "allowed", inherited: false });
  });

  it("a group grant is conditional for an agent (membership can't be told here)", () => {
    expect(line(focus(w0, hr.name), hr.name, dest("Knowledge Base Agent").name)).toMatchObject({ verdict: "conditional", inherited: true });
  });

  it("no grant: would_deny under dry run, blocked under enforce, unchecked without an IAP policy", () => {
    const ls = focus(w0, hd.name);
    expect(line(ls, hd.name, dest("HR Directory MCP").name)).toMatchObject({ verdict: "would_deny", implicit: true, reasons: [] });
    const enforce = world({ ...CTX, region: "us-central1" });
    const e2 = enforce.inventory.engines.find((e) => e.display_name === "Helpdesk Agent")!;
    const hrd = enforce.inventory.mcp_servers.find((m) => m.display_name === "HR Directory MCP")!;
    expect(line(focus(enforce, e2.name), e2.name, hrd.name)).toMatchObject({ verdict: "blocked", implicit: true });
    const none = world();
    none.gateways.find((g) => g.type === "egress")!.enforcement!.mode = null;
    expect(line(focus(none, hd.name), hd.name, dest("HR Directory MCP").name)?.verdict).toBe("unchecked");
  });

  it("no implicit line to an unreadable destination", () => {
    expect(line(focus(w0, hd.name), hd.name, dest("Cloud SQL Admin API").name)).toBeUndefined();
  });

  it("a registry-wide grant on the agent reaches every destination, inherited", () => {
    const w = world();
    const b: Binding = { role: ROLE, member: hd.principal, member_label: "Helpdesk Agent", condition: null, english: "" };
    w.inventory.access[REG] = [b];
    const ls = focus(w, hd.name);
    expect(line(ls, hd.name, REG)).toMatchObject({ verdict: "allowed", inherited: false });
    const hrd = line(ls, hd.name, dest("HR Directory MCP").name)!;
    expect(hrd).toMatchObject({ verdict: "allowed", inherited: true });
    expect(hrd.reasons[0].via).toBe("registry_wide");
    expect(ls.filter((l) => l.implicit)).toEqual([]);
  });

  it("with inherited grants off, only the agent's own grants count", () => {
    const ls = focus(w0, hd.name, { inherited: false });
    expect(line(ls, hd.name, dest("Calendar Agent").name)).toMatchObject({ verdict: "would_deny", implicit: true });
  });

  it("an agent with no gateway: dormant lines, no implicit denies", () => {
    const t = eng("Travel Planner");
    const ls = focus(w0, t.name);
    expect(line(ls, t.name, dest("Calendar Agent").name)).toMatchObject({ verdict: "dormant", source: NOGW.egress });
    expect(ls.some((l) => l.implicit)).toBe(false);
  });

  it("caps implicit lines at 60 in the view, with the rest counted", () => {
    const w = world();
    for (let i = 0; i < 80; i++)
      w.inventory.endpoints.push({ name: `${REG}/endpoints/extra-${String(i).padStart(3, "0")}`, id: `extra-${i}`, display_name: `Extra API ${String(i).padStart(3, "0")}`, url: `https://extra${i}.example.com` });
    const g = buildPolicyGraph(input(w, "egress", { focus: hd.name }));
    const v = viewOf(g, filters(), hd.name);
    const implicit = v.edges.filter((e) => e.implicit);
    expect(implicit).toHaveLength(IMPLICIT_CAP);
    expect(v.more).toBe(g.focusLines!.filter((l) => l.implicit).length - IMPLICIT_CAP);
    expect(v.focus).toBe(hd.name);
    expect(viewOf(g, filters({ implicit: false }), hd.name).edges.some((e) => e.implicit)).toBe(false);
  });
});

describe("filters (§5.1)", () => {
  const g = buildPolicyGraph(input(w0));
  const ids = (f: Partial<MapFilters>) => new Set(viewOf(g, filters(f), null).nodes.map((n) => n.id));

  it("defaults to Agent-to-Anywhere, every agent, empty destinations grouped", () => {
    expect(DEFAULT_DIRECTION).toBe("egress");
    const v = viewOf(g, filters(), null);
    const group = v.nodes.find((n) => n.id === "group:api")!;
    // 25 endpoints: 3 with project-wide grants, 1 unreadable (always shown), 21 grouped
    expect(group.grouped).toHaveLength(21);
    expect(group.label).toBe("+21 API endpoints with no grants");
    expect(viewOf(g, filters({ expanded: ["api"] }), null).nodes.some((n) => n.id === "group:api")).toBe(false);
    expect(viewOf(g, filters({ hideEmpty: false }), null).nodes.filter((n) => n.kind === "endpoint")).toHaveLength(25);
  });

  it("No gateway: only unbound agents, their direct traffic and dormant grants", () => {
    const s = ids({ affiliation: "none" });
    expect(s.has(eng("Travel Planner").name) && s.has(eng("simple-agent-with-psc").name)).toBe(true);
    expect(s.has(eng("Helpdesk Agent").name) || s.has(EGRESS) || s.has(PSEUDO.public)).toBe(false);
    expect(s.has(NOGW.egress) && s.has(PSEUDO.anywhere)).toBe(true);
    const v = viewOf(g, filters({ affiliation: "none" }), null);
    expect(v.edges.filter((e) => e.verdict !== "direct").map((e) => e.verdict)).toEqual(["dormant"]);
  });

  it("Behind a gateway: no unbound agents and no No-gateway lane", () => {
    const s = ids({ affiliation: "gateway" });
    expect(s.has(eng("Helpdesk Agent").name) && s.has(eng("HR Assistant").name) && s.has(EGRESS)).toBe(true);
    expect(s.has(eng("Travel Planner").name) || s.has(NOGW.egress)).toBe(false);
  });

  it("one gateway of several: its agents only, and combined lines recounted", () => {
    const w = world();
    const lab: Gateway = { ...structuredClone(w.gateways[0]), name: EGRESS.replace("corp-egress", "lab-egress"), id: "lab-egress", bound_engines: [] };
    w.gateways.push(lab);
    const hr = w.inventory.engines.find((e) => e.display_name === "HR Assistant")!;
    hr.gateways.egress = lab.name;
    lab.bound_engines.push({ engine: hr.name, display_name: hr.display_name, direction: "egress" });
    w.gateways[0].bound_engines = w.gateways[0].bound_engines.filter((b) => b.engine !== hr.name);
    const g2 = buildPolicyGraph(input(w));
    const tickets = dest("Tickets MCP").name;
    expect(g2.edges.filter((e) => e.target === tickets && e.parts).map((e) => [e.source, e.parts!.length]).sort()).toEqual([
      [EGRESS, 1],
      [lab.name, 1],
    ]);
    const v = viewOf(g2, filters({ gateway: lab.name }), null);
    expect(v.nodes.filter((n) => n.kind === "engine").map((n) => n.label)).toEqual(["HR Assistant"]);
    expect(v.nodes.some((n) => n.id === EGRESS)).toBe(false);
  });

  it("combined lines keep only the parts whose agent is shown", () => {
    const w = world();
    const tr = w.inventory.engines.find((e) => e.display_name === "Travel Planner")!;
    // Travel Planner gets a grant on Tickets MCP while unbound: one dormant part via No gateway.
    w.inventory.access[dest("Tickets MCP").name].push({ role: ROLE, member: tr.principal, member_label: "Travel Planner", condition: null, english: "" });
    const g2 = buildPolicyGraph(input(w));
    const all = viewOf(g2, filters(), null).edges.filter((e) => e.target === dest("Tickets MCP").name);
    expect(all.map((e) => e.parts?.length).sort()).toEqual([1, 2]);
    expect(viewOf(g2, filters({ affiliation: "gateway" }), null).edges.filter((e) => e.target === dest("Tickets MCP").name).map((e) => e.parts!.length)).toEqual([2]);
    expect(viewOf(g2, filters({ affiliation: "gateway" }), null).nodes.some((n) => n.id === tr.name)).toBe(false);
  });

  it("destination types and the legend's verdict filter", () => {
    const s = ids({ types: { a2a: true, runtime: true, mcp: false, api: true } });
    expect([...inv.mcp_servers].some((m) => s.has(m.name))).toBe(false);
    const v = viewOf(g, filters({ hidden: ["dormant", "partial"] }), null);
    expect(v.edges.some((e) => e.verdict === "dormant" || e.verdict === "partial")).toBe(false);
    expect(v.edges.some((e) => e.verdict === "path")).toBe(true); // trunks are never hidden
  });

  it("table rows: one per agent of a combined line", () => {
    const rows = tableRows(viewOf(g, filters(), null));
    expect(rows.filter((r) => r.target === dest("Tickets MCP").name)).toHaveLength(2);
    expect(rows.some((r) => r.verdict === "path")).toBe(false);
  });

  it("a pseudo caller selected: only its lines", () => {
    const v = viewOf(g, filters(), PSEUDO.project);
    expect(v.edges.map((e) => e.source)).toEqual([PSEUDO.project, PSEUDO.project, PSEUDO.project]);
  });
});

describe("Client-to-Agent (§6.2, §6.3)", () => {
  it("bound agents through the ingress gateway, the rest direct; screening follows Model Armor", () => {
    const g = buildPolicyGraph(input(w0, "ingress"));
    const hd = eng("Helpdesk Agent").name;
    expect(edge(g.edges, `i:${INGRESS}|${hd}`)?.verdict).toBe("unscreened");
    expect(edge(g.edges, `i:${INGRESS}|${eng("HR Assistant").name}`)?.verdict).toBe("unscreened");
    expect(edge(g.edges, `i:${NOGW.ingress}|${eng("Travel Planner").name}`)?.verdict).toBe("direct");
    expect(edge(g.edges, `i:${CLIENT.any}|${INGRESS}`)).toMatchObject({ verdict: "unscreened", label: "2 agents" });
    expect(g.nodes.some((n) => n.id === CLIENT.ge)).toBe(false);
    expect(g.nodes.find((n) => n.id === CLIENT.any)!.sub).toMatch(/not read by Policy Studio/);

    const w = world();
    w.modelArmor.gateways.find((m) => m.gateway === INGRESS)!.enabled = true;
    const g2 = buildPolicyGraph(input(w, "ingress", { ctx: { ge_app: "support-app" } }));
    expect(edge(g2.edges, `i:${INGRESS}|${hd}`)).toMatchObject({ verdict: "screened", modelArmor: true });
    expect(g2.nodes.find((n) => n.id === CLIENT.ge)!.sub).toMatch(/support-app .*registration not verified/);
  });

  it("an IAP policy on an ingress gateway shows as configured, not as identity checks", () => {
    const g = buildPolicyGraph(input(w0, "ingress"));
    // us-east4: corp-ingress shares the dry-run IAP extension with corp-egress
    const chip = g.nodes.find((n) => n.id === INGRESS)!.chips.find((c) => c.text.startsWith("IAP REQUEST_AUTHZ"));
    expect(chip).toMatchObject({ text: "IAP REQUEST_AUTHZ · dry run", tone: "neutral", title: "Configured; Client-to-Agent doesn't check caller identity." });
  });
});

describe("layout (§7)", () => {
  it("is deterministic, whatever the input order", () => {
    const g = buildPolicyGraph(input(w0));
    const v = viewOf(g, filters(), null);
    const a = layoutView(v);
    expect(layoutView(v)).toEqual(a);
    expect(layoutView({ nodes: [...v.nodes].reverse(), edges: [...v.edges].reverse() }).pos).toEqual(a.pos);
  });

  it("puts callers, gateways and destinations in columns, left to right", () => {
    const v = viewOf(buildPolicyGraph(input(w0)), filters(), null);
    const { pos } = layoutView(v);
    expect(pos[eng("Helpdesk Agent").name].x).toBeLessThan(pos[EGRESS].x);
    expect(pos[EGRESS].x).toBeLessThan(pos[dest("Tickets MCP").name].x);
    expect(pos[dest("Tickets MCP").name].x).toBeLessThan(pos[PSEUDO.anywhere].x);
  });

  it("orders destinations by the callers that reach them (barycenter)", () => {
    // HR Assistant is placed below Helpdesk Agent; HR Directory MCP (only HR) comes below Tickets MCP (both).
    const v = viewOf(buildPolicyGraph(input(w0)), filters(), null);
    const { pos } = layoutView(v);
    expect(pos[dest("Tickets MCP").name].y).toBeLessThan(pos[dest("HR Directory MCP").name].y);
  });

  it("wraps a section of more than 25 nodes into sub-columns", () => {
    const w = world();
    for (let i = 0; i < 30; i++) w.inventory.endpoints.push({ name: `${REG}/endpoints/x-${i}`, id: `x-${i}`, display_name: `X ${String(i).padStart(2, "0")}`, url: "https://x.example.com" });
    const v = viewOf(buildPolicyGraph(input(w)), filters({ hideEmpty: false }), null);
    const { pos } = layoutView(v);
    const xs = new Set(v.nodes.filter((n) => n.kind === "endpoint").map((n) => pos[n.id].x));
    expect(xs.size).toBe(Math.ceil(v.nodes.filter((n) => n.kind === "endpoint").length / WRAP));
  });
});
