// buildPolicyGraph over the mock world (docs/VISUALIZATION_PLAN.md §4.4, §6.3, §14): one check per egress case, lines
// only for the selected agents (each agent's own, never combined), Allows / Denies, the filters and the layout.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Binding, Ctx, Gateway } from "../api/types";
import { ROLE } from "../lib/policy";
import { CLIENT, NOGW, PSEUDO, buildPolicyGraph, type Direction, type GraphInput, type PEdge } from "./graph";
import { DEFAULT_DIRECTION, DEFAULT_FILTERS, DENY_CAP, GOOGLE_GROUP, tableRows, viewOf, type MapFilters } from "./view";
import { presetAffiliation, DEFAULT_PICKER } from "./picker";
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
  /** An agent's own line to a destination. */
  const own = (a: string, d: string) => edge(g.edges, `a:${eng(a).name}|${dest(d).name}`);

  it("an unconditional grant: allowed, through the agent's gateway, with Model Armor", () => {
    expect(own("Helpdesk Agent", "Knowledge Base Agent")).toMatchObject({ verdict: "allowed", source: EGRESS, mode: "DRY_RUN", modelArmor: true, caller: eng("Helpdesk Agent").name, inherited: false });
    expect(edge(g.edges, `trunk:${eng("Helpdesk Agent").name}`)).toMatchObject({ verdict: "path", target: EGRESS, caller: eng("Helpdesk Agent").name });
  });

  it("MCP read-only hint and a tools list: partial, one line per agent (never combined)", () => {
    const hd = own("Helpdesk Agent", "Tickets MCP")!;
    expect(hd).toMatchObject({ verdict: "partial", label: "read-only" });
    expect(hd.tools!.allowed.sort()).toEqual(["get_ticket", "list_tickets", "search_tickets"]);
    const hr = own("HR Assistant", "Tickets MCP")!;
    expect(hr).toMatchObject({ verdict: "partial", label: "2/6 tools" });
    expect(hr.tools!.allowed.sort()).toEqual(["create_ticket", "get_ticket"]);
    // every line belongs to exactly one caller
    expect(g.edges.every((e) => !!e.caller)).toBe(true);
    expect(g.edges.some((e) => e.id.startsWith("c:"))).toBe(false);
  });

  it("an unconditional grant on an MCP server: allowed (every tool)", () => {
    expect(own("HR Assistant", "HR Directory MCP")!.verdict).toBe("allowed");
  });

  it("a custom CEL condition: conditional", () => {
    expect(own("HR Assistant", "Billing Agent")).toMatchObject({ verdict: "conditional", label: "?" });
  });

  it("an agent with no egress gateway: its grants are dormant, its traffic direct", () => {
    const travel = eng("Travel Planner").name;
    expect(own("Travel Planner", "Calendar Agent")).toMatchObject({ verdict: "dormant", source: NOGW.egress });
    expect(edge(g.edges, `direct:${travel}`)).toMatchObject({ verdict: "direct", target: NOGW.egress });
    expect(edge(g.edges, `out:${travel}`)).toMatchObject({ verdict: "direct", source: NOGW.egress, target: PSEUDO.anywhere, caller: travel });
  });

  it("an agent that can't be bound: direct, flagged", () => {
    const psc = g.nodes.find((n) => n.id === eng("simple-agent-with-psc").name)!;
    expect(psc.gateway).toBeNull();
    expect(psc.chips.map((c) => c.text)).toContain("Can't be bound");
    expect(edge(g.edges, `direct:${psc.id}`)?.verdict).toBe("direct");
  });

  it("project-wide principalSet grants: drawn once from All agents in this project", () => {
    for (const d of ["Vertex AI API", "Cloud Logging API", "Telemetry API"])
      expect(edge(g.edges, `p:${PSEUDO.project}|${dest(d).name}`)).toMatchObject({ verdict: "allowed", source: PSEUDO.project, caller: PSEUDO.project });
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

  it("engine summary chips: the allowed count, inherited reach and would-be-denied count", () => {
    const hd = g.nodes.find((n) => n.id === eng("Helpdesk Agent").name)!;
    expect(hd.inheritedCount).toBe(17); // 3 + 13 platform project-wide endpoints and the public Calendar Agent
    expect(hd.allowedCount).toBe(2); // Knowledge Base Agent, Tickets MCP
    const texts = hd.chips.map((c) => c.text);
    expect(texts).toContain("2 allowed");
    expect(texts.some((t) => t.startsWith("Would be denied:"))).toBe(true);
    expect(texts.indexOf("2 allowed")).toBeLessThan(texts.findIndex((t) => t.startsWith("Would be denied:")));
    // an unbound agent: its grants, not enforced
    expect(g.nodes.find((n) => n.id === eng("Travel Planner").name)!.chips.map((c) => c.text)).toContain("2 grants not enforced");
  });
});

describe("each agent's inherited and default-deny lines", () => {
  const hd = eng("Helpdesk Agent");
  const hr = eng("HR Assistant");
  const lines = (w: ReturnType<typeof world>, extra: Partial<GraphInput> = {}) => buildPolicyGraph(input(w, "egress", extra)).edges;
  const line = (ls: PEdge[], e: string, d: string) => ls.find((l) => l.caller === e && l.target === d);

  it("adds project-wide and public grants as inherited, own grants as not", () => {
    const ls = lines(w0);
    expect(line(ls, hd.name, dest("Calendar Agent").name)).toMatchObject({ verdict: "allowed", inherited: true });
    expect(line(ls, hd.name, dest("Vertex AI API").name)).toMatchObject({ verdict: "allowed", inherited: true });
    expect(line(ls, hd.name, dest("Knowledge Base Agent").name)).toMatchObject({ verdict: "allowed", inherited: false });
  });

  it("a group grant is conditional for an agent (membership can't be told here)", () => {
    expect(line(lines(w0), hr.name, dest("Knowledge Base Agent").name)).toMatchObject({ verdict: "conditional", inherited: true });
  });

  it("no grant: would_deny under dry run, blocked under enforce, unchecked without an IAP policy", () => {
    expect(line(lines(w0), hd.name, dest("HR Directory MCP").name)).toMatchObject({ verdict: "would_deny", implicit: true, reasons: [], source: EGRESS });
    const enforce = world({ ...CTX, region: "us-central1" });
    const e2 = enforce.inventory.engines.find((e) => e.display_name === "Helpdesk Agent")!;
    const hrd = enforce.inventory.mcp_servers.find((m) => m.display_name === "HR Directory MCP")!;
    expect(line(lines(enforce), e2.name, hrd.name)).toMatchObject({ verdict: "blocked", implicit: true });
    const none = world();
    none.gateways.find((g) => g.type === "egress")!.enforcement!.mode = null;
    expect(line(lines(none), hd.name, dest("HR Directory MCP").name)?.verdict).toBe("unchecked");
  });

  it("no implicit line to an unreadable destination, nor to the agent's own registry entry", () => {
    expect(line(lines(w0), hd.name, dest("Cloud SQL Admin API").name)).toBeUndefined();
    const self = inv.agents.find((a) => a.engine === hd.name)!;
    expect(line(lines(w0), hd.name, self.name)).toBeUndefined();
  });

  it("a registry-wide grant on the agent reaches every destination, inherited", () => {
    const w = world();
    const b: Binding = { role: ROLE, member: hd.principal, member_label: "Helpdesk Agent", condition: null, english: "" };
    w.inventory.access[REG] = [b];
    const ls = lines(w).filter((l) => l.caller === hd.name);
    expect(line(ls, hd.name, REG)).toMatchObject({ verdict: "allowed", inherited: false });
    const hrd = line(ls, hd.name, dest("HR Directory MCP").name)!;
    expect(hrd).toMatchObject({ verdict: "allowed", inherited: true });
    expect(hrd.reasons[0].via).toBe("registry_wide");
    expect(ls.filter((l) => l.implicit)).toEqual([]);
  });

  it("with inherited grants off, only the agent's own grants count", () => {
    expect(line(lines(w0, { inherited: false }), hd.name, dest("Calendar Agent").name)).toMatchObject({ verdict: "would_deny", implicit: true });
  });

  it("an agent with no gateway: dormant lines, no implicit denies", () => {
    const t = eng("Travel Planner");
    const ls = lines(w0).filter((l) => l.caller === t.name);
    expect(line(ls, t.name, dest("Calendar Agent").name)).toMatchObject({ verdict: "dormant", source: NOGW.egress });
    expect(ls.some((l) => l.implicit)).toBe(false);
  });
});

describe("lines only for the selected agents", () => {
  const g = buildPolicyGraph(input(w0));
  const hd = eng("Helpdesk Agent").name;
  const hr = eng("HR Assistant").name;
  const hrd = dest("HR Directory MCP").name;

  it("no lines without a selection, in both directions: nodes only", () => {
    const v = viewOf(g, filters(), []);
    expect(v.edges).toEqual([]);
    expect(v.lines).toBe(0);
    expect(v.agents).toEqual([]);
    expect(v.nodes.some((n) => n.id === hd) && v.nodes.some((n) => n.id === EGRESS) && v.nodes.some((n) => n.id === dest("Tickets MCP").name)).toBe(true);
    // pseudo callers with grants stay on the map, so they can be selected
    expect(v.nodes.some((n) => n.id === PSEUDO.project)).toBe(true);
    const vi = viewOf(buildPolicyGraph(input(w0, "ingress")), filters(), []);
    expect(vi.edges).toEqual([]);
    expect(vi.nodes.some((n) => n.id === hd)).toBe(true);
  });

  it("two agents behind one gateway, one allowed to X and the other not: two lines, each with its own verdict", () => {
    const v = viewOf(g, filters(), [hd, hr]);
    const into = v.edges.filter((e) => e.target === hrd);
    expect(into).toHaveLength(2);
    expect(into.find((e) => e.caller === hr)).toMatchObject({ id: `a:${hr}|${hrd}`, verdict: "allowed", source: EGRESS });
    expect(into.find((e) => e.caller === hd)).toMatchObject({ id: `x:${hd}|${hrd}`, verdict: "would_deny", implicit: true, source: EGRESS });
    // no combined line, no "N agents" badge
    expect(v.edges.every((e) => !!e.caller && !/agents$/.test(e.label ?? ""))).toBe(true);
    expect(v.agents).toEqual([hd, hr]);
    // each agent's trunk to the gateway
    expect(v.edges.filter((e) => e.verdict === "path").map((e) => e.caller).sort()).toEqual([hd, hr].sort());
  });

  it("only the selected agent's lines, with its inherited ones", () => {
    const v = viewOf(g, filters(), [hd]);
    expect(new Set(v.edges.map((e) => e.caller))).toEqual(new Set([hd]));
    expect(v.edges.some((e) => e.inherited)).toBe(true);
  });

  it("Show: Allows and Denies", () => {
    const both = viewOf(g, filters(), [hd]);
    expect(both.edges.some((e) => e.implicit) && both.edges.some((e) => !e.implicit && e.verdict !== "path")).toBe(true);
    const allows = viewOf(g, filters({ denies: false }), [hd]);
    expect(allows.edges.some((e) => e.implicit)).toBe(false);
    expect(allows.edges.filter((e) => e.verdict !== "path").every((e) => ["allowed", "partial", "conditional"].includes(e.verdict))).toBe(true);
    const denies = viewOf(g, filters({ allows: false }), [hd]);
    expect(denies.edges.filter((e) => e.verdict !== "path").every((e) => e.implicit && (e.verdict === "would_deny" || e.verdict === "blocked"))).toBe(true);
    // the trunk stays either way
    expect(viewOf(g, filters({ allows: false, denies: false }), [hd]).edges.map((e) => e.id)).toEqual([`trunk:${hd}`]);
    // Client-to-Agent: no denies, the choice doesn't apply
    const gi = buildPolicyGraph(input(w0, "ingress"));
    expect(viewOf(gi, filters({ allows: false, denies: false }), [hd]).edges).toHaveLength(2);
  });

  it("an unbound agent's dormant grants count as Allows; its lanes always show", () => {
    const t = eng("Travel Planner").name;
    expect(viewOf(g, filters(), [t]).edges.filter((e) => e.verdict === "dormant" && !e.inherited)).toHaveLength(2);
    expect(viewOf(g, filters({ allows: false }), [t]).edges.map((e) => e.id).sort()).toEqual([`direct:${t}`, `out:${t}`].sort());
  });

  it("a destination the picker hides is drawn faded while a selected agent has a line to it", () => {
    const v = viewOf(g, filters({ off: [hrd] }), [hr]);
    expect(v.nodes.some((n) => n.id === hrd)).toBe(true);
    expect(v.faded).toEqual([hrd]);
    // nothing selected (or Allows off for an allowed line): hidden for real
    expect(viewOf(g, filters({ off: [hrd] }), []).nodes.some((n) => n.id === hrd)).toBe(false);
    expect(viewOf(g, filters({ off: [hrd], allows: false }), [hr]).nodes.some((n) => n.id === hrd)).toBe(false);
  });

  it("caps an agent's default-deny lines at DENY_CAP, with the rest counted", () => {
    const w = world();
    for (let i = 0; i < 80; i++)
      w.inventory.endpoints.push({ name: `${REG}/endpoints/extra-${String(i).padStart(3, "0")}`, id: `extra-${i}`, display_name: `Extra API ${String(i).padStart(3, "0")}`, url: `https://extra${i}.example.com` });
    const gx = buildPolicyGraph(input(w));
    // Google API endpoints shown one by one (collapsed, their default-deny lines are one line into the group)
    const v = viewOf(gx, filters({ googleApis: true }), [hd]);
    expect(v.edges.filter((e) => e.implicit)).toHaveLength(DENY_CAP);
    expect(v.more).toBe(gx.edges.filter((l) => l.implicit && l.caller === hd).length - DENY_CAP);
    // per agent: two agents, each capped
    const two = viewOf(gx, filters({ googleApis: true }), [hd, hr]);
    expect(two.edges.filter((e) => e.implicit && e.caller === hr)).toHaveLength(DENY_CAP);
    expect(viewOf(gx, filters({ denies: false }), [hd]).edges.some((e) => e.implicit)).toBe(false);
  });
});

describe("filters (§5.1)", () => {
  const g = buildPolicyGraph(input(w0));
  const ids = (f: Partial<MapFilters>) => new Set(viewOf(g, filters(f), []).nodes.map((n) => n.id));

  it("defaults to Agent-to-Anywhere, every object, destinations with no grants grouped", () => {
    expect(DEFAULT_DIRECTION).toBe("egress");
    const v = viewOf(g, filters(), []);
    // by default the 38 Google API endpoints are one node: only Partner payments is left with no grants
    expect(v.nodes.find((n) => n.id === "group:api")!.grouped).toHaveLength(1);
    // shown one by one: 25 + 13 platform Google APIs + 2 others; 16 with project-wide grants, Weather API granted,
    // 1 unreadable (always shown), 22 grouped
    const all = viewOf(g, filters({ googleApis: true }), []);
    const group = all.nodes.find((n) => n.id === "group:api")!;
    expect(group.grouped).toHaveLength(22);
    expect(group.label).toBe("+22 API endpoints with no grants");
    expect(viewOf(g, filters({ googleApis: true, expanded: ["api"] }), []).nodes.some((n) => n.id === "group:api")).toBe(false);
    expect(viewOf(g, filters({ googleApis: true, hideEmpty: false }), []).nodes.filter((n) => n.kind === "endpoint")).toHaveLength(40);
  });

  it("the No gateway shortcut: only unbound agents, their lanes and dormant grants", () => {
    const off = presetAffiliation(DEFAULT_PICKER, g, "none").off;
    const s = ids({ off });
    expect(s.has(eng("Travel Planner").name) && s.has(eng("simple-agent-with-psc").name)).toBe(true);
    expect(s.has(eng("Helpdesk Agent").name) || s.has(EGRESS) || s.has(PSEUDO.public)).toBe(false);
    expect(s.has(NOGW.egress) && s.has(PSEUDO.anywhere)).toBe(true);
    // Travel Planner's Calendar Agent and Weather API grants, once it's selected
    const v = viewOf(g, filters({ off }), [eng("Travel Planner").name]);
    expect(v.edges.filter((e) => e.verdict !== "direct" && !e.inherited).map((e) => e.verdict)).toEqual(["dormant", "dormant"]);
  });

  it("the Behind a gateway shortcut: no unbound agents and no No-gateway lane", () => {
    const s = ids({ off: presetAffiliation(DEFAULT_PICKER, g, "gateway").off });
    expect(s.has(eng("Helpdesk Agent").name) && s.has(eng("HR Assistant").name) && s.has(EGRESS)).toBe(true);
    expect(s.has(eng("Travel Planner").name) || s.has(NOGW.egress)).toBe(false);
  });

  it("one gateway of several: its agents only, each agent's lines through its own gateway", () => {
    const w = world();
    const lab: Gateway = { ...structuredClone(w.gateways[0]), name: EGRESS.replace("corp-egress", "lab-egress"), id: "lab-egress", bound_engines: [] };
    w.gateways.push(lab);
    const hr = w.inventory.engines.find((e) => e.display_name === "HR Assistant")!;
    hr.gateways.egress = lab.name;
    lab.bound_engines.push({ engine: hr.name, display_name: hr.display_name, direction: "egress" });
    w.gateways[0].bound_engines = w.gateways[0].bound_engines.filter((b) => b.engine !== hr.name);
    const g2 = buildPolicyGraph(input(w));
    const tickets = dest("Tickets MCP").name;
    expect(g2.edges.filter((e) => e.target === tickets && !e.implicit && !e.inherited && !e.caller?.startsWith("pseudo:")).map((e) => e.source).sort()).toEqual([EGRESS, lab.name].sort());
    const v = viewOf(g2, filters({ gateway: lab.name }), [hr.name, eng("Helpdesk Agent").name]);
    expect(v.nodes.filter((n) => n.kind === "engine").map((n) => n.label)).toEqual(["HR Assistant"]);
    expect(v.nodes.some((n) => n.id === EGRESS)).toBe(false);
    // Helpdesk Agent isn't shown, so it isn't drawn even though it's selected
    expect(v.agents).toEqual([hr.name]);
  });

  it("the picker hides objects; the legend hides kinds of line", () => {
    const s = ids({ off: inv.mcp_servers.map((m) => m.name) });
    expect([...inv.mcp_servers].some((m) => s.has(m.name))).toBe(false);
    const v = viewOf(g, filters({ hidden: ["dormant", "partial"] }), inv.engines.map((e) => e.name));
    expect(v.edges.some((e) => e.verdict === "dormant" || e.verdict === "partial")).toBe(false);
    expect(v.edges.some((e) => e.verdict === "path")).toBe(true); // trunks are never hidden
  });

  it("table rows: the selected agents' lines; with no selection, every agent's own grants", () => {
    const rows = tableRows(viewOf(g, filters(), []));
    expect(rows.filter((r) => r.target === dest("Tickets MCP").name).map((r) => r.caller).sort()).toEqual([eng("Helpdesk Agent").name, eng("HR Assistant").name].sort());
    expect(rows.some((r) => r.verdict === "path" || r.implicit)).toBe(false);
    const hd = eng("Helpdesk Agent").name;
    const sel = tableRows(viewOf(g, filters(), [hd]));
    expect(new Set(sel.map((r) => r.caller))).toEqual(new Set([hd]));
    expect(sel.some((r) => r.implicit)).toBe(true);
  });

  it("a pseudo caller selected: only its lines", () => {
    const v = viewOf(g, filters({ googleApis: true }), [PSEUDO.project]);
    expect(v.edges.map((e) => e.source)).toEqual(Array(16).fill(PSEUDO.project));
    // collapsed: its 16 Google API lines are one line into the group
    expect(viewOf(g, filters(), [PSEUDO.project]).edges.map((e) => [e.source, e.target, e.label])).toEqual([[PSEUDO.project, GOOGLE_GROUP, "16 APIs"]]);
  });
});

describe("Client-to-Agent (§6.2, §6.3)", () => {
  it("bound agents through the ingress gateway, the rest direct; screening follows Model Armor", () => {
    const g = buildPolicyGraph(input(w0, "ingress"));
    const hd = eng("Helpdesk Agent").name;
    expect(edge(g.edges, `i:${INGRESS}|${hd}`)?.verdict).toBe("unscreened");
    expect(edge(g.edges, `i:${INGRESS}|${eng("HR Assistant").name}`)?.verdict).toBe("unscreened");
    expect(edge(g.edges, `i:${NOGW.ingress}|${eng("Travel Planner").name}`)?.verdict).toBe("direct");
    // each agent's own line from each client into its lane
    expect(edge(g.edges, `i:${CLIENT.any}|${INGRESS}|${hd}`)).toMatchObject({ verdict: "unscreened", caller: hd, source: CLIENT.any, target: INGRESS });
    expect(edge(g.edges, `i:${CLIENT.any}|${NOGW.ingress}|${eng("Travel Planner").name}`)).toMatchObject({ verdict: "direct", caller: eng("Travel Planner").name });
    expect(g.edges.every((e) => !!e.caller && !e.label)).toBe(true);
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
    const v = viewOf(g, filters(), []);
    const a = layoutView(v);
    expect(layoutView(v)).toEqual(a);
    expect(layoutView({ nodes: [...v.nodes].reverse(), edges: [], layoutEdges: [...v.layoutEdges].reverse() }).pos).toEqual(a.pos);
  });

  it("doesn't move nodes when an agent is selected (its default-deny lines can bring grouped destinations out)", () => {
    const g = buildPolicyGraph(input(w0));
    const none = layoutView(viewOf(g, filters(), [])).pos;
    const sel = layoutView(viewOf(g, filters({ denies: false }), [eng("HR Assistant").name])).pos;
    expect(sel[eng("Helpdesk Agent").name]).toEqual(none[eng("Helpdesk Agent").name]);
    expect(sel[dest("Tickets MCP").name]).toEqual(none[dest("Tickets MCP").name]);
  });

  it("puts callers, gateways and destinations in columns, left to right", () => {
    const v = viewOf(buildPolicyGraph(input(w0)), filters(), []);
    const { pos } = layoutView(v);
    expect(pos[eng("Helpdesk Agent").name].x).toBeLessThan(pos[EGRESS].x);
    expect(pos[EGRESS].x).toBeLessThan(pos[dest("Tickets MCP").name].x);
    expect(pos[dest("Tickets MCP").name].x).toBeLessThan(pos[PSEUDO.anywhere].x);
  });

  it("orders destinations by the callers that reach them (barycenter)", () => {
    // HR Assistant is placed below Helpdesk Agent; HR Directory MCP (only HR) comes below Tickets MCP (both).
    const v = viewOf(buildPolicyGraph(input(w0)), filters(), []);
    const { pos } = layoutView(v);
    expect(pos[dest("Tickets MCP").name].y).toBeLessThan(pos[dest("HR Directory MCP").name].y);
  });

  it("wraps a section of more than 25 nodes into sub-columns", () => {
    const w = world();
    for (let i = 0; i < 30; i++) w.inventory.endpoints.push({ name: `${REG}/endpoints/x-${i}`, id: `x-${i}`, display_name: `X ${String(i).padStart(2, "0")}`, url: "https://x.example.com" });
    const v = viewOf(buildPolicyGraph(input(w)), filters({ hideEmpty: false }), []);
    const { pos } = layoutView(v);
    const xs = new Set(v.nodes.filter((n) => n.kind === "endpoint").map((n) => pos[n.id].x));
    expect(xs.size).toBe(Math.ceil(v.nodes.filter((n) => n.kind === "endpoint").length / WRAP));
  });
});
