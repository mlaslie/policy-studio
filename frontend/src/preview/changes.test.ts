// The Add to cart preview's change list and warnings (preview/changes.ts), and its Approve / Modify / Cancel
// transitions (preview/flow.ts), on the mock's world (?case=merge for the user's case: the Helpdesk Agent's read-only
// grant plus a separate close_ticket grant on Tickets MCP; search_tickets also allowed project-wide).
import { afterAll, describe, expect, it } from "vitest";
import type { Binding, Intent, Inventory } from "../api/types";
import { buildWorld } from "../api/mockData";
import { changeIntent, existingFor, targetOf, lockedTools, toolsToday } from "../lib/existing";
import { ROLE } from "../lib/policy";
import { previewModel } from "./changes";
import { approve, cancel, modify, openPreview } from "./flow";
import { previewGraph } from "./graph";
import { buildPolicyGraph, NOGW } from "../map/graph";
import { simulate } from "../map/simulate";
import { diffGraphs, mergeStaged } from "../map/diff";

const saved = Object.getOwnPropertyDescriptor(globalThis, "window");
afterAll(() => {
  if (saved) Object.defineProperty(globalThis, "window", saved);
  else delete (globalThis as { window?: unknown }).window;
});
function world(merge: boolean) {
  Object.defineProperty(globalThis, "window", { value: { location: { search: merge ? "?case=merge" : "" } }, configurable: true });
  return buildWorld({ project: "my-demo-project", region: "us-east4" });
}
function env(inv: Inventory) {
  const eng = (n: string) => inv.engines.find((e) => e.display_name === n)!;
  const src = (n: string): NonNullable<Intent["source"]> => ({ type: "engine", principal: eng(n).principal, label: n, engine: eng(n).name });
  const dest = (label: string): NonNullable<Intent["destination"]> => {
    const m = inv.mcp_servers.find((x) => x.display_name === label);
    if (m) return { kind: "mcp_server", id: m.id, name: m.name, label };
    const a = inv.agents.find((x) => x.display_name === label);
    if (a) return { kind: "agent", id: a.id, name: a.name, label };
    const p = inv.endpoints.find((x) => x.display_name === label)!;
    return { kind: "endpoint", id: p.id, name: p.name, label };
  };
  const staged = (who: string, where: string, choice: Parameters<typeof targetOf>[0]): Intent => {
    const s = src(who);
    const d = dest(where);
    const ex = existingFor(inv, s.principal, d.name);
    const mcp = inv.mcp_servers.find((m) => m.name === d.name);
    const locked = new Set(lockedTools(toolsToday(mcp, ex)).keys());
    return changeIntent({ id: "c1", source: s, destination: d, own: ex.own, target: targetOf(choice, d.kind, ex.own.length ? "change" : "new", locked) })!;
  };
  return { eng, src, dest, staged };
}

describe("the change list", () => {
  it("MCP, two grants merged into one: each tool today → after, with the grants behind each side", () => {
    const w = world(true);
    const e = env(w.inventory);
    const i = e.staged("Helpdesk Agent", "Tickets MCP", { mode: "tools", tools: ["list_tickets", "get_ticket", "update_ticket"], expr: "" });
    const m = previewModel({ intent: i, inv: w.inventory, engine: e.eng("Helpdesk Agent") });
    expect(m.kind).toBe("change");
    const row = (t: string) => m.rows.find((r) => r.name === t)!;
    expect(row("list_tickets")).toMatchObject({ today: "allowed", todayBy: ["read-only grant"], after: "allowed", afterBy: ["tools grant"], change: "same" });
    expect(row("close_ticket")).toMatchObject({ today: "allowed", todayBy: ["tools grant"], after: "denied", afterBy: [], change: "removed" });
    expect(row("update_ticket")).toMatchObject({ today: "denied", after: "allowed", change: "added" });
    expect(row("search_tickets")).toMatchObject({ today: "allowed", todayBy: ["read-only grant", "project-wide grant"], after: "allowed", afterBy: ["project-wide grant"], inheritedOnly: true });
    expect(row("create_ticket")).toMatchObject({ today: "denied", after: "denied", change: "same" });
    expect(m.removed.map((l) => l.text)).toEqual(["read-only grant: only read-only tools", "tools grant: only tools close_ticket"]);
    expect(m.added.map((l) => l.text)).toEqual(["tools grant: only tools list_tickets, get_ticket, update_ticket"]);
    expect(m.sentence).toBe("Change Helpdesk Agent's access to Tickets MCP: read-only + close_ticket → list_tickets, get_ticket, update_ticket.");
    expect(m.warnings.map((x) => x.id)).toEqual(["widen", "inherited", "hint"]);
    expect(m.warnings[0].text).toBe("This widens access: update_ticket becomes allowed.");
    expect(m.warnings[1].text).toBe("search_tickets stays allowed by the project-wide grant: change it there.");
  });

  it("MCP, remove all: every own grant goes; inherited tools stay (and are named)", () => {
    const w = world(true);
    const e = env(w.inventory);
    const i = e.staged("Helpdesk Agent", "Tickets MCP", { mode: "tools", tools: ["search_tickets"], expr: "" });
    expect(i).toMatchObject({ kind: "modify", access_list: [] });
    const m = previewModel({ intent: i, inv: w.inventory, engine: e.eng("Helpdesk Agent") });
    expect(m.kind).toBe("remove_all");
    expect(m.added).toEqual([]);
    expect(m.removed).toHaveLength(2);
    expect(m.rows.filter((r) => r.after === "allowed").map((r) => r.name)).toEqual(["search_tickets"]);
    expect(m.warnings.map((x) => x.id)).toEqual(["remove_all", "inherited"]);
    expect(m.warnings[0].text).toBe("This removes all of Helpdesk Agent's own access to Tickets MCP (2 grants, in one change). Inherited grants still allow some of it (below).");
    expect(m.title).toBe("Remove access: Helpdesk Agent → Tickets MCP");
  });

  it("remove all with nothing inherited: the red “removes all access” warning", () => {
    const w = world(false);
    const e = env(w.inventory);
    const hr = e.src("HR Assistant");
    const hrdir = e.dest("HR Directory MCP");
    const extra: Binding = { role: ROLE, member: hr.principal, member_label: "HR Assistant", condition: { title: "ro", expression: "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['lookup_employee', '']" }, english: "" };
    w.inventory.access[hrdir.name].push(extra);
    const i = e.staged("HR Assistant", "HR Directory MCP", { mode: "tools", tools: [], expr: "" });
    const m = previewModel({ intent: i, inv: w.inventory, engine: e.eng("HR Assistant") });
    expect(m.rows.every((r) => r.after === "denied")).toBe(true);
    expect(m.warnings.find((x) => x.id === "remove_all")).toMatchObject({ tone: "red", text: "This removes all of HR Assistant's access to HR Directory MCP (2 grants, in one change)." });
  });

  it("A2A agent, a new grant: one row for the destination; the no-gateway warning", () => {
    const w = world(false);
    const e = env(w.inventory);
    const i = e.staged("Travel Planner", "Billing Agent", { mode: "all", tools: [], expr: "" });
    expect(i.kind).toBe("grant");
    const m = previewModel({ intent: i, inv: w.inventory, engine: e.eng("Travel Planner") });
    expect(m.kind).toBe("grant");
    expect(m.rows).toEqual([expect.objectContaining({ name: "Billing Agent", tool: false, today: "denied", after: "allowed", afterBy: ["full-access grant"], change: "added" })]);
    expect(m.added).toHaveLength(1);
    expect(m.warnings.map((x) => x.id)).toEqual(["no_gateway"]);
    expect(m.warnings[0].text).toMatch(/^Travel Planner isn't behind an egress gateway/);
    const staged = previewModel({ intent: i, inv: w.inventory, engine: e.eng("Travel Planner"), cart: [{ id: "b", kind: "bind_gateway", engine: e.eng("Travel Planner").name, gateway: { name: "g", direction: "egress" } }] });
    expect(staged.warnings[0]).toMatchObject({ id: "no_gateway", tone: "info" });
  });

  it("endpoint, Remove access: a revoke; the destination row goes from allowed to denied", () => {
    const w = world(false);
    const e = env(w.inventory);
    const i = e.staged("Travel Planner", "Weather API", { mode: "all", tools: [], expr: "", remove: true });
    expect(i).toMatchObject({ kind: "revoke", access: { mode: "all" } });
    const m = previewModel({ intent: i, inv: w.inventory });
    expect(m.kind).toBe("revoke");
    expect(m.rows).toEqual([expect.objectContaining({ name: "Weather API", today: "allowed", todayBy: ["full-access grant"], after: "denied", change: "removed" })]);
    expect(m.warnings.map((x) => x.id)).toEqual(["remove_all"]);
  });

  it("A2A agent, a custom condition instead of full access: today allowed, after can't tell", () => {
    const w = world(false);
    const e = env(w.inventory);
    const i = e.staged("Helpdesk Agent", "Knowledge Base Agent", { mode: "custom", tools: [], expr: "request.time < timestamp('2027-01-01T00:00:00Z')" });
    const m = previewModel({ intent: i, inv: w.inventory, engine: e.eng("Helpdesk Agent") });
    expect(m.rows[0]).toMatchObject({ today: "allowed", todayBy: ["full-access grant", "group grant (if a member)"], after: "unknown", change: "unknown" });
    // the group grant on it can't be told here either: "can't tell" is explained
    expect(m.warnings.map((x) => x.id)).toContain("unknown");
  });

  it("read-only hint added where there was none: the info note", () => {
    const w = world(false);
    const e = env(w.inventory);
    const i = e.staged("HR Assistant", "Tickets MCP", { mode: "read_only_hint", tools: [], expr: "" });
    const m = previewModel({ intent: i, inv: w.inventory, engine: e.eng("HR Assistant") });
    expect(m.warnings.map((x) => x.id)).toContain("hint_new");
  });
});

describe("the preview map", () => {
  it("only the source, its gateway and the destination; the line is a pending change", () => {
    const w = world(true);
    const e = env(w.inventory);
    const i = e.staged("Helpdesk Agent", "Tickets MCP", { mode: "tools", tools: ["list_tickets"], expr: "" });
    const input = { context: w.context, direction: "egress" as const };
    const base = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, ...input });
    const sim = simulate({ inventory: w.inventory, gateways: w.gateways }, [i]);
    const after = buildPolicyGraph({ inventory: sim.inventory, gateways: sim.gateways, ...input });
    const merged = mergeStaged(base, after, diffGraphs(base, after), [i], w.inventory, sim.effects);
    const { view } = previewGraph(merged, i, w.inventory.project_agents_principal ?? null);
    expect(view.nodes.map((n) => n.kind).sort()).toEqual(["engine", "gateway", "mcp"]);
    const line = view.edges.find((x) => x.target === i.destination!.name)!;
    expect(line.pending).toBe("change");
    expect(view.edges.find((x) => x.verdict === "path")).toBeTruthy();
  });

  it("an agent with no gateway: the No gateway lane instead", () => {
    const w = world(false);
    const e = env(w.inventory);
    const i = e.staged("Travel Planner", "Billing Agent", { mode: "all", tools: [], expr: "" });
    const g = buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, direction: "egress" });
    const sim = simulate({ inventory: w.inventory, gateways: w.gateways }, [i]);
    const after = buildPolicyGraph({ inventory: sim.inventory, gateways: sim.gateways, direction: "egress" });
    const { view } = previewGraph(mergeStaged(g, after, diffGraphs(g, after), [i], w.inventory, sim.effects), i, null);
    expect(view.nodes.map((n) => n.id)).toContain(NOGW.egress);
    expect(view.edges.find((x) => x.target === i.destination!.name)).toMatchObject({ pending: "add", verdict: "dormant" });
  });
});

describe("Approve / Modify / Cancel", () => {
  const intent: Intent = { id: "preview", kind: "grant", source: { type: "custom", principal: "user:a@example.com", label: "a" }, destination: { kind: "agent", id: "x", name: "x", label: "X" }, access: { mode: "all" } };
  const fix: Intent = { id: "f", kind: "bind_gateway", engine: "e", gateway: { name: "g", direction: "egress" } };

  it("Approve stages the fixes then the change (a fresh id) and focuses it in Review", () => {
    const p = openPreview(intent, [fix], false);
    const { state, effect } = approve(p, () => "i-new");
    expect(state).toBeNull();
    expect(effect).toEqual({ kind: "stage", intents: [fix, { ...intent, id: "i-new" }], focus: "i-new", another: false });
  });
  it("Approve from Add & build another stays in the builder; editing a cart item replaces it", () => {
    expect(approve(openPreview(intent, [], true), () => "n").effect).toMatchObject({ kind: "stage", another: true });
    const e = approve(openPreview(intent, [fix], false, "cart-1"), () => "n").effect;
    expect(e).toEqual({ kind: "stage", intents: [fix], replace: { id: "cart-1", intent: { ...intent, id: "cart-1" } }, focus: "cart-1", another: false });
  });
  it("Modify (and Esc) keeps every choice; Cancel resets “how much” to where the pair started and drops the fixes", () => {
    expect(modify()).toEqual({ state: null, effect: { kind: "keep" } });
    const initial = { mode: "tools" as const, tools: ["a", "b"], expr: "" };
    const c = cancel(initial);
    expect(c).toEqual({ state: null, effect: { kind: "reset", choice: initial, clearExtras: true } });
    if (c.effect.kind === "reset") expect(c.effect.choice.tools).not.toBe(initial.tools);
  });
});
