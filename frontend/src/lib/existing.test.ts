// The Build step's "change existing access" (lib/existing.ts): mode detection, the tool checklist (notes, locked
// inherited tools), the choices offered, unchecking everything, and the one intent it stages. On the mock's world, with
// ?case=merge (the Helpdesk Agent's read-only grant plus a separate close_ticket grant on Tickets MCP, and a
// project-wide search_tickets grant).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Intent, Inventory } from "../api/types";
import { buildWorld } from "../api/mockData";
import { buildModeOf, changeIntent, existingFor, initialChoice, isSame, lockedTools, modeOptions, targetOf, toolNote, toolsToday, usesHint } from "./existing";
import { READ_ONLY_EXPR, intentEnglish, intentKey, toolsExpr } from "./policy";
import { isDestructive } from "./apply";

const ctx = { project: "my-demo-project", region: "us-east4" };
let saved: PropertyDescriptor | undefined;
const setSearch = (search: string) => Object.defineProperty(globalThis, "window", { value: { location: { search } }, configurable: true });
beforeAll(() => {
  saved = Object.getOwnPropertyDescriptor(globalThis, "window");
});
afterAll(() => {
  if (saved) Object.defineProperty(globalThis, "window", saved);
  else delete (globalThis as { window?: unknown }).window;
});

function world(merge: boolean): Inventory {
  setSearch(merge ? "?case=merge" : "");
  return buildWorld(ctx).inventory;
}
const pick = (inv: Inventory) => {
  const eng = (n: string) => inv.engines.find((e) => e.display_name === n)!;
  const tickets = inv.mcp_servers.find((m) => m.display_name === "Tickets MCP")!;
  const kb = inv.agents.find((a) => a.display_name === "Knowledge Base Agent")!;
  const weather = inv.endpoints.find((e) => e.display_name === "Weather API")!;
  const src = (n: string): NonNullable<Intent["source"]> => ({ type: "engine", principal: eng(n).principal, label: n, engine: eng(n).name });
  const dst = (d: { name: string; id: string; display_name: string }, kind: "mcp_server" | "agent" | "endpoint"): NonNullable<Intent["destination"]> => ({ kind, id: d.id, name: d.name, label: d.display_name });
  return { eng, tickets, kb, weather, src, dst };
};

describe("mode detection", () => {
  it("no existing grant: new; one: change; several: change; inherited only: new (with locked tools)", () => {
    const base = world(false);
    const b = pick(base);
    expect(buildModeOf(existingFor(base, b.eng("Travel Planner").principal, b.tickets.name))).toBe("new");
    const one = existingFor(base, b.eng("Helpdesk Agent").principal, b.tickets.name);
    expect(one.own).toHaveLength(1);
    expect(buildModeOf(one)).toBe("change");

    const inv = world(true);
    const m = pick(inv);
    const several = existingFor(inv, m.eng("Helpdesk Agent").principal, m.tickets.name);
    expect(several.own.map((x) => x.condition?.expression)).toEqual([READ_ONLY_EXPR, toolsExpr(["close_ticket"])]);
    expect(buildModeOf(several)).toBe("change");

    const inherited = existingFor(inv, m.eng("Travel Planner").principal, m.tickets.name);
    expect(inherited.own).toEqual([]);
    expect(inherited.inherited.map((h) => h.via)).toEqual(["project_agents"]);
    expect(buildModeOf(inherited)).toBe("new");
    expect([...lockedTools(toolsToday(m.tickets, inherited)).keys()]).toEqual(["search_tickets"]);
  });

  it("a registry-wide grant the source matches is inherited; another member's grant isn't", () => {
    const inv = world(false);
    const m = pick(inv);
    const reg = Object.keys(inv.access).find((k) => /^projects\/[^/]+\/locations\/[^/]+$/.test(k))!;
    inv.access[reg].push({ role: "roles/iap.egressor", member: "allAuthenticatedUsers", member_label: "x", condition: null, english: "" });
    const ex = existingFor(inv, m.eng("Travel Planner").principal, m.tickets.name);
    expect(ex.inherited.map((h) => [h.via, h.resource])).toEqual([["registry_wide", reg]]);
    expect(ex.inherited.some((h) => h.binding.member.startsWith("serviceAccount:"))).toBe(false);
  });
});

describe("the tool checklist in change mode", () => {
  const inv = world(true);
  const m = pick(inv);
  const ex = existingFor(inv, m.eng("Helpdesk Agent").principal, m.tickets.name);
  const today = toolsToday(m.tickets, ex);
  const note = (t: string) => toolNote(today.find((x) => x.name === t)!);

  it("starts on Specific tools with today's tools checked, each noting the grant that allows it", () => {
    const c = initialChoice("mcp_server", ex, m.tickets);
    expect(c.mode).toBe("tools");
    expect(c.tools).toEqual(["list_tickets", "get_ticket", "search_tickets", "close_ticket"]);
    expect(note("list_tickets")).toBe("allowed today by: read-only grant");
    expect(note("close_ticket")).toBe("allowed today by: tools grant");
    expect(note("update_ticket")).toBeNull();
  });

  it("locks the tools an inherited grant allows", () => {
    const locked = lockedTools(today);
    expect([...locked.keys()]).toEqual(["search_tickets"]);
    expect(locked.get("search_tickets")!.via).toBe("project_agents");
    // not part of the change: a tools list leaves it out
    expect(targetOf({ mode: "tools", tools: ["list_tickets", "search_tickets"], expr: "" }, "mcp_server", "change", new Set(locked.keys()))).toEqual({ mode: "tools", tools: ["list_tickets"] });
  });

  it("one binding keeps its mode (the read-only hint), with today's tools ready under Specific tools", () => {
    const base = world(false);
    const b = pick(base);
    const one = existingFor(base, b.eng("Helpdesk Agent").principal, b.tickets.name);
    expect(initialChoice("mcp_server", one, b.tickets)).toEqual({ mode: "read_only_hint", tools: ["list_tickets", "get_ticket", "search_tickets"], expr: READ_ONLY_EXPR });
  });
});

describe("the choices offered", () => {
  const inv = world(true);
  const m = pick(inv);
  it("MCP, change mode: Read-only (hint) only when an existing binding uses it", () => {
    const hd = existingFor(inv, m.eng("Helpdesk Agent").principal, m.tickets.name);
    expect(usesHint(hd)).toBe(true);
    expect(modeOptions("mcp_server", "change", hd)).toEqual(["read_only_hint", "tools", "all", "custom"]);
    const hr = existingFor(inv, m.eng("HR Assistant").principal, m.tickets.name);
    expect(usesHint(hr)).toBe(false);
    expect(modeOptions("mcp_server", "change", hr)).toEqual(["tools", "all", "custom"]);
  });
  it("new grants: all four on MCP, full access elsewhere; other destinations in change mode: All / Custom", () => {
    const none = { own: [], inherited: [] };
    expect(modeOptions("mcp_server", "new", none)).toEqual(["read_only_hint", "tools", "all", "custom"]);
    expect(modeOptions("agent", "new", none)).toEqual(["all"]);
    expect(modeOptions("agent", "change", existingFor(inv, m.eng("Helpdesk Agent").principal, m.kb.name))).toEqual(["all", "custom"]);
  });
});

describe("the intent it stages", () => {
  const inv = world(true);
  const m = pick(inv);
  const hd = m.src("Helpdesk Agent");
  const tickets = m.dst(m.tickets, "mcp_server");
  const ex = existingFor(inv, hd.principal, m.tickets.name);
  const locked = new Set(lockedTools(toolsToday(m.tickets, ex)).keys());
  const build = (choice: Parameters<typeof targetOf>[0], own = ex.own, dest = tickets, kind = "mcp_server") =>
    changeIntent({ id: "x", source: hd, destination: dest, own, target: targetOf(choice, kind, own.length ? "change" : "new", locked) });

  it("several bindings → one: a modify with access_from_list (exact) and the new access", () => {
    const i = build({ mode: "tools", tools: ["list_tickets", "get_ticket", "update_ticket", "search_tickets"], expr: "" })!;
    expect(i.kind).toBe("modify");
    expect(i.access_from).toBeUndefined();
    expect(i.access_from_list).toEqual([
      { mode: "custom", expression: READ_ONLY_EXPR, title: "MCP read-only tools (by hint)" },
      { mode: "custom", expression: toolsExpr(["close_ticket"]), title: "MCP tools: close_ticket" },
    ]);
    expect(i.access).toEqual({ mode: "tools", tools: ["list_tickets", "get_ticket", "update_ticket"] });
    expect(intentEnglish(i)).toBe("Change Helpdesk Agent's access to Tickets MCP: read-only + close_ticket → list_tickets, get_ticket, update_ticket.");
  });

  it("unchecking every tool (locked ones aside): several bindings → the remove-all form; one → a revoke", () => {
    expect(targetOf({ mode: "tools", tools: ["search_tickets"], expr: "" }, "mcp_server", "change", locked)).toBe("remove");
    const all = build({ mode: "tools", tools: [], expr: "" })!;
    expect(all).toMatchObject({ kind: "modify", access_list: [] });
    expect(all.access_from_list).toHaveLength(2);
    expect(intentEnglish(all)).toBe("Remove all of Helpdesk Agent's access to Tickets MCP (2 grants): read-only + close_ticket → no access.");
    const one = build({ mode: "tools", tools: [], expr: "" }, [ex.own[0]])!;
    expect(one).toMatchObject({ kind: "revoke", access: { mode: "custom", expression: READ_ONLY_EXPR } });
    // the remove-all form and a merge of the same bindings are different changes (the cart keeps both)
    const merge = build({ mode: "tools", tools: ["list_tickets"], expr: "" })!;
    expect(intentKey(all)).not.toBe(intentKey(merge));
    expect(isDestructive(all) && !isDestructive(merge)).toBe(true);
  });

  it("one binding: a modify of exactly it; the same access is no change", () => {
    const i = build({ mode: "all", tools: [], expr: "" }, [ex.own[0]])!;
    expect(i).toMatchObject({ kind: "modify", access_from: { mode: "custom", expression: READ_ONLY_EXPR }, access: { mode: "all" } });
    expect(isSame([ex.own[0]], { mode: "read_only_hint" })).toBe(true);
    expect(build({ mode: "read_only_hint", tools: [], expr: "" }, [ex.own[0]])).toBeNull();
  });

  it("no binding: a grant (Specific tools with nothing but locked tools is incomplete)", () => {
    const i = build({ mode: "read_only_hint", tools: [], expr: "" }, [])!;
    expect(i).toMatchObject({ kind: "grant", access: { mode: "read_only_hint" } });
    expect(build({ mode: "tools", tools: ["search_tickets"], expr: "" }, [])).toBeNull();
  });

  it("other destinations: All / Custom stage a modify, Remove access a revoke; a new grant is full access", () => {
    const kb = m.dst(m.kb, "agent");
    const own = existingFor(inv, hd.principal, m.kb.name).own;
    expect(initialChoice("agent", { own, inherited: [] })).toMatchObject({ mode: "all" });
    expect(build({ mode: "all", tools: [], expr: "" }, own, kb, "agent")).toBeNull();
    const custom = build({ mode: "custom", tools: [], expr: "request.time < timestamp('2027-01-01T00:00:00Z')" }, own, kb, "agent")!;
    expect(custom).toMatchObject({ kind: "modify", access_from: { mode: "all" }, access: { mode: "custom" } });
    expect(build({ mode: "all", tools: [], expr: "", remove: true }, own, kb, "agent")).toMatchObject({ kind: "revoke", access: { mode: "all" } });
    const tp = m.src("Travel Planner");
    expect(changeIntent({ id: "g", source: tp, destination: kb, own: [], target: targetOf({ mode: "custom", tools: [], expr: "x" }, "agent", "new") })).toMatchObject({ kind: "grant", access: { mode: "all" } });
  });
});
