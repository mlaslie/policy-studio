// The mock's modify behaves like the backend's: the same cases as backend/tests/test_modify.py (apply outcome, the
// bindings after, the diff status), then a staged modify through the mock's preflight, apply and undo.
import { beforeAll, describe, expect, it } from "vitest";
import cases from "../../../backend/tests/fixtures/modify_cases.json";
import type { Binding, Intent } from "./types";
import { buildWorld } from "./mockData";
const world = buildWorld;
import { mockDiff, mockRender, modifyBindings } from "./mockRender";
import { changeIntent } from "../lib/existing";
import { isDestructive } from "../lib/apply";
import { ROLE, conditionFor } from "../lib/policy";
import { grantToModify } from "../lib/grants";
import { applyStream, audit, context, diff, gatewayLogs, inventory, preflight } from "./mock";
import { groupPerms } from "../steps/ContextStep";

const RES = "projects/my-demo-project/locations/us-east4/mcpServers/tickets";
const binding = (b: { member: string; expression: string | null }): Binding => ({ role: ROLE, member: b.member, member_label: "x", condition: b.expression ? { title: "t", expression: b.expression } : null, english: "" });
type Case = { access_from?: unknown; access?: unknown; access_from_list?: unknown; access_list?: unknown };
// One binding each way (access_from / access) or several (access_from_list / access_list; [] = remove all).
const intentOf = (c: Case): Intent => ({
  id: "m",
  kind: "modify",
  source: { type: "custom", principal: cases.member, label: "x" },
  destination: { kind: "mcp_server", id: "tickets", name: RES, label: "Tickets MCP" },
  ...(c.access_from ? { access_from: c.access_from as Intent["access_from"] } : {}),
  ...(c.access ? { access: c.access as Intent["access"] } : {}),
  ...(c.access_from_list ? { access_from_list: c.access_from_list as Intent["access_from_list"] } : {}),
  ...(c.access_list ? { access_list: c.access_list as Intent["access_list"] } : {}),
});

describe("modify cases shared with the backend", () => {
  it.each(cases.cases.map((c) => [c.name, c] as const))("%s", (_, c) => {
    const r = modifyBindings(c.bindings.map(binding), intentOf(c));
    expect(r.outcome).toBe(c.outcome);
    expect(r.bindings.map((b) => ({ member: b.member, expression: b.condition?.expression || null }))).toEqual(c.after);
    const w = buildWorld({ project: "my-demo-project", region: "us-east4" });
    w.inventory.access[RES] = c.bindings.map(binding);
    expect(mockDiff(w, [intentOf(c)]).items[0].status).toBe(c.status);
  });
});

describe("a modify through the mock's preflight, apply and undo", () => {
  const ctx = { project: "my-demo-project", region: "us-east4" };
  beforeAll(() => {
    Object.defineProperty(globalThis, "window", { value: { location: { search: "?fast=1" } }, configurable: true });
  });
  const run = async (intents: Intent[]) => {
    const out = [];
    for await (const e of applyStream(ctx, intents, { project: ctx.project, acknowledge_destructive: false })) out.push(e);
    return out;
  };

  it("changes the grant in place, and the undo puts it back", async () => {
    // The Tickets MCP grant with a tools condition, changed to read-only (as the builder's "Change the existing grant
    // instead" stages it).
    const g = audit(ctx).grants.find((x) => x.resource_kind === "mcp_server" && x.condition && !x.condition.expression.includes("isReadOnly"))!;
    const before = inventory(ctx).access[g.resource];
    const m = grantToModify(g, new Map(), { mode: "read_only_hint" });
    expect(m.access_from).toEqual({ mode: "custom", expression: g.condition!.expression, title: g.condition!.title });
    // ok, with the backend's warning: the read-only hint also allows read-only tools the tools list didn't name
    expect(preflight(ctx, [m]).items[0]).toMatchObject({ intent_id: m.id, status: "ok", warning: expect.stringMatching(/^This widens access: only tools .* → only read-only tools\.$/) });
    expect(diff(ctx, [m]).items[0].status).toBe("replace");

    const ev = await run([m]);
    const done = ev.find((e) => "state" in e && e.state === "verified");
    expect(done && "undo" in done && done.undo).toBeTruthy();
    const after = inventory(ctx).access[g.resource].filter((b) => b.member === g.member);
    expect(after.map((b) => b.condition?.expression)).toEqual([conditionFor({ mode: "read_only_hint" })!.expression]);
    expect(diff(ctx, [m]).items[0].status).toBe("present");               // already changed: apply skips it

    const undo = (done as { undo: Intent }).undo;
    expect(undo.kind).toBe("modify");
    await run([undo]);
    const back = inventory(ctx).access[g.resource];
    const key = (b: Binding) => `${b.member}|${b.condition?.expression ?? ""}`;
    expect(back.map(key).sort()).toEqual(before.map(key).sort());
  }, 20000);
});

describe("a modify of several bindings through the mock (?case=merge)", () => {
  const ctx = { project: "my-demo-project", region: "us-east4" };
  const run = async (intents: Intent[], ack = false) => {
    const out = [];
    for await (const e of applyStream(ctx, intents, { project: ctx.project, acknowledge_destructive: ack })) out.push(e);
    return out;
  };
  it("merges the read-only and close_ticket grants into one, verified; the undo restores both exactly", async () => {
    Object.defineProperty(globalThis, "window", { value: { location: { search: "?fast=1&case=merge" } }, configurable: true });
    const inv = inventory(ctx);
    const hd = inv.engines.find((e) => e.display_name === "Helpdesk Agent")!;
    const t = inv.mcp_servers.find((m) => m.display_name === "Tickets MCP")!;
    const before = inv.access[t.name];
    const own = before.filter((b) => b.member === hd.principal);
    expect(own).toHaveLength(2);
    const m = changeIntent({
      id: "mm",
      source: { type: "engine", principal: hd.principal, label: "Helpdesk Agent", engine: hd.name },
      destination: { kind: "mcp_server", id: t.id, name: t.name, label: "Tickets MCP" },
      own,
      target: { mode: "tools", tools: ["list_tickets", "get_ticket", "update_ticket"] },
    })!;
    expect(preflight(ctx, [m]).items[0]).toMatchObject({ status: "ok", warning: "This widens access: read-only + close_ticket → list_tickets, get_ticket, update_ticket." });
    const d = diff(ctx, [m]).items[0];
    expect(d.status).toBe("replace");
    expect(d.after?.map((b) => b.condition?.expression)).toEqual([conditionFor({ mode: "tools", tools: ["list_tickets", "get_ticket", "update_ticket"] })!.expression]);
    const r = mockRender(ctx, world(ctx), [m]).items[0];
    expect(r.english).toBe("Change Helpdesk Agent's access to Tickets MCP: read-only + close_ticket → list_tickets, get_ticket, update_ticket.");
    expect(r.outputs.gcloud).toContain("--argjson froms");
    expect(r.outputs.python).toContain("modify_many(");

    const ev = await run([m]);
    const done = ev.find((e) => "state" in e && e.state === "verified") as { undo: Intent; detail: string };
    expect(done.detail).toBe("Read back: the new binding is there and the old ones are gone.");
    expect(inventory(ctx).access[t.name].filter((b) => b.member === hd.principal)).toHaveLength(1);
    expect(done.undo).toMatchObject({ kind: "modify", access_list: [{ mode: "custom", expression: own[0].condition!.expression }, { mode: "custom", expression: own[1].condition!.expression }] });
    await run([done.undo]);
    const key = (b: Binding) => `${b.member}|${b.condition?.expression ?? ""}|${b.condition?.title ?? ""}`;
    expect(inventory(ctx).access[t.name].map(key).sort()).toEqual(before.map(key).sort());
  }, 20000);

  it("the remove-all form is destructive: it needs the acknowledgement", async () => {
    const inv = inventory(ctx);
    const hd = inv.engines.find((e) => e.display_name === "Helpdesk Agent")!;
    const t = inv.mcp_servers.find((m) => m.display_name === "Tickets MCP")!;
    const own = inv.access[t.name].filter((b) => b.member === hd.principal);
    const m = changeIntent({ id: "ra", source: { type: "engine", principal: hd.principal, label: "Helpdesk Agent", engine: hd.name }, destination: { kind: "mcp_server", id: t.id, name: t.name, label: "Tickets MCP" }, own, target: "remove" })!;
    expect(isDestructive(m)).toBe(true);
    await expect(run([m])).rejects.toThrow(/acknowledge_destructive/);
    expect(diff(ctx, [m]).items[0].status).toBe("remove");
    Object.defineProperty(globalThis, "window", { value: { location: { search: "?fast=1" } }, configurable: true });
  });
});

describe("a modify on an entry registered in the same cart", () => {
  const ctx = { project: "my-demo-project", region: "us-east4" };
  it("looks the entry id up and uses the variable, like the backend's render", () => {
    const base = { ...intentOf({ access_from: { mode: "all" }, access: { mode: "read_only_hint" } }), destination: { kind: "mcp_server" as const, id: "", name: "", label: "Notes MCP", pending_service: "notes-mcp" } };
    const many = { ...base, id: "m2", access_from: undefined, access: undefined, access_from_list: [{ mode: "all" as const }, { mode: "read_only_hint" as const }], access_list: [{ mode: "read_only_hint" as const }] };
    for (const m of [base, many]) {
      const o = mockRender(ctx, world(ctx), [m]).items[0].outputs;
      expect(o.gcloud).toContain('--mcp-server="$ENTRY_NOTES_MCP"');
      expect(o.gcloud).toContain("services describe notes-mcp");
      expect(o.rest).toContain("services describe notes-mcp");
      expect(o.terraform).toContain("basename(google_agent_registry_service.registry_notes_mcp.registry_resource)");
    }
  });
});

describe("dry-run would-deny, like the backend's dryrun.check", () => {
  const ctx = { project: "my-demo-project", region: "us-east4" };
  it("no grant on the destination or the registry is unknown (grants above it aren't read); a limited grant is would_deny", () => {
    const r = gatewayLogs(ctx, "projects/my-demo-project/locations/us-east4/agentGateways/corp-egress", "24h");
    const none = r.entries.find((e) => e.reason?.includes("holds no roles/iap.egressor grant"))!;
    expect(none.decision).toBe("unknown");
    expect(none.reason).toContain("grants above the registry (project, folder, organization) aren't read");
    const limited = r.entries.filter((e) => e.decision === "would_deny");
    expect(limited.length).toBeGreaterThan(0);
    expect(limited.every((e) => e.reason?.includes("is limited"))).toBe(true);
  });
});

describe("Context step permissions (the duplicate-key fix)", () => {
  it("the mock lists each permission once (the read-back purpose joins the existing read permission)", () => {
    Object.defineProperty(globalThis, "window", { value: { location: { search: "" } }, configurable: true });
    const perms = context({ project: "my-demo-project", region: "us-east4" }).permissions;
    const names = perms.map((p) => p.permission);
    expect(new Set(names).size).toBe(names.length);
    expect(perms.find((p) => p.permission === "iap.webServices.getIamPolicy")).toMatchObject({ granted: true, write: false, role: "roles/iap.admin", needed_for: expect.stringContaining("read grants back after Apply") });
  });

  it("rows have unique keys even when a permission is listed twice", () => {
    const p = { permission: "iap.webServices.getIamPolicy", granted: true, needed_for: "a" };
    const keys = groupPerms([p, { ...p, needed_for: "b" }, { permission: "x.y.z", granted: false, needed_for: "c", fix: "cmd" }]).map((g) => g.key);
    expect(keys).toEqual(["iap.webServices.getIamPolicy", "iap.webServices.getIamPolicy#2", "x.y.z"]);
  });
});
