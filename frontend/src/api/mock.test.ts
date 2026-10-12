// The mock's modify behaves like the backend's: the same cases as backend/tests/test_modify.py (apply outcome, the
// bindings after, the diff status), then a staged modify through the mock's preflight, apply and undo.
import { beforeAll, describe, expect, it } from "vitest";
import cases from "../../../backend/tests/fixtures/modify_cases.json";
import type { Binding, Intent } from "./types";
import { buildWorld } from "./mockData";
import { mockDiff, modifyBindings } from "./mockRender";
import { ROLE, conditionFor } from "../lib/policy";
import { grantToModify } from "../lib/grants";
import { applyStream, audit, context, diff, inventory, preflight } from "./mock";
import { groupPerms } from "../steps/ContextStep";

const RES = "projects/my-demo-project/locations/us-east4/mcpServers/tickets";
const binding = (b: { member: string; expression: string | null }): Binding => ({ role: ROLE, member: b.member, member_label: "x", condition: b.expression ? { title: "t", expression: b.expression } : null, english: "" });
const intentOf = (c: (typeof cases.cases)[number]): Intent => ({
  id: "m",
  kind: "modify",
  source: { type: "custom", principal: cases.member, label: "x" },
  destination: { kind: "mcp_server", id: "tickets", name: RES, label: "Tickets MCP" },
  access_from: c.access_from as Intent["access_from"],
  access: c.access as Intent["access"],
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
