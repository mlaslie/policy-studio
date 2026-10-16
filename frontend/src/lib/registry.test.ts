// Agent Registry entries (registry_service): the builder's form checks, the create + grant it stages (and their apply
// order in the mock), the map's pending destination nodes, the mock's preflight, and the private-domain hint.
import { beforeAll, describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Ctx, Intent } from "../api/types";
import { applyStream, inventory, preflight, render } from "../api/mock";
import { mockDiff } from "../api/mockRender";
import { approve, openPreview } from "../preview/flow";
import { previewModel } from "../preview/changes";
import { buildPolicyGraph } from "../map/graph";
import { diffGraphs, mergeStaged } from "../map/diff";
import { simulate } from "../map/simulate";
import { isDestructive } from "./apply";
import { intentKey } from "./policy";
import {
  checkForm,
  createIntent,
  deleteIntent,
  emptyForm,
  normUrl,
  parseTools,
  pendingDestination,
  pendingEntryName,
  privateDomainMatch,
  privateGateways,
  registryEnglish,
  runAppForm,
  runAppHint,
  suggestServiceId,
  urlProblem,
  type RegForm,
} from "./registry";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const w0 = buildWorld(CTX);
const inv = w0.inventory;
const hd = inv.engines.find((e) => e.display_name === "Helpdesk Agent")!;
const RUN_A = "https://notes-mcp-123456789012.us-east4.run.app/mcp";
const RUN_B = "https://notes-mcp-x7k2p9q-uk.a.run.app/mcp";

const form = (p: Partial<RegForm> = {}): RegForm => ({ ...emptyForm("mcp_server"), display_name: "Notes MCP", service_id: "notes-mcp", rows: [{ url: RUN_A, protocol_binding: "JSONRPC" }, { url: RUN_B, protocol_binding: "JSONRPC" }], ...p });
const grantOn = (create: Intent, mode: "all" | "read_only_hint" = "read_only_hint"): Intent => ({
  id: "g1",
  kind: "grant",
  source: { type: "engine", principal: hd.principal, label: hd.display_name, engine: hd.name },
  destination: pendingDestination(create),
  access: { mode },
});

describe("URL helpers (as the backend's gcp/registry.py)", () => {
  it("checks scheme, wildcard and host", () => {
    expect(urlProblem("https://x.example/mcp")).toBeNull();
    expect(urlProblem("http://x.example")).toMatch(/isn't https/);
    expect(urlProblem("https://*.example.com")).toMatch(/wildcard/);
    expect(urlProblem("https:///x")).toMatch(/no host/);
    expect(urlProblem("")).toMatch(/empty/);
    expect(normUrl("HTTPS://X.Example/mcp/")).toBe("https://x.example/mcp");
  });
  it("tells the two run.app forms apart and asks for the other one", () => {
    expect(runAppForm(RUN_A)).toBe("number");
    expect(runAppForm(RUN_B)).toBe("hash");
    expect(runAppForm("https://api.example.com")).toBeNull();
    expect(runAppHint([RUN_A, RUN_B])).toBeNull();
    expect(runAppHint([RUN_B])).toMatch(/also register the other run.app URL shown on the Cloud Run page/);
  });
  it("suggests a valid service id from the name", () => {
    expect(suggestServiceId("Notes MCP (prod)")).toBe("notes-mcp-prod");
    expect(suggestServiceId("42 Orders")).toBe("orders");
    expect(suggestServiceId("AB")).toBe("ab-svc");
    expect(suggestServiceId("!!!")).toBe("");
  });
  it("reads a tools/list response", () => {
    expect(parseTools("").spec).toBeNull();
    expect(parseTools('{"tools":[{"name":"read_note","annotations":{"readOnlyHint":true}}]}').spec?.tools).toHaveLength(1);
    expect(parseTools('{"result":{"tools":[{"name":"a"}]}}').spec?.tools).toHaveLength(1);
    expect(parseTools("{").error).toMatch(/JSON/);
    expect(parseTools('{"tools":[{"x":1}]}').error).toMatch(/tools\/list/);
  });
});

describe("private-domain hint", () => {
  it("matches a host under a domain with a trailing dot, not a look-alike", () => {
    expect(privateDomainMatch("https://x.run.app/mcp", ["run.app."])).toBe("run.app.");
    expect(privateDomainMatch("https://run.app.evil.com", ["run.app."])).toBeNull();
    expect(privateDomainMatch("https://evilrun.app", ["run.app."])).toBeNull();
    expect(privateDomainMatch("https://RUN.APP", ["run.app."])).toBe("run.app.");
    expect(privateDomainMatch("https://db.eu.corp.internal:8443/x", ["run.app.", "corp.internal."])).toBe("corp.internal.");
    expect(privateDomainMatch("https://a.b.corp.internal", ["corp.internal.", "b.corp.internal."])).toBe("b.corp.internal.");
    expect(privateDomainMatch("not a url", ["run.app."])).toBeNull();
  });
  it("lists only egress gateways whose private egress has domains", () => {
    const gws = privateGateways(w0.gateways);
    expect(gws.every((g) => g.domains.length > 0)).toBe(true);
    expect(gws.some((g) => g.domains.includes("run.app."))).toBe(true);
  });
});

describe("the builder's form", () => {
  it("accepts a good MCP server and warns about the missing tool list", () => {
    const c = checkForm(form(), { inv, region: "us-east4" });
    expect(c.ok).toBe(true);
    expect(c.warnings.join(" ")).toMatch(/No tool list/);
    expect(checkForm(form({ tools_json: '{"tools":[{"name":"read_note"}]}' }), { inv, region: "us-east4" }).warnings).toEqual([]);
  });
  it("blocks what preflight would block", () => {
    const at = (rows: string[], p: Partial<RegForm> = {}) => checkForm(form({ rows: rows.map((url) => ({ url, protocol_binding: "JSONRPC" })), ...p }), { inv, region: "us-east4" });
    expect(at(["http://x.example"]).rowErrors[0]).toMatch(/isn't https/);
    expect(at(["https://*.run.app"]).rowErrors[0]).toMatch(/wildcard/);
    expect(at([RUN_A, RUN_A]).rowErrors[1]).toBe("Listed twice.");
    const dup = at(["https://tickets-mcp-a1b2c3-uk.a.run.app/mcp/"]);
    expect(dup.ok).toBe(false);
    expect(dup.rowErrors[0]).toMatch(/Duplicate: already registered as Tickets MCP/);
    expect(at([""]).errors.rows).toMatch(/at least one URL/);
    expect(at([RUN_A], { service_id: "Bad_Id" }).errors.service_id).toMatch(/lowercase/);
    expect(at([RUN_A], { service_id: "tickets-mcp" }).errors.service_id).toMatch(/already exists/);
    expect(at([RUN_A], { display_name: "" }).errors.display_name).toBeTruthy();
    expect(at([RUN_A], { kind: "mcp_server", tools_json: "{" }).errors.tools_json).toBeTruthy();
    expect(checkForm(form(), { inv, region: "us" }).errors.region).toMatch(/single region/);
    expect(at([RUN_A]).warnings.join(" ")).toMatch(/other run.app URL/);
  });
  it("blocks an id or URL another create in the cart already uses", () => {
    const cart = [createIntent(form())];
    const c = checkForm(form({ service_id: "notes-two", rows: [{ url: RUN_B, protocol_binding: "JSONRPC" }] }), { inv, region: "us-east4", cart });
    expect(c.rowErrors[0]).toMatch(/also registered by notes-mcp in the cart/);
    expect(checkForm(form(), { inv, region: "us-east4", cart }).errors.service_id).toMatch(/already staged/);
  });
});

describe("create + grant in one flow", () => {
  const create = createIntent(form(), "reg1");
  const grant = grantOn(create);
  it("builds the create and a grant that names the new entry's service", () => {
    expect(create).toMatchObject({ kind: "registry_service", params: { kind: "mcp_server", service_id: "notes-mcp", interfaces: [{ url: RUN_A }, { url: RUN_B }] } });
    expect(grant.destination).toEqual({ kind: "mcp_server", id: "", name: pendingEntryName("notes-mcp"), label: "Notes MCP", pending_service: "notes-mcp" });
    expect(registryEnglish(create)).toBe(`Register MCP server Notes MCP (notes-mcp) in Agent Registry, at 2 URLs: ${RUN_A}, ${RUN_B}.`);
    expect(isDestructive(create)).toBe(false);
    expect(isDestructive(deleteIntent(inv.services![0]))).toBe(true);
    // two grants on different new entries aren't the same change
    const other = grantOn(createIntent(form({ service_id: "notes-two" })));
    expect(intentKey(grant)).not.toBe(intentKey(other));
  });
  it("stages the create before the grant (the preview's Approve)", () => {
    const { effect } = approve(openPreview(grant, [create], false), () => "g-final");
    expect(effect.kind).toBe("stage");
    if (effect.kind === "stage") expect(effect.intents.map((i) => i.kind)).toEqual(["registry_service", "grant"]);
  });
  it("previews both: the new entry, and the grant on it", () => {
    const m = previewModel({ intent: grant, inv, extras: [create] });
    expect(m.kind).toBe("grant");
    expect(m.warnings.map((w) => w.id)).toEqual(expect.arrayContaining(["new_entry", "no_tools"]));
    expect(m.added).toHaveLength(1);
  });
  it("renders the grant with the entry id looked up (mock)", () => {
    const r = render(CTX, [create, grant]);
    expect(r.items[0].outputs.gcloud).toMatch(/gcloud agent-registry services create notes-mcp/);
    expect(r.items[0].outputs.gcloud.match(/--interfaces=/g)).toHaveLength(2);
    expect(r.items[1].outputs.gcloud).toMatch(/--mcp-server="\$ENTRY_NOTES_MCP"/);
    expect(r.items[1].outputs.terraform).toMatch(/basename\(google_agent_registry_service\.registry_notes_mcp\.registry_resource\)/);
    expect(mockDiff(w0, [create, grant]).items.map((x) => x.status)).toEqual(["add", "add"]);
  });
});

describe("map: pending registry nodes", () => {
  const input = { direction: "egress" as const, ctx: CTX };
  const staged = (cart: Intent[]) => {
    const st = { inventory: inv, gateways: w0.gateways, modelArmor: w0.modelArmor };
    const sim = simulate(st, cart);
    const before = buildPolicyGraph({ ...input, ...st });
    const after = buildPolicyGraph({ ...input, inventory: sim.inventory, gateways: sim.gateways, modelArmor: sim.modelArmor });
    return { sim, merged: mergeStaged(before, after, diffGraphs(before, after), cart, inv, sim.effects) };
  };
  it("draws a staged create as a pending destination, with the grant's line into it", () => {
    const create = createIntent(form(), "reg1");
    const grant = grantOn(create, "all");
    const { sim, merged } = staged([create, grant]);
    const name = pendingEntryName("notes-mcp");
    expect(sim.effects.reg1).toEqual([name]);
    const n = merged.nodes.find((x) => x.id === name)!;
    expect(n).toBeTruthy();
    expect(n.pending).toMatchObject({ added: true, intents: ["reg1"] });
    expect(n.chips.some((c) => c.text === "New entry (staged)" && c.pending)).toBe(true);
    const e = merged.edges.find((x) => x.caller === hd.name && x.target === name && !x.implicit);
    expect(e?.pending).toBe("add");
  });
  it("draws a staged delete as a pending removal (its grants go with it)", () => {
    const svc = inv.services!.find((s) => s.id === "weather-api")!;
    const entry = inv.endpoints.find((x) => x.service === svc.name)!;
    const del = deleteIntent(svc, "del1");
    const { sim, merged } = staged([del]);
    expect(sim.inventory.endpoints.some((x) => x.name === entry.name)).toBe(false);
    expect(sim.inventory.access[entry.name]).toBeUndefined();
    const n = merged.nodes.find((x) => x.id === entry.name)!;
    expect(n.pending).toMatchObject({ removed: true, intents: ["del1"] });
    expect(n.chips.some((c) => c.text === "Deletion staged")).toBe(true);
    expect(merged.edges.filter((x) => x.target === entry.name && x.pending === "remove").length).toBeGreaterThan(0);
  });
});

describe("the mock's preflight and apply", () => {
  beforeAll(() => {
    Object.defineProperty(globalThis, "window", { value: { location: { search: "?fast=1" } }, configurable: true });
  });
  const run = async (intents: Intent[], ack = false) => {
    const out = [];
    for await (const e of applyStream(CTX, intents, { project: CTX.project, acknowledge_destructive: ack })) out.push(e);
    return out;
  };
  const final = (evs: Awaited<ReturnType<typeof run>>) => Object.fromEntries(evs.filter((e) => "intent_id" in e && !e.progress && ["verified", "failed", "skipped"].includes(e.state)).map((e) => ["intent_id" in e ? e.intent_id : "", e]));

  it("blocks a duplicate URL and warns about one run.app form", () => {
    const dup = createIntent(form({ rows: [{ url: "https://tickets-mcp-a1b2c3-uk.a.run.app/mcp", protocol_binding: "JSONRPC" }] }), "dup");
    const one = createIntent(form({ service_id: "notes-one", rows: [{ url: RUN_A, protocol_binding: "JSONRPC" }] }), "one");
    const lone = grantOn(createIntent(form({ service_id: "not-staged" })));
    const items = Object.fromEntries(preflight(CTX, [dup, one, { ...lone, id: "lone" }]).items.map((i) => [i.intent_id, i]));
    expect(items.dup).toMatchObject({ status: "blocked", fix: "duplicate" });
    expect(items.dup.reason).toMatch(/already registered in us-east4 as Tickets MCP/);
    expect(items.one).toMatchObject({ status: "ok" });
    expect(items.one.warning).toMatch(/other run.app URL/);
    expect(items.lone).toMatchObject({ status: "blocked" });
    expect(items.lone.reason).toMatch(/isn't registered by an item in this request/);
    const w = preflight({ ...CTX, region: "us" }, [one]).items[0];
    expect(w.status).toBe("blocked");
  });
  it("warns that a delete removes the entry's grants", () => {
    const svc = inv.services!.find((s) => s.id === "weather-api")!;
    const p = preflight(CTX, [deleteIntent(svc, "d")]).items[0];
    expect(p.status).toBe("ok");
    expect(p.warning).toMatch(/^1 grant on this entry will be removed/);
  });
  it("registers first, grants on the new id, then undoes both", async () => {
    const create = createIntent(form({ service_id: "notes-run", rows: [{ url: "https://notes-run-123456789012.us-east4.run.app/mcp", protocol_binding: "JSONRPC" }, { url: "https://notes-run-x7k2p9q-uk.a.run.app/mcp", protocol_binding: "JSONRPC" }] }), "reg");
    const grant = grantOn(create);
    const evs = await run([grant, create]);
    const f = final(evs);
    expect(f.reg.state).toBe("verified");
    expect(f.g1.state).toBe("verified");
    const running = evs.filter((e) => "intent_id" in e && e.state === "running").map((e) => ("intent_id" in e ? e.intent_id : ""));
    expect(running.indexOf("reg")).toBeLessThan(running.indexOf("g1"));
    const after = inventory(CTX);
    const entry = after.mcp_servers.find((m) => m.service?.endsWith("/services/notes-run"))!;
    expect(entry.urls).toHaveLength(2);
    expect(after.access[entry.name].map((b) => b.member)).toEqual([hd.principal]);
    const ug = f.g1.undo as Intent;
    const ur = f.reg.undo as Intent;
    expect(ug.kind).toBe("revoke");
    expect(ug.destination?.name).toBe(entry.name);
    expect(ur.params?.delete).toBe(true);
    await expect(run([ur, ug])).rejects.toThrow(/acknowledge_destructive/);
    const f2 = final(await run([ur, ug], true));
    expect(f2[ur.id].state).toBe("verified");
    expect(inventory(CTX).services!.some((s) => s.id === "notes-run")).toBe(false);
    // the undo of the delete registers it again with the same body: a new entry, without the grant
    const again = f2[ur.id].undo as Intent;
    expect(again.params?.delete).toBeFalsy();
    expect(again.params).toMatchObject({ service_id: "notes-run", interfaces: create.params!.interfaces });
    const f3 = final(await run([again]));
    expect(f3[again.id].state).toBe("verified");
    const back = inventory(CTX).mcp_servers.find((m) => m.service?.endsWith("/services/notes-run"))!;
    expect(back.name).not.toBe(entry.name);
    expect(inventory(CTX).access[back.name]).toEqual([]);
  }, 30_000);
});
