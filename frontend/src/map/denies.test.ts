// Default deny on the policy map: a destination (or an MCP tool) is denied for an agent only when no grant applies to
// it at all, inherited ones included; the Agent Registry node is never denied; the type filters take the group nodes
// with them. Over the mock's us-central1 world (corp-egress in ENFORCE), set up like the screenshot this was reported
// from: Helpdesk Agent selected, only MCP servers checked, Show: Denies only, Inherited grants off.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Binding, Ctx } from "../api/types";
import { ROLE, toolsExpr } from "../lib/policy";
import { NOGW, PSEUDO, buildPolicyGraph, type GraphInput, type PEdge, type PolicyGraph } from "./graph";
import { DEFAULT_FILTERS, DEST_TYPES, GOOGLE_GROUP, destType, viewOf, type DestType, type MapFilters } from "./view";
import { isGoogleApi } from "./labels";
import { DEFAULT_PICKER, countGrouped, pickerItems, pickerStatus, setTypes, typeState, type PickerEnv } from "./picker";
import { toolStatesOf } from "./toFlow";

const CTX: Ctx = { project: "my-demo-project", region: "us-central1" };
const REG_RE = /^projects\/[^/]+\/locations\/[^/]+$/;

/** The us-central1 world with every readable Google API endpoint granted project-wide (principalSet), like the
 *  screenshot ("+25 inherited"); `tweak` changes it further. */
function world(tweak?: (w: ReturnType<typeof buildWorld>, grant: (member: string, expression?: string) => Binding) => void) {
  const w = buildWorld(CTX);
  const set = w.inventory.project_agents_principal!;
  const grant = (member: string, expression?: string): Binding => ({ role: ROLE, member, member_label: member, condition: expression ? { title: "t", expression } : null, english: "" });
  for (const e of w.inventory.endpoints) if (isGoogleApi(e.url) && w.inventory.access[e.name]) w.inventory.access[e.name] = [grant(set)];
  tweak?.(w, grant);
  return w;
}
const graphOf = (w: ReturnType<typeof buildWorld>, extra: Partial<GraphInput> = {}): PolicyGraph =>
  buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction: "egress", ...extra });
const filters = (f: Partial<MapFilters> = {}): MapFilters => ({ ...DEFAULT_FILTERS, ...f });
const w0 = world();
const inv = w0.inventory;
const hd = inv.engines.find((e) => e.display_name === "Helpdesk Agent")!;
const REG = Object.keys(inv.access).find((k) => REG_RE.test(k))!;
const google = inv.endpoints.filter((e) => isGoogleApi(e.url) && inv.access[e.name]);
const mcpId = (name: string) => inv.mcp_servers.find((m) => m.display_name === name)!.name;
/** The screenshot's filters: only MCP servers checked, Denies only, Inherited grants off. */
const SHOT: Partial<MapFilters> = { typesOff: ["a2a", "runtime", "api", "google"], allows: false, denies: true, inherited: false };
const SHOWS = [true, false].flatMap((allows) => [true, false].flatMap((denies) => [true, false].map((inherited) => ({ allows, denies, inherited }))));
/** Every line a view draws, the lines merged into the Google APIs group included. */
const drawn = (es: PEdge[]) => es.flatMap((e) => [e, ...(e.members ?? [])]);

describe("the screenshot: Helpdesk Agent, MCP servers only, Denies only, Inherited grants off", () => {
  const g = graphOf(w0, { inherited: false });
  const v = viewOf(g, filters(SHOT), [hd.name]);
  const byId = new Map(g.nodes.map((n) => [n.id, n]));

  it("no API endpoint, Google API or registry node, nor a line to one", () => {
    const kinds = new Set(v.nodes.filter((n) => n.column === "dests").map((n) => n.kind));
    expect([...kinds]).toEqual(["mcp"]);
    expect(v.nodes.some((n) => n.id === GOOGLE_GROUP || n.id === REG || n.kind === "endpoint_group")).toBe(false);
    for (const e of drawn(v.edges)) expect(["endpoint", "google_apis", "registry", "endpoint_group"]).not.toContain(byId.get(e.target)?.kind ?? (e.target === GOOGLE_GROUP ? "google_apis" : "?"));
  });

  it("only MCP deny lines, and only for the tools no grant allows", () => {
    const lines = v.edges.filter((e) => e.verdict !== "path");
    expect(lines.length).toBeGreaterThan(0);
    for (const e of lines) {
      expect(byId.get(e.target)?.kind).toBe("mcp");
      expect(e.verdict).toBe("blocked");
    }
    // Tickets MCP: its own read-only grant allows the read tools; the deny line shows just the write tools
    const t = lines.find((e) => e.target === mcpId("Tickets MCP"))!;
    expect(t.shownTools!.sort()).toEqual([...t.tools!.denied].sort());
    expect(t.shownTools!.some((x) => t.tools!.allowed.includes(x))).toBe(false);
    // HR Directory MCP: no grant at all, denied whole
    expect(lines.find((e) => e.target === mcpId("HR Directory MCP"))).toMatchObject({ implicit: true, verdict: "blocked" });
  });

  it("the agent's chips: denied by default counts only destinations no grant reaches, the registry left out", () => {
    const n = g.nodes.find((x) => x.id === hd.name)!;
    const denied = new Set(g.edges.filter((e) => e.caller === hd.name && e.implicit).map((e) => e.target));
    expect(n.deniedCount).toBe(denied.size);
    expect(denied.has(REG)).toBe(false);
    for (const e of google) expect(denied.has(e.name)).toBe(false);
    expect(n.chips.map((c) => c.text)).toContain(`Denied by default: ${denied.size}`);
    // the same with Inherited grants on
    const on = graphOf(w0).nodes.find((x) => x.id === hd.name)!;
    expect([on.deniedCount, on.inheritedCount, on.allowedCount]).toEqual([n.deniedCount, n.inheritedCount, n.allowedCount]);
  });

  it("the picker agrees: the APIs box and the Google APIs and API endpoints groups read unchecked, nothing in a group", () => {
    const env: PickerEnv = { graph: g, tools: { gateway: "all", expanded: [], hidden: [], inherited: false, allows: false, denies: true } };
    const d = { ...DEFAULT_PICKER, typesOff: SHOT.typesOff!, selected: [hd.name] };
    const s = pickerStatus(env, d);
    const items = pickerItems(g);
    expect(typeState(s, items, ["api", "google"], d)).toBe("none");
    expect(typeState(s, items, ["google"], d)).toBe("none");
    expect(countGrouped(s, items.filter((i) => i.group === "google" || i.group === "api"))).toBe(0);
    for (const i of items.filter((x) => x.group === "google" || x.group === "api")) expect(s.get(i.id)).toMatchObject({ on: false, hidden: "type" });
    // the registry node: MCP servers are on, but no registry-wide grant applies to the agent
    expect(s.get(REG)).toMatchObject({ on: false, hidden: "noGrants" });
    expect(typeState(s, items, ["mcp"], d)).not.toBe("none");
  });
});

describe("a destination reached only through an inherited grant is never denied", () => {
  it("a Google API endpoint granted project-wide: no deny line under any Show combination, grouped or not", () => {
    for (const { allows, denies, inherited } of SHOWS)
      for (const googleApis of [false, true]) {
        const g = graphOf(w0, { inherited });
        const v = viewOf(g, filters({ allows, denies, inherited, googleApis }), [hd.name]);
        const into = drawn(v.edges).filter((e) => google.some((x) => x.name === e.target) || e.target === GOOGLE_GROUP);
        expect(into.some((e) => e.implicit || e.verdict === "blocked")).toBe(false);
        // drawn only as the inherited allow line, with Allows and Inherited grants on
        const want = allows && inherited;
        expect(into.length > 0).toBe(want);
        if (want) expect(into.every((e) => e.inherited && e.verdict === "allowed")).toBe(true);
        expect(g.edges.some((e) => e.caller === hd.name && e.implicit && google.some((x) => x.name === e.target))).toBe(false);
      }
  });

  it("the default-deny lines and the chip are the same with Inherited grants on or off", () => {
    const deny = (g: PolicyGraph, c: string) => g.edges.filter((e) => e.caller === c && e.implicit).map((e) => e.target).sort();
    const on = graphOf(w0);
    const off = graphOf(w0, { inherited: false });
    for (const e of inv.engines) {
      expect(deny(off, e.name)).toEqual(deny(on, e.name));
      const a = on.nodes.find((n) => n.id === e.name)!;
      const b = off.nodes.find((n) => n.id === e.name)!;
      expect(b.deniedCount).toBe(a.deniedCount);
      // every default-deny line is counted, and only those
      expect(a.deniedCount).toBe(new Set(deny(on, e.name)).size);
    }
  });

  it("an MCP tool allowed only through an inherited grant isn't shown as denied", () => {
    // HR Directory MCP: no grant for the Helpdesk Agent, but every agent may call lookup_employee (project-wide)
    const w = world((x, grant) => {
      const hr = x.inventory.mcp_servers.find((m) => m.display_name === "HR Directory MCP")!;
      x.inventory.access[hr.name].push(grant(x.inventory.project_agents_principal!, toolsExpr(["lookup_employee"])));
    });
    const hrdir = w.inventory.mcp_servers.find((m) => m.display_name === "HR Directory MCP")!;
    for (const inherited of [true, false]) {
      const g = graphOf(w, { inherited });
      const v = viewOf(g, filters({ allows: false, denies: true, inherited }), [hd.name]);
      const e = v.edges.find((x) => x.target === hrdir.name)!;
      expect(e.verdict).toBe("blocked");
      expect(e.shownTools).not.toContain("lookup_employee");
      expect(e.shownTools).toHaveLength(5);
      const node = g.nodes.find((n) => n.id === hrdir.name)!;
      expect(toolStatesOf(e, node)?.lookup_employee).not.toBe("denied");
      expect(v.nodes.find((n) => n.id === hrdir.name)!.shownTools).not.toContain("lookup_employee");
      // Allows only: the inherited tool is drawn with Inherited grants on, nothing with them off
      const a = viewOf(g, filters({ allows: true, denies: false, inherited }), [hd.name]).edges.find((x) => x.target === hrdir.name);
      if (inherited) expect(a).toMatchObject({ verdict: "allowed", inherited: true, shownTools: ["lookup_employee"] });
      else expect(a).toBeUndefined();
    }
  });

  it("on the agent's own MCP line, a tool only an inherited grant allows is set aside (Inherited off), not denied", () => {
    // Tickets MCP: the Helpdesk Agent's own read-only grant, and close_ticket for every agent (project-wide)
    const w = world((x, grant) => {
      const t = x.inventory.mcp_servers.find((m) => m.display_name === "Tickets MCP")!;
      x.inventory.access[t.name].push(grant(x.inventory.project_agents_principal!, toolsExpr(["close_ticket"])));
    });
    const t = w.inventory.mcp_servers.find((m) => m.display_name === "Tickets MCP")!;
    const own = graphOf(w, { inherited: false }).edges.find((e) => e.id === `a:${hd.name}|${t.name}`)!;
    expect(own.tools!.inherited).toEqual(["close_ticket"]);
    expect(own.tools!.denied).not.toContain("close_ticket");
    const v = viewOf(graphOf(w, { inherited: false }), filters({ allows: false, inherited: false }), [hd.name]).edges.find((e) => e.target === t.name)!;
    expect(v.shownTools).not.toContain("close_ticket");
    expect(v.hiddenTools).toMatchObject({ inherited: 1 });
  });
});

describe("pseudo nodes never get a default-deny line", () => {
  it("not the Agent Registry node, nor the pseudo callers, the No gateway lane or Anywhere", () => {
    const pseudo = [REG, PSEUDO.project, PSEUDO.public, PSEUDO.other, PSEUDO.anywhere, NOGW.egress];
    for (const region of ["us-east4", "us-central1", "europe-west1"])
      for (const inherited of [true, false]) {
        const w = buildWorld({ ...CTX, region });
        const g = graphOf(w, { inherited });
        const reg = Object.keys(w.inventory.access).find((k) => REG_RE.test(k));
        expect(g.edges.filter((e) => e.implicit && (pseudo.includes(e.target) || e.target === reg))).toEqual([]);
      }
  });

  it("the registry node: shown for a selected agent only when a registry-wide grant applies to it", () => {
    const g = graphOf(w0);
    // nothing selected: ops-bot's registry-wide grant (Other principals) puts it on the map
    expect(viewOf(g, filters(), []).nodes.some((n) => n.id === REG)).toBe(true);
    // Helpdesk Agent: the grant isn't its, so the registry node goes, under any Show
    for (const { allows, denies, inherited } of SHOWS) expect(viewOf(graphOf(w0, { inherited }), filters({ allows, denies, inherited }), [hd.name]).nodes.some((n) => n.id === REG)).toBe(false);
    // its own registry-wide grant: shown with Allows (whatever Inherited), an allow line, never a deny
    const mine = world((x, grant) => void (x.inventory.access[REG] = [grant(hd.principal)]));
    for (const inherited of [true, false]) {
      const gm = graphOf(mine, { inherited });
      const v = viewOf(gm, filters({ inherited }), [hd.name]);
      expect(v.nodes.some((n) => n.id === REG)).toBe(true);
      expect(v.edges.find((e) => e.target === REG)).toMatchObject({ verdict: "allowed", inherited: false });
      expect(viewOf(gm, filters({ inherited, allows: false }), [hd.name]).nodes.some((n) => n.id === REG)).toBe(false);
    }
    // a project-wide registry-wide grant: inherited, so shown only with Inherited grants (and Allows) on
    const set = world((x, grant) => void (x.inventory.access[REG] = [grant(x.inventory.project_agents_principal!)]));
    expect(viewOf(graphOf(set), filters(), [hd.name]).edges.find((e) => e.target === REG)).toMatchObject({ verdict: "allowed", inherited: true });
    expect(viewOf(graphOf(set, { inherited: false }), filters({ inherited: false }), [hd.name]).nodes.some((n) => n.id === REG)).toBe(false);
    // and it isn't counted as a destination: same chips as without it
    const plain = graphOf(world()).nodes.find((n) => n.id === hd.name)!;
    const withSet = graphOf(set).nodes.find((n) => n.id === hd.name)!;
    expect([withSet.allowedCount, withSet.deniedCount]).toEqual([plain.allowedCount, 0]);
  });

  it("the registry node follows the type filter: on while any destination type is", () => {
    const g = graphOf(w0);
    expect(viewOf(g, filters({ typesOff: ["a2a", "runtime", "api", "google"] }), []).nodes.some((n) => n.id === REG)).toBe(true);
    expect(viewOf(g, filters({ typesOff: [...DEST_TYPES] }), []).nodes.some((n) => n.id === REG)).toBe(false);
  });
});

describe("type filters remove grouped nodes", () => {
  const g = graphOf(w0);
  /** The type of a node the view draws, group nodes included. */
  const typeOf = (id: string, v: ReturnType<typeof viewOf>) => {
    const n = v.nodes.find((x) => x.id === id) ?? g.nodes.find((x) => x.id === id);
    return n ? destType(n) : null;
  };
  it.each(DEST_TYPES.map((t) => [t]))("%s off: no node of that type, no group of it, no line to either", (t: DestType) => {
    for (const sel of [[], [hd.name]]) {
      const base = viewOf(g, filters(), sel);
      // grouped by default (Google APIs collapsed, "no grants" groups): the type is on the map before
      expect(base.nodes.some((n) => destType(n) === t)).toBe(true);
      const v = viewOf(g, filters({ typesOff: [t] }), sel);
      expect(v.nodes.filter((n) => destType(n) === t)).toEqual([]);
      expect(drawn(v.edges).filter((e) => typeOf(e.target, v) === t)).toEqual([]);
    }
  });

  it("APIs off (the toolbar box): no API endpoint, no Google APIs group, no API endpoints \"no grants\" group", () => {
    const v = viewOf(g, filters({ typesOff: ["api", "google"] }), [hd.name]);
    expect(v.nodes.some((n) => n.section === "api")).toBe(false);
    expect(v.edges.some((e) => e.target === GOOGLE_GROUP || e.target === "group:api")).toBe(false);
  });

  it("the type box reads \"some\", never \"none\", while the type is on the map only as groups; a click hides it", () => {
    const env: PickerEnv = { graph: g, tools: { gateway: "all", expanded: [], hidden: [], inherited: true, allows: true, denies: true } };
    const items = pickerItems(g);
    const s = pickerStatus(env, DEFAULT_PICKER);
    const gItems = items.filter((i) => i.group === "google");
    // every Google API endpoint is in the collapsed group: none checked, all in a group
    expect(gItems.every((i) => s.get(i.id)?.hidden === "google")).toBe(true);
    expect(countGrouped(s, gItems)).toBe(gItems.length);
    expect(typeState(s, items, ["google"], DEFAULT_PICKER)).toBe("some");
    const off = setTypes(env, DEFAULT_PICKER, ["google"], false);
    expect(viewOf(g, filters({ typesOff: off.typesOff }), []).nodes.some((n) => n.id === GOOGLE_GROUP)).toBe(false);
    expect(typeState(pickerStatus(env, off), items, ["google"], off)).toBe("none");
  });
});
