// The object picker (picker.ts): rows and groups, the text filter, group checkboxes, "Only this", Apply / Cancel,
// persistence, the affiliation shortcut, auto-select, Reset view and "Show on map" focus; and how the canvas tells
// several agents' lines apart (toFlow.ts), over the mock world.
import { describe, expect, it } from "vitest";
import { buildWorld } from "../api/mockData";
import type { Ctx } from "../api/types";
import { NOGW, PSEUDO, buildPolicyGraph, type Direction } from "./graph";
import { DEFAULT_FILTERS, revealPatch, viewOf, type MapFilters } from "./view";
import { layoutView } from "./layout";
import { findFocusEdge, focusForGrant } from "./focus";
import { toFlow } from "./toFlow";
import {
  DEFAULT_PICKER,
  DEFAULT_TOOLS,
  affiliationOf,
  applyDraft,
  autoSelect,
  checkRows,
  checkState,
  countOn,
  dropOverrides,
  enterInFilter,
  filterItems,
  focusPicker,
  groupItems,
  loadPicker,
  onlyThis,
  pickerItems,
  pickerKey,
  pickerStatus,
  presetAffiliation,
  rebaseDraft,
  resetPicker,
  savePicker,
  setItems,
  setQuick,
  setTypes,
  toggleAgent,
  toggleItem,
  toggleSelected,
  toggleTypes,
  typeState,
  type PickerEnv,
  type PickerState,
} from "./picker";
import type { PinStore } from "./usePositions";

const CTX: Ctx = { project: "my-demo-project", region: "us-east4" };
const w0 = buildWorld(CTX);
const inv = w0.inventory;
const graph = (direction: Direction = "egress", w = w0) => buildPolicyGraph({ inventory: w.inventory, gateways: w.gateways, modelArmor: w.modelArmor, direction });
const g = graph();
const items = pickerItems(g);
const eng = (name: string) => inv.engines.find((e) => e.display_name === name)!;
const dest = (name: string) => [...inv.agents, ...inv.mcp_servers, ...inv.endpoints].find((d) => d.display_name === name)!;
const item = (id: string) => items.find((i) => i.id === id)!;
const hd = eng("Helpdesk Agent").name;
const hr = eng("HR Assistant").name;
const travel = eng("Travel Planner").name;
const tickets = dest("Tickets MCP").name;
const EGRESS = w0.gateways.find((x) => x.type === "egress")!.name;
/** The picker applied to the view, as MapStep does. */
const view = (st: PickerState, f: Partial<MapFilters> = {}, gg = g) =>
  viewOf(gg, { ...DEFAULT_FILTERS, ...f, off: st.off, forced: st.forced, typesOff: st.typesOff, hideEmpty: st.hideEmpty, googleApis: st.googleApis }, st.selected);
/** The rest of the map's state, as MapStep passes it. */
const env = (gg = g, tools: Partial<PickerEnv["tools"]> = {}, opts: Partial<PickerEnv> = {}): PickerEnv => ({ graph: gg, tools: { ...DEFAULT_TOOLS, ...tools }, ...opts });
const E = env();

describe("rows and groups", () => {
  it("groups by type, in map order, with the agents first; no lane or sink rows", () => {
    const groups = groupItems(items).map((x) => x.label);
    expect(groups).toEqual(["Agent Runtime agents", "Other callers", "Gateways", "A2A agents", "Agent Runtime agents (registry entries)", "MCP servers", "API endpoints", "Google APIs", "Agent Registry"]);
    expect(items.some((i) => i.id === NOGW.egress || i.id === PSEUDO.anywhere)).toBe(false);
    expect(items.filter((i) => i.group === "google")).toHaveLength(38);
    expect(item(hd).source && item(PSEUDO.project).source).toBe(true);
    expect(item(tickets).source).toBe(false);
  });

  it("Client-to-Agent: agents, gateways and clients", () => {
    expect(groupItems(pickerItems(graph("ingress"))).map((x) => x.group)).toEqual(["engine", "gateway", "client"]);
  });

  it("the text filter matches name, id and URL", () => {
    expect(filterItems(items, "tickets").map((i) => i.id)).toEqual([tickets]);
    expect(filterItems(items, "weather.example.com").map((i) => i.label)).toEqual(["Weather API"]);
    expect(filterItems(items, tickets.split("/").pop()!).map((i) => i.id)).toEqual([tickets]);
    expect(filterItems(items, "  ")).toHaveLength(items.length);
  });
});

describe("the draft", () => {
  it("checking an agent selects it; unchecking hides it and drops the selection", () => {
    const hidden = { ...DEFAULT_PICKER, off: [hd] };
    const on = toggleItem(E, hidden, item(hd));
    expect(on).toMatchObject({ off: [], selected: [hd] });
    expect(toggleItem(E, on, item(hd))).toMatchObject({ off: [hd], selected: [] });
    // a destination: shown or hidden, never selected
    expect(toggleItem(E, DEFAULT_PICKER, item(tickets))).toMatchObject({ off: [tickets], selected: [] });
  });

  it("group checkboxes (and Select all / Clear over the filtered rows) show or hide, without selecting", () => {
    const agents = items.filter((i) => i.group === "engine");
    const none = setItems(E, DEFAULT_PICKER, agents, false);
    expect(checkState(pickerStatus(E, none), agents)).toBe("none");
    expect(checkState(pickerStatus(E, toggleItem(E, none, item(hd))), agents)).toBe("some");
    const all = setItems(E, toggleItem(E, none, item(hd)), agents, true);
    expect(checkState(pickerStatus(E, all), agents)).toBe("all");
    expect(all.selected).toEqual([hd]);
    expect(setItems(E, all, agents, false).selected).toEqual([]);
  });

  it("Only this: everything else unchecked; an agent is the only one selected", () => {
    const st = onlyThis(E, { ...DEFAULT_PICKER, selected: [hr] }, items, hd);
    expect(st.off).toHaveLength(items.length - 1);
    expect(st.off).not.toContain(hd);
    expect(st.selected).toEqual([hd]);
    expect(onlyThis(E, DEFAULT_PICKER, items, tickets).selected).toEqual([]);
  });

  it("the Lines toggle selects or deselects a checked agent without hiding it", () => {
    expect(toggleSelected(DEFAULT_PICKER, hd).selected).toEqual([hd]);
    expect(toggleSelected({ ...DEFAULT_PICKER, selected: [hd] }, hd).selected).toEqual([]);
    expect(toggleSelected({ ...DEFAULT_PICKER, off: [hd] }, hd).selected).toEqual([]);
  });

  it("Apply commits the draft (deduplicated, the selection only of checked callers); Cancel keeps the state as it was", () => {
    const state: PickerState = { ...DEFAULT_PICKER, selected: [hr] };
    const draft = { ...toggleItem(E, toggleItem(E, state, item(tickets)), item(hr)), selected: [hd, hd, hr] };
    // Cancel: the draft is dropped, nothing else to do; the state object is untouched
    expect(state).toEqual({ ...DEFAULT_PICKER, selected: [hr] });
    const applied = applyDraft(draft);
    expect(applied.off.sort()).toEqual([hr, tickets].sort());
    expect(applied.selected).toEqual([hd]);
  });

  it("Enter in the filter: Only this and Apply on a single match, just Apply otherwise", () => {
    expect(enterInFilter(E, DEFAULT_PICKER, items, "helpdesk agent").selected).toEqual(filterItems(items, "helpdesk agent").length === 1 ? [hd] : []);
    const one = enterInFilter(E, DEFAULT_PICKER, items, "tickets");
    expect(one.off).toHaveLength(items.length - 1);
    expect(enterInFilter(E, DEFAULT_PICKER, items, "api")).toEqual(DEFAULT_PICKER);
  });

  it("clicking an agent on the canvas toggles its selection (and checks it)", () => {
    const a = toggleAgent(DEFAULT_PICKER, hd);
    expect(a.selected).toEqual([hd]);
    expect(toggleAgent(toggleAgent(a, hr), hd).selected).toEqual([hr]);
    expect(toggleAgent({ ...DEFAULT_PICKER, off: [hd] }, hd)).toMatchObject({ off: [], selected: [hd] });
  });
});

describe("the picker on the map", () => {
  it("checked objects are on the map, unchecked ones aren't; checked agents' lines draw", () => {
    const st = applyDraft(toggleItem(E, toggleItem(E, DEFAULT_PICKER, item(tickets)), item(hd)));
    // hd was checked (visible): unchecking hid it
    const v = view(st);
    expect(v.nodes.some((n) => n.id === hd)).toBe(false);
    expect(v.edges).toEqual([]);
    const sel = view(toggleItem(E, st, item(hd)));
    expect(sel.agents).toEqual([hd]);
    // Tickets MCP is unchecked, but Helpdesk Agent has a line to it: drawn faded
    expect(sel.faded).toContain(tickets);
  });

  it("Only this on an agent: just it, with its gateway and destinations faded in for its lines", () => {
    const v = view(applyDraft(onlyThis(E, DEFAULT_PICKER, items, hr)), { denies: false });
    expect(v.nodes.filter((n) => n.kind === "engine").map((n) => n.id)).toEqual([hr]);
    expect(v.faded).toContain(EGRESS);
    expect(v.faded).toContain(dest("HR Directory MCP").name);
  });

  it("the quick toggles: Hide destinations with no grants, Show Google API endpoints", () => {
    expect(view({ ...DEFAULT_PICKER, hideEmpty: false }).nodes.some((n) => n.kind === "endpoint_group")).toBe(false);
    expect(view({ ...DEFAULT_PICKER, googleApis: true }).nodes.filter((n) => n.kind === "endpoint" && n.googleApi).length).toBeGreaterThan(10);
  });

  it("Only this on an endpoint inside the Google APIs group: forced on as itself, out of the group", () => {
    const sts = inv.endpoints.find((e) => e.url === "https://sts.googleapis.com")!.name;
    const st = applyDraft(onlyThis(E, DEFAULT_PICKER, items, sts));
    expect(st.forced).toEqual([sts]);
    expect(view(st).nodes.some((n) => n.id === sts)).toBe(true);
    expect(pickerStatus(E, st).get(sts)).toEqual({ on: true, manual: "google" });
    // nothing left for revealPatch to expand
    expect(revealPatch(g, { ...DEFAULT_FILTERS, off: st.off, forced: st.forced }, st.selected, sts)).toEqual({});
  });
});

describe("the affiliation shortcut", () => {
  it("pre-sets the agents' (and gateways') checks, leaves the destinations alone, and drops hidden agents from the selection", () => {
    const st = presetAffiliation({ ...DEFAULT_PICKER, off: [tickets], selected: [hd, travel] }, g, "none");
    expect(st.off).toContain(hd);
    expect(st.off).toContain(EGRESS);
    expect(st.off).toContain(PSEUDO.project);
    expect(st.off).toContain(tickets);
    expect(st.off).not.toContain(travel);
    expect(st.selected).toEqual([travel]);
    expect(affiliationOf(st, g)).toBe("none");
    expect(affiliationOf(presetAffiliation(st, g, "gateway"), g)).toBe("gateway");
    const all = presetAffiliation(st, g, "all");
    expect(all.off).toEqual([tickets]);
    expect(affiliationOf(all, g)).toBe("all");
    // a custom choice matches none of them
    expect(affiliationOf({ ...DEFAULT_PICKER, off: [hd] }, g)).toBeNull();
  });
});

describe("auto-select and Reset view", () => {
  it("selects the only agent in view when nothing is selected", () => {
    expect(autoSelect([hd], [])).toEqual([hd]);
    expect(autoSelect([hd, hr], [])).toBeNull();
    expect(autoSelect([hd], [hr])).toBeNull();
    // the picker narrowed to one agent (a group uncheck, then one row back): it's the one in view
    const agents = items.filter((i) => i.group === "engine");
    const st = applyDraft(setItems(E, setItems(E, DEFAULT_PICKER, agents, false), [item(hr)], true));
    const inView = view(st).nodes.filter((n) => n.kind === "engine").map((n) => n.id);
    expect(autoSelect(inView, st.selected)).toEqual([hr]);
  });

  it("Reset view: everything visible, nothing selected; auto-select when the project has one agent", () => {
    expect(resetPicker(g)).toEqual(DEFAULT_PICKER);
    const w = buildWorld(CTX);
    w.inventory.engines = w.inventory.engines.slice(0, 1);
    const one = graph("egress", w);
    expect(resetPicker(one)).toEqual({ ...DEFAULT_PICKER, selected: [w.inventory.engines[0].name] });
    // its view: the agent's lines, groups collapsed
    const v = view(resetPicker(one), {}, one);
    expect(v.agents).toEqual([w.inventory.engines[0].name]);
    expect(v.edges.length).toBeGreaterThan(0);
  });
});

describe("saved per project, region and direction", () => {
  const fake = (init: Record<string, string> = {}) => {
    const m = new Map(Object.entries(init));
    const s: PinStore & { m: Map<string, string> } = { m, getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) };
    return s;
  };
  const key = pickerKey("my-demo-project", "us-east4", "egress");
  const known = (id: string) => items.some((i) => i.id === id);

  it("uses the pins' key scheme", () => {
    expect(key).toBe("studio.map.picker.v1:my-demo-project:us-east4:egress");
    expect(pickerKey("my-demo-project", "us-east4", "ingress")).not.toBe(key);
  });

  it("round trip; unknown ids and junk dropped; the default clears the key", () => {
    const s = fake();
    const st: PickerState = { off: [tickets], forced: [hr], typesOff: ["mcp"], selected: [hd], hideEmpty: false, googleApis: true };
    savePicker(s, key, st);
    expect(loadPicker(s, key, known)).toEqual(st);
    s.m.set(key, JSON.stringify({ off: [tickets, "gone", 3], forced: [tickets, "gone"], typesOff: ["mcp", "nope"], selected: [hd, "gone", tickets], hideEmpty: "yes" }));
    expect(loadPicker(s, key, known)).toEqual({ off: [tickets], forced: [], typesOff: ["mcp"], selected: [hd], hideEmpty: true, googleApis: false });
    savePicker(s, key, DEFAULT_PICKER);
    expect(s.m.has(key)).toBe(false);
    expect(loadPicker(fake({ [key]: "not json" }), key, known)).toEqual(DEFAULT_PICKER);
    expect(loadPicker(null, key, known)).toEqual(DEFAULT_PICKER);
  });

  it("storage errors are swallowed", () => {
    const broken: PinStore = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("full");
      },
      removeItem: () => undefined,
    };
    expect(() => savePicker(broken, key, { ...DEFAULT_PICKER, off: [hd] })).not.toThrow();
    expect(loadPicker(broken, key, known)).toEqual(DEFAULT_PICKER);
  });
});

describe("Show on map (openMap focus)", () => {
  it("a grant: its agent is checked and selected (the only one), the destination checked, the line found", () => {
    const grant = w0.audit().grants.find((x) => x.member === inv.engines.find((e) => e.name === hd)!.principal && x.resource === tickets)!;
    const f = focusForGrant(grant, inv);
    const st = focusPicker({ ...DEFAULT_PICKER, off: [hd, tickets], selected: [hr] }, f, (id) => item(id)?.source ?? false);
    expect(st).toMatchObject({ off: [], selected: [hd] });
    expect(findFocusEdge(view(st).edges, f)).toMatchObject({ id: `a:${hd}|${tickets}`, caller: hd });
  });

  it("a destination alone: revealed (checked, then out of its group), the selection kept", () => {
    const iam = inv.endpoints.find((e) => e.display_name === "IAM Credentials API")!.name; // a Google API with no grants
    const st = focusPicker({ ...DEFAULT_PICKER, off: [iam], selected: [hr] }, { target: iam }, (id) => item(id)?.source ?? false);
    expect(st).toMatchObject({ off: [], selected: [hr] });
    const f = { ...DEFAULT_FILTERS, off: st.off };
    const patch = revealPatch(g, f, st.selected, iam)!;
    // HR Assistant (selected) has a default-deny line to it, so it isn't in the "no grants" group: only Google APIs opens
    expect(patch).toEqual({ googleApis: true });
    // with nothing selected it has no grants, but shown one by one Google API endpoints aren't grouped as "no grants"
    expect(revealPatch(g, f, [], iam)).toEqual({ googleApis: true });
    expect(viewOf(g, { ...f, ...patch }, st.selected).nodes.some((n) => n.id === iam)).toBe(true);
  });

  it("a gateway: checked, not selected (it isn't a caller)", () => {
    expect(focusPicker({ ...DEFAULT_PICKER, off: [EGRESS] }, { node: EGRESS }, (id) => item(id)?.source ?? false)).toEqual(DEFAULT_PICKER);
  });
});

describe("several agents' lines on the canvas", () => {
  it("parallel lines to one destination move apart at the shared ends, and name their agent", () => {
    const v = viewOf(g, DEFAULT_FILTERS, [hd, hr]);
    const flow = toFlow(v, layoutView(v), { node: null, edge: null, hit: null }, new Set());
    const into = flow.edges.filter((e) => e.target === tickets);
    expect(into).toHaveLength(2);
    const [a, b] = into.map((e) => e.data!);
    expect(a.offT).not.toBe(b.offT);
    expect(a.multi && b.multi).toBe(true);
    expect(into.map((e) => e.data!.agent).sort()).toEqual(["HR Assistant", "Helpdesk Agent"]);
    expect(into.map((e) => e.ariaLabel)).toEqual(expect.arrayContaining([expect.stringMatching(/^Helpdesk Agent to Tickets MCP/), expect.stringMatching(/^HR Assistant to Tickets MCP/)]));
    // each line carries its agent's index (hover highlights one agent's path)
    expect(into.map((e) => e.className!.match(/ag(\d)/)![1]).sort()).toEqual(["0", "1"]);
    // the trunk leaves its own agent without an offset
    const trunk = flow.edges.find((e) => e.id === `trunk:${hr}`)!;
    expect(trunk.data!.offS).toBe(0);
    // selected agents are marked on their nodes; one agent alone: its verdict ring on destinations
    expect(flow.nodes.find((n) => n.id === hd)!.data.picked).toBe(true);
    const single = viewOf(g, DEFAULT_FILTERS, [hd]);
    const f1 = toFlow(single, layoutView(single), { node: null, edge: null, hit: null }, new Set());
    expect(f1.nodes.find((n) => n.id === tickets)!.data.ring).toBe("partial");
    expect(flow.nodes.find((n) => n.id === tickets)!.data.ring).toBeUndefined();
  });
});

describe("the picker reflects the map: filters write through to the checks", () => {
  /** Rows on the map as themselves, read off the view (what the checks must match). */
  const onMap = (st: PickerState, e = E) => {
    const v = viewOf(e.graph, { ...DEFAULT_FILTERS, ...e.tools, off: st.off, forced: st.forced, typesOff: st.typesOff, hideEmpty: st.hideEmpty, googleApis: st.googleApis }, st.selected, {
      changesOnly: e.changesOnly,
      active: e.active,
    });
    const faded = new Set(v.faded);
    const ids = new Set(pickerItems(e.graph).map((i) => i.id));
    return v.nodes.filter((n) => ids.has(n.id) && !faded.has(n.id)).map((n) => n.id).sort();
  };
  const checked = (st: PickerState, e = E) => {
    const s = pickerStatus(e, st);
    return pickerItems(e.graph).filter((i) => s.get(i.id)!.on).map((i) => i.id).sort();
  };
  /** The no-grants Agent Runtime registry entries (grouped by default). */
  const noGrants = view(DEFAULT_PICKER).nodes.find((n) => n.id === "group:runtime")!.grouped!;
  const google = items.filter((i) => i.group === "google");
  const mcp = items.filter((i) => i.group === "mcp");

  it("counts match the visible nodes, whatever the state", () => {
    const states: [PickerState, PickerEnv][] = [
      [DEFAULT_PICKER, E],
      [{ ...DEFAULT_PICKER, hideEmpty: false, googleApis: true }, E],
      [{ ...DEFAULT_PICKER, typesOff: ["mcp", "google"], off: [hd], selected: [hr] }, E],
      [presetAffiliation(DEFAULT_PICKER, g, "none"), env(g, { gateway: EGRESS })],
      [{ ...DEFAULT_PICKER, forced: [noGrants[0]] }, env(g, { expanded: ["api"] })],
      [{ ...DEFAULT_PICKER, selected: [hd] }, env(g, {}, { changesOnly: true })],
    ];
    for (const [st, e] of states) {
      expect(checked(st, e)).toEqual(onMap(st, e));
      expect(countOn(pickerStatus(e, st), pickerItems(e.graph))).toBe(onMap(st, e).length);
    }
  });

  it("Hide destinations with no grants: unchecks them with the reason; relaxing checks them again", () => {
    const s = pickerStatus(E, DEFAULT_PICKER);
    for (const id of noGrants) expect(s.get(id)).toEqual({ on: false, hidden: "noGrants" });
    const relaxed = setQuick(E, DEFAULT_PICKER, "hideEmpty", false);
    for (const id of noGrants) expect(pickerStatus(E, relaxed).get(id)).toEqual({ on: true });
    // a group expanded on the canvas: its rows checked
    for (const id of noGrants) expect(pickerStatus(env(g, { expanded: ["runtime"] }), DEFAULT_PICKER).get(id)!.on).toBe(true);
  });

  it("Show Google API endpoints: collapsed rows unchecked (\"Google API (collapsed)\"); on, every one checked", () => {
    const s = pickerStatus(E, DEFAULT_PICKER);
    for (const i of google) expect(s.get(i.id)).toEqual({ on: false, hidden: "google" });
    const on = pickerStatus(E, setQuick(E, DEFAULT_PICKER, "googleApis", true));
    expect(google.every((i) => on.get(i.id)!.on)).toBe(true);
  });

  it("each quick toggle, then Apply, changes the nodes on the map; Cancel leaves them", () => {
    const value = DEFAULT_PICKER;
    const before = view(value).nodes.map((n) => n.id);
    for (const [k, v] of [["hideEmpty", false], ["googleApis", true]] as const) {
      const draft = setQuick(E, value, k, v);
      // the draft's rows change at once
      expect(countOn(pickerStatus(E, draft), items)).toBeGreaterThan(countOn(pickerStatus(E, value), items));
      // Apply: the map changes
      const after = view(applyDraft(draft)).nodes.map((n) => n.id);
      expect(after).not.toEqual(before);
      expect(after.length).toBeGreaterThan(before.length);
      // Cancel: the draft is dropped, the state (and the map) as before
      expect(view(value).nodes.map((n) => n.id)).toEqual(before);
    }
    // Show Google API endpoints alone (Hide destinations with no grants still on) shows all 38, not a "no grants" group
    const v = view(setQuick(E, value, "googleApis", true));
    expect(v.nodes.filter((n) => n.kind === "endpoint" && n.googleApi)).toHaveLength(38);
  });

  it("the type filter: the toolbar box and the picker's group checkbox are one state", () => {
    const off = setTypes(E, DEFAULT_PICKER, ["mcp"], false);
    const s = pickerStatus(E, off);
    for (const i of mcp) expect(s.get(i.id)).toEqual({ on: false, hidden: "type" });
    // the toolbar box and the picker group read the same rows
    expect(typeState(s, items, ["mcp"], off)).toBe("none");
    expect(checkState(s, mcp)).toBe("none");
    // re-checking either one (both call toggleTypes) restores them
    const back = toggleTypes(E, off, ["mcp"], s);
    expect(back.typesOff).toEqual([]);
    expect(checkState(pickerStatus(E, back), mcp)).toBe(checkState(pickerStatus(E, DEFAULT_PICKER), mcp));
    // the toolbar's APIs box covers the API endpoints and the Google APIs groups
    const apis = toggleTypes(E, setQuick(E, DEFAULT_PICKER, "googleApis", true), ["api", "google"]);
    expect(apis.typesOff.sort()).toEqual(["api", "google"]);
    expect(pickerStatus(E, apis).get(google[0].id)!.hidden).toBe("type");
    // partly checked (some hidden by another filter): a click hides the type
    expect(typeState(pickerStatus(E, DEFAULT_PICKER), items, ["api", "google"], DEFAULT_PICKER)).toBe("some");
    expect(toggleTypes(E, DEFAULT_PICKER, ["api", "google"]).typesOff.sort()).toEqual(["api", "google"]);
    // all of a type still hidden by another filter once restored (Google APIs collapsed): checking it shows them
    // (here by turning "Show Google API endpoints" on), so the click is never lost
    const restored = setTypes(E, { ...DEFAULT_PICKER, typesOff: ["google"] }, ["google"], true);
    expect(restored).toMatchObject({ typesOff: [], googleApis: true, forced: [] });
    expect(checkState(pickerStatus(E, restored), google)).toBe("all");
  });

  it("the gateway filter: other gateways and their agents unchecked; a new choice drops its overrides", () => {
    const e = env(g, { gateway: EGRESS });
    const s = pickerStatus(e, DEFAULT_PICKER);
    expect(s.get(travel)).toEqual({ on: false, hidden: "otherGateway" });
    expect(s.get(hd)!.on).toBe(true);
    const forced = checkRows(e, DEFAULT_PICKER, [item(travel)], true);
    expect(forced).toMatchObject({ forced: [travel], selected: [travel] });
    expect(pickerStatus(e, forced).get(travel)).toEqual({ on: true, manual: "otherGateway" });
    expect(dropOverrides(forced, pickerStatus(e, forced), "otherGateway").forced).toEqual([]);
  });

  it("the affiliation shortcut: the reason names it; All agents checks them again", () => {
    const none = presetAffiliation(DEFAULT_PICKER, g, "none");
    const s = pickerStatus(E, none);
    expect(s.get(hd)).toEqual({ on: false, hidden: "hasGateway" });
    expect(s.get(EGRESS)).toEqual({ on: false, hidden: "affiliation" });
    expect(pickerStatus(E, presetAffiliation(DEFAULT_PICKER, g, "gateway")).get(travel)).toEqual({ on: false, hidden: "noGateway" });
    expect(pickerStatus(E, presetAffiliation(none, g, "all")).get(hd)!.on).toBe(true);
  });

  it("Changes only: objects the cart doesn't change are unchecked (\"not changed\")", () => {
    expect(pickerStatus(env(g, {}, { changesOnly: true }), DEFAULT_PICKER).get(hd)).toEqual({ on: false, hidden: "changes" });
  });

  it("a manual override reveals an item; the filter's own toggle drops it", () => {
    const id = noGrants[0];
    const st = toggleItem(E, DEFAULT_PICKER, item(id));
    expect(st.forced).toEqual([id]);
    expect(view(st).nodes.some((n) => n.id === id)).toBe(true);
    expect(pickerStatus(E, st).get(id)).toEqual({ on: true, manual: "noGrants" });
    // unchecking it: hidden by hand, the override gone
    expect(toggleItem(E, st, item(id))).toMatchObject({ off: [id], forced: [] });
    // the quick toggle changed (off, then on again): the override is dropped and the filter applies again
    const relaxed = setQuick(E, st, "hideEmpty", false);
    expect(relaxed.forced).toEqual([]);
    expect(pickerStatus(E, setQuick(E, relaxed, "hideEmpty", true)).get(id)).toEqual({ on: false, hidden: "noGrants" });
    // a type-filtered row checked by hand
    const t = toggleItem(E, setTypes(E, DEFAULT_PICKER, ["mcp"], false), item(tickets));
    expect(pickerStatus(E, t).get(tickets)).toEqual({ on: true, manual: "type" });
  });

  it("a hidden destination a selected agent has a line to: unchecked, drawn faded", () => {
    const st = { ...DEFAULT_PICKER, off: [tickets], selected: [hd] };
    expect(pickerStatus(E, st).get(tickets)).toEqual({ on: false, hidden: "unchecked", faded: true });
  });

  it("the direction switch: Client-to-Agent lists only what it can show, all checked; type filters don't apply", () => {
    const gi = graph("ingress");
    const ii = pickerItems(gi);
    expect(new Set(ii.map((i) => i.group))).toEqual(new Set(["engine", "gateway", "client"]));
    const st = { ...DEFAULT_PICKER, typesOff: ["a2a", "runtime", "mcp", "api", "google"] as PickerState["typesOff"] };
    const s = pickerStatus(env(gi), st);
    expect(ii.every((i) => s.get(i.id)!.on)).toBe(true);
    expect(pickerKey("p", "r", "ingress")).not.toBe(pickerKey("p", "r", "egress"));
  });

  it("Reset view: every row checked again, the overrides and type filters gone", () => {
    const messy: PickerState = { off: [hd], forced: [noGrants[0]], typesOff: ["mcp"], selected: [hr], hideEmpty: false, googleApis: true };
    const st = resetPicker(g);
    expect(st).toEqual(DEFAULT_PICKER);
    expect(checked(st)).toEqual(onMap(st));
    expect(pickerStatus(E, st).get(hd)!.on).toBe(true);
    expect(mcp.every((i) => pickerStatus(E, st).get(i.id)!.on)).toBe(true);
    expect(messy.off).toEqual([hd]); // untouched
  });

  it("a canvas selection shows in the picker; while it's open the draft keeps the rows changed there", () => {
    const value = { ...DEFAULT_PICKER, off: [hd] };
    // clicking an agent on the canvas (Show on map's same-agent link too) checks and selects it
    const clicked = toggleAgent(value, hd);
    expect(pickerStatus(E, clicked).get(hd)!.on).toBe(true);
    expect(clicked.selected).toEqual([hd]);
    // open picker: tickets unchecked in the draft, then the canvas selects Helpdesk Agent
    const draft = toggleItem(E, value, item(tickets));
    const merged = rebaseDraft(value, draft, clicked);
    expect(merged.off).toEqual([tickets]);
    expect(merged.selected).toEqual([hd]);
    // a row the person changed wins over the outside change
    const mine = toggleItem(E, value, item(hd)); // checked (and selected) in the draft
    expect(rebaseDraft(value, mine, { ...value, hideEmpty: false })).toMatchObject({ off: [], selected: [hd], hideEmpty: false });
  });

  it("Show on map forces a type-filtered target on", () => {
    const st = focusPicker({ ...DEFAULT_PICKER, typesOff: ["mcp"] }, { node: hd, target: tickets }, (id) => item(id)?.source ?? false, E);
    expect(st.forced).toEqual([tickets]);
    expect(pickerStatus(E, st).get(tickets)).toEqual({ on: true, manual: "type" });
  });

  it("the v1 shape saved before overrides and type filters loads as is", () => {
    const key = pickerKey("my-demo-project", "us-east4", "egress");
    const m = new Map([[key, JSON.stringify({ off: [tickets], selected: [hd], hideEmpty: false, googleApis: true })]]);
    const store: PinStore = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), removeItem: (k) => void m.delete(k) };
    expect(loadPicker(store, key, (id) => items.some((i) => i.id === id))).toEqual({ off: [tickets], forced: [], typesOff: [], selected: [hd], hideEmpty: false, googleApis: true });
  });
});
