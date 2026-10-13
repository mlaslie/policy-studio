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
  affiliationOf,
  applyDraft,
  autoSelect,
  checkState,
  enterInFilter,
  filterItems,
  focusPicker,
  groupItems,
  loadPicker,
  onlyThis,
  pickerItems,
  pickerKey,
  presetAffiliation,
  resetPicker,
  savePicker,
  setItems,
  toggleAgent,
  toggleItem,
  toggleSelected,
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
const view = (st: PickerState, f: Partial<MapFilters> = {}, gg = g) => viewOf(gg, { ...DEFAULT_FILTERS, ...f, off: st.off, hideEmpty: st.hideEmpty, googleApis: st.googleApis }, st.selected);

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
    const on = toggleItem(hidden, item(hd));
    expect(on).toMatchObject({ off: [], selected: [hd] });
    expect(toggleItem(on, item(hd))).toMatchObject({ off: [hd], selected: [] });
    // a destination: shown or hidden, never selected
    expect(toggleItem(DEFAULT_PICKER, item(tickets))).toMatchObject({ off: [tickets], selected: [] });
  });

  it("group checkboxes (and Select all / Clear over the filtered rows) show or hide, without selecting", () => {
    const agents = items.filter((i) => i.group === "engine");
    const none = setItems(DEFAULT_PICKER, agents, false);
    expect(checkState(none, agents)).toBe("none");
    expect(checkState(toggleItem(none, item(hd)), agents)).toBe("some");
    const all = setItems(toggleItem(none, item(hd)), agents, true);
    expect(checkState(all, agents)).toBe("all");
    expect(all.selected).toEqual([hd]);
    expect(setItems(all, agents, false).selected).toEqual([]);
  });

  it("Only this: everything else unchecked; an agent is the only one selected", () => {
    const st = onlyThis({ ...DEFAULT_PICKER, selected: [hr] }, items, hd);
    expect(st.off).toHaveLength(items.length - 1);
    expect(st.off).not.toContain(hd);
    expect(st.selected).toEqual([hd]);
    expect(onlyThis(DEFAULT_PICKER, items, tickets).selected).toEqual([]);
  });

  it("the Lines toggle selects or deselects a checked agent without hiding it", () => {
    expect(toggleSelected(DEFAULT_PICKER, hd).selected).toEqual([hd]);
    expect(toggleSelected({ ...DEFAULT_PICKER, selected: [hd] }, hd).selected).toEqual([]);
    expect(toggleSelected({ ...DEFAULT_PICKER, off: [hd] }, hd).selected).toEqual([]);
  });

  it("Apply commits the draft (deduplicated, the selection only of checked callers); Cancel keeps the state as it was", () => {
    const state: PickerState = { ...DEFAULT_PICKER, selected: [hr] };
    const draft = { ...toggleItem(toggleItem(state, item(tickets)), item(hr)), selected: [hd, hd, hr] };
    // Cancel: the draft is dropped, nothing else to do; the state object is untouched
    expect(state).toEqual({ ...DEFAULT_PICKER, selected: [hr] });
    const applied = applyDraft(draft);
    expect(applied.off.sort()).toEqual([hr, tickets].sort());
    expect(applied.selected).toEqual([hd]);
  });

  it("Enter in the filter: Only this and Apply on a single match, just Apply otherwise", () => {
    expect(enterInFilter(DEFAULT_PICKER, items, "helpdesk agent").selected).toEqual(filterItems(items, "helpdesk agent").length === 1 ? [hd] : []);
    const one = enterInFilter(DEFAULT_PICKER, items, "tickets");
    expect(one.off).toHaveLength(items.length - 1);
    expect(enterInFilter(DEFAULT_PICKER, items, "api")).toEqual(DEFAULT_PICKER);
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
    const st = applyDraft(toggleItem(toggleItem(DEFAULT_PICKER, item(tickets)), item(hd)));
    // hd was checked (visible): unchecking hid it
    const v = view(st);
    expect(v.nodes.some((n) => n.id === hd)).toBe(false);
    expect(v.edges).toEqual([]);
    const sel = view(toggleItem(st, item(hd)));
    expect(sel.agents).toEqual([hd]);
    // Tickets MCP is unchecked, but Helpdesk Agent has a line to it: drawn faded
    expect(sel.faded).toContain(tickets);
  });

  it("Only this on an agent: just it, with its gateway and destinations faded in for its lines", () => {
    const v = view(applyDraft(onlyThis(DEFAULT_PICKER, items, hr)), { denies: false });
    expect(v.nodes.filter((n) => n.kind === "engine").map((n) => n.id)).toEqual([hr]);
    expect(v.faded).toContain(EGRESS);
    expect(v.faded).toContain(dest("HR Directory MCP").name);
  });

  it("the quick toggles: Hide destinations with no grants, Show Google API endpoints", () => {
    expect(view({ ...DEFAULT_PICKER, hideEmpty: false }).nodes.some((n) => n.kind === "endpoint_group")).toBe(false);
    expect(view({ ...DEFAULT_PICKER, googleApis: true }).nodes.filter((n) => n.kind === "endpoint" && n.googleApi).length).toBeGreaterThan(10);
  });

  it("Only this on an endpoint inside the Google APIs group expands it (the old search behaviour)", () => {
    const sts = inv.endpoints.find((e) => e.url === "https://sts.googleapis.com")!.name;
    const st = applyDraft(onlyThis(DEFAULT_PICKER, items, sts));
    const f = { ...DEFAULT_FILTERS, off: st.off, hideEmpty: st.hideEmpty, googleApis: st.googleApis };
    const patch = revealPatch(g, f, st.selected, sts)!;
    expect(patch.googleApis).toBe(true);
    expect(viewOf(g, { ...f, ...patch }, st.selected).nodes.some((n) => n.id === sts)).toBe(true);
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
    const st = applyDraft(setItems(setItems(DEFAULT_PICKER, agents, false), [item(hr)], true));
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
    const st: PickerState = { off: [tickets], selected: [hd], hideEmpty: false, googleApis: true };
    savePicker(s, key, st);
    expect(loadPicker(s, key, known)).toEqual(st);
    s.m.set(key, JSON.stringify({ off: [tickets, "gone", 3], selected: [hd, "gone", tickets], hideEmpty: "yes" }));
    expect(loadPicker(s, key, known)).toEqual({ off: [tickets], selected: [hd], hideEmpty: true, googleApis: false });
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
    expect(revealPatch(g, f, [], iam)).toEqual({ googleApis: true, expanded: ["api"] });
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
