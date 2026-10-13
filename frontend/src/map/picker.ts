// The map's object picker (docs/VISUALIZATION_PLAN.md §5.4): which objects are on the map and which agents' lines are
// drawn. Pure; ObjectPicker.tsx draws it and MapStep keeps one state per project, region and direction, saved in
// localStorage next to the pins (usePositions.ts). Every storage access is wrapped: private windows and disabled
// storage just don't remember.
//
// One source of truth: a row's checkbox is never stored, it's read off the map (pickerStatus): checked = on the map
// as itself, unchecked = not, with the reason ("hidden: no grants", "hidden: type filter", ...). The state holds what
// the person chose: the objects they unchecked (`off`), the ones they checked although a filter hides them (`forced`,
// a manual override), the destination types they unchecked (`typesOff`, the toolbar's type boxes and the picker's
// type group checkboxes), the selection and the quick toggles. The filters (the toolbar, the quick toggles, the
// groups expanded on the canvas, Changes only) hide what they hide, so changing one checks or unchecks its rows by
// itself, and relaxing it checks them again. Checking a row the filters hide forces it on; unchecking it hides it.
// Changing a quick toggle or the gateway filter drops the overrides of that filter: the newer choice wins.
//
// Checking an agent (or a pseudo caller) one by one also selects it, so its lines draw; a group checkbox, Select all
// and the affiliation shortcut only show or hide. Clicking an agent on the canvas toggles its selection. The picker
// edits a draft: Apply commits it, Cancel and Esc drop it; a change made elsewhere while it's open (a canvas click,
// auto-select) is merged into it row by row (rebaseDraft), keeping the rows the person already changed.
import type { Direction, PNode, PolicyGraph } from "./graph";
import { DEFAULT_FILTERS, DEST_TYPES, destType, isSource, viewOf, type Affiliation, type DestType, type MapFilters, type MapView } from "./view";
import type { MapFocus } from "./focus";
import type { PinStore } from "./usePositions";

export type PickGroup = "engine" | "pseudo" | "client" | "gateway" | "registry" | "a2a" | "runtime" | "mcp" | "api" | "google";
export const GROUP_LABEL: Record<PickGroup, string> = {
  engine: "Agent Runtime agents",
  pseudo: "Other callers",
  client: "Clients",
  gateway: "Gateways",
  registry: "Agent Registry",
  a2a: "A2A agents",
  runtime: "Agent Runtime agents (registry entries)",
  mcp: "MCP servers",
  api: "API endpoints",
  google: "Google APIs",
};
const ORDER: Record<Direction, PickGroup[]> = {
  egress: ["engine", "pseudo", "gateway", "a2a", "runtime", "mcp", "api", "google", "registry"],
  ingress: ["engine", "gateway", "client"],
};

export interface PickItem {
  id: string;
  label: string;
  sub?: string;
  group: PickGroup;
  /** Lowercase name, id and URL, for the text filter. */
  search: string;
  /** An agent or pseudo caller: checking it selects it. */
  source: boolean;
}

export interface PickerState {
  /** Objects unchecked by hand (hidden). */
  off: string[];
  /** Objects checked by hand although a filter hides them: shown anyway (a manual override). */
  forced: string[];
  /** Destination types unchecked (the toolbar's type boxes, the picker's type group checkboxes). */
  typesOff: DestType[];
  /** Selected callers, in selection order: their lines are drawn. */
  selected: string[];
  /** Quick toggles. */
  hideEmpty: boolean;
  googleApis: boolean;
}
export const DEFAULT_PICKER: PickerState = { off: [], forced: [], typesOff: [], selected: [], hideEmpty: true, googleApis: false };

/** The filter fields the picker holds; MapStep's toolbar holds the rest. */
export const PICKER_KEYS = ["off", "forced", "typesOff", "hideEmpty", "googleApis"] as const;
export type Tools = Omit<MapFilters, (typeof PICKER_KEYS)[number]>;
/** What else decides what's on the map: the graph, the toolbar's filters, Changes only and the node in the panel. */
export interface PickerEnv {
  graph: PolicyGraph;
  tools: Tools;
  changesOnly?: boolean;
  active?: string | null;
}
export const DEFAULT_TOOLS: Tools = (({ off: _o, forced: _f, typesOff: _t, hideEmpty: _h, googleApis: _g, ...t }) => t)(DEFAULT_FILTERS);
export const filtersOf = (tools: Tools, d: PickerState): MapFilters => ({ ...tools, off: d.off, forced: d.forced, typesOff: d.typesOff, hideEmpty: d.hideEmpty, googleApis: d.googleApis });
/** A picker group that is also a destination type (its group checkbox is the type filter). */
export const isTypeGroup = (g: PickGroup): g is DestType => (DEST_TYPES as readonly string[]).includes(g);

function groupOf(n: PNode, direction: Direction): PickGroup | null {
  if (isSource(n, direction) && n.kind === "engine") return "engine";
  switch (n.kind) {
    case "principal_group":
      return "pseudo";
    case "client":
      return "client";
    case "gateway":
      return "gateway";
    case "registry":
      return "registry";
    case "a2a":
      return "a2a";
    case "runtime_dest":
      return "runtime";
    case "mcp":
      return "mcp";
    case "endpoint":
      return n.googleApi ? "google" : "api";
    default:
      return null; // the "No gateway" lane and Anywhere follow the agents
  }
}

/** The picker's rows, by group (in map order) and label. */
export function pickerItems(g: Pick<PolicyGraph, "nodes" | "direction">): PickItem[] {
  const order = ORDER[g.direction];
  const items: PickItem[] = [];
  for (const n of g.nodes) {
    const group = groupOf(n, g.direction);
    if (!group || !order.includes(group)) continue;
    items.push({ id: n.id, label: n.label, sub: n.sub, group, search: `${n.search} ${n.label} ${n.id} ${n.url ?? ""}`.toLowerCase(), source: isSource(n, g.direction) });
  }
  return items.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
}

/** Rows matching the text filter (name, id and URL); every row when it's empty. */
export function filterItems(items: PickItem[], query: string): PickItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((i) => i.search.includes(q));
}

/** The groups of these rows, in order, with their rows. */
export function groupItems(items: PickItem[]): { group: PickGroup; label: string; items: PickItem[] }[] {
  const out = new Map<PickGroup, PickItem[]>();
  for (const i of items) out.set(i.group, [...(out.get(i.group) ?? []), i]);
  return [...out].map(([group, is]) => ({ group, label: GROUP_LABEL[group], items: is }));
}

const uniq = <T>(xs: T[]) => [...new Set(xs)];

// ---------- each row's status, read off the map ----------
/** Why a row is unchecked. */
export type Hidden = "unchecked" | "noGateway" | "hasGateway" | "affiliation" | "type" | "otherGateway" | "google" | "noGrants" | "changes" | "filtered";
export const HIDDEN_LABEL: Record<Hidden, string> = {
  unchecked: "",
  noGateway: "hidden: no gateway",
  hasGateway: "hidden: behind a gateway",
  affiliation: "hidden: No gateway filter",
  type: "hidden: type filter",
  otherGateway: "hidden: other gateway",
  google: "hidden: Google API (collapsed)",
  noGrants: "hidden: no grants",
  changes: "hidden: not changed",
  filtered: "hidden by a filter",
};
export interface RowStatus {
  /** On the map as itself (not in a group): the row is checked. */
  on: boolean;
  /** Why it isn't. */
  hidden?: Hidden;
  /** Checked against this filter: a manual override. */
  manual?: Hidden;
}
export type Statuses = Map<string, RowStatus>;

/** Why node `n` isn't on the map as itself in state `d`. `groupedIn`: the group node kind
 *  each grouped object is in. */
function reasonIn(env: PickerEnv, d: PickerState, n: PNode, aff: Affiliation | null, groupedIn: Map<string, string>): Hidden {
  const f = env.tools;
  if (d.off.includes(n.id) && n.id !== env.active) {
    if (aff === "gateway" && n.kind === "engine" && !n.gateway) return "noGateway";
    if (aff === "none" && n.kind === "engine" && n.gateway) return "hasGateway";
    if (aff === "none" && (n.kind === "gateway" || n.kind === "principal_group")) return "affiliation";
    return "unchecked";
  }
  const t = env.graph.direction === "egress" ? destType(n) : null;
  if (t && d.typesOff.includes(t) && !d.forced.includes(n.id)) return "type";
  if (f.gateway !== "all" && !d.forced.includes(n.id) && ((n.kind === "engine" && isSource(n, env.graph.direction) && n.gateway !== f.gateway) || (n.kind === "gateway" && n.id !== f.gateway))) return "otherGateway";
  const grp = groupedIn.get(n.id);
  if (grp) return grp === "google_apis" ? "google" : "noGrants";
  if (env.changesOnly) return "changes";
  if (n.kind === "principal_group" || n.kind === "registry") return "noGrants";
  return "filtered";
}

function statusesIn(env: PickerEnv, d: PickerState, v: MapView, items: PickItem[]): Statuses {
  const byId = new Map(env.graph.nodes.map((n) => [n.id, n]));
  const shown = new Set(v.nodes.map((n) => n.id));
  const groupedIn = new Map<string, string>();
  for (const n of v.nodes) for (const id of n.grouped ?? []) groupedIn.set(id, n.kind);
  const aff = affiliationOf(d, env.graph);
  const out: Statuses = new Map();
  for (const i of items) {
    const n = byId.get(i.id);
    if (!n) continue;
    if (shown.has(i.id)) out.set(i.id, { on: true });
    else out.set(i.id, { on: false, hidden: reasonIn(env, d, n, aff, groupedIn) });
  }
  return out;
}

/** Every row's status in state `d`: checked when it's on the map, unchecked (with the reason) when it isn't, and the
 *  manual overrides marked with the filter they beat. `view`: the map's view of `d`, when the caller has it. */
export function pickerStatus(env: PickerEnv, d: PickerState, view?: MapView): Statuses {
  const items = pickerItems(env.graph);
  const opts = { changesOnly: env.changesOnly, active: env.active ?? null };
  const out = statusesIn(env, d, view ?? viewOf(env.graph, filtersOf(env.tools, d), d.selected, opts), items);
  const forced = d.forced.filter((id) => out.get(id)?.on);
  if (forced.length) {
    // what each override beats: the row's status without the overrides
    const bare = { ...d, forced: [] };
    const without = statusesIn(env, bare, viewOf(env.graph, filtersOf(env.tools, bare), d.selected, opts), items.filter((i) => forced.includes(i.id)));
    for (const id of forced) {
      const h = without.get(id)?.hidden;
      if (h && h !== "unchecked") out.set(id, { on: true, manual: h });
    }
  }
  return out;
}

/** "N of M": the rows on the map. */
export const countOn = (s: Statuses, items: PickItem[]) => items.filter((i) => s.get(i.id)?.on).length;

/** "all" / "some" / "none" of these rows checked (a group checkbox's state). */
export function checkState(s: Statuses, items: PickItem[]): "all" | "some" | "none" {
  const n = countOn(s, items);
  return n === 0 ? "none" : n === items.length ? "all" : "some";
}

/** Whether an object is unchecked by hand (the Lines toggle only shows on checked rows). */
export const isChecked = (d: PickerState, id: string) => !d.off.includes(id);

// ---------- the draft: rows, groups, types, quick toggles ----------
/** Check rows: show them, overriding the filters that would still hide them. A whole type checked clears its type
 *  filter, every Google API endpoint checked turns "Show Google API endpoints" on (rather than one override each).
 *  `select`: the callers among them are selected too (one row checked by hand). */
export function checkRows(env: PickerEnv, d: PickerState, rows: PickItem[], select = false): PickerState {
  const ids = new Set(rows.map((i) => i.id));
  const all = pickerItems(env.graph);
  const whole = (t: PickGroup) => {
    const of = all.filter((i) => i.group === t);
    return of.length > 0 && of.every((i) => ids.has(i.id));
  };
  let next: PickerState = {
    ...d,
    off: d.off.filter((x) => !ids.has(x)),
    typesOff: d.typesOff.filter((t) => !whole(t)),
    googleApis: d.googleApis || (env.graph.direction === "egress" && whole("google")),
    selected: select ? uniq([...d.selected, ...rows.filter((i) => i.source).map((i) => i.id)]) : d.selected,
  };
  const s = pickerStatus(env, next);
  const still = rows.filter((i) => !s.get(i.id)?.on).map((i) => i.id);
  if (still.length) next = { ...next, forced: uniq([...next.forced, ...still]) };
  return next;
}

/** Uncheck rows: hidden by hand (and no longer overridden or selected). */
export function uncheckRows(d: PickerState, rows: PickItem[]): PickerState {
  const ids = new Set(rows.map((i) => i.id));
  return { ...d, off: uniq([...d.off, ...ids]), forced: d.forced.filter((x) => !ids.has(x)), selected: d.selected.filter((x) => !ids.has(x)) };
}

/** One row's checkbox: checking a caller also selects it; unchecking hides it and drops it from the selection. */
export function toggleItem(env: PickerEnv, d: PickerState, item: PickItem, s: Statuses = pickerStatus(env, d)): PickerState {
  return s.get(item.id)?.on ? uncheckRows(d, [item]) : checkRows(env, d, [item], item.source);
}

/** A group checkbox (or Select all / Clear over the filtered rows): show or hide them all. Showing doesn't select. */
export function setItems(env: PickerEnv, d: PickerState, rows: PickItem[], on: boolean): PickerState {
  return on ? checkRows(env, d, rows) : uncheckRows(d, rows);
}

/** A type filter on or off (the toolbar's type box, or the picker's group checkbox of that type). On restores the
 *  type as it was before (its rows unchecked by hand checked again); if that still leaves all of it hidden by other
 *  filters, its rows are forced on, so the click never does nothing. Off hides the type and drops its overrides. */
export function setTypes(env: PickerEnv, d: PickerState, types: DestType[], on: boolean): PickerState {
  const rows = pickerItems(env.graph).filter((i) => (types as string[]).includes(i.group));
  const ids = new Set(rows.map((i) => i.id));
  const forced = d.forced.filter((x) => !ids.has(x));
  if (!on) return { ...d, typesOff: uniq([...d.typesOff, ...types]), forced };
  const next = { ...d, typesOff: d.typesOff.filter((t) => !types.includes(t)), off: d.off.filter((x) => !ids.has(x)), forced };
  return rows.length && checkState(pickerStatus(env, next), rows) === "none" ? checkRows(env, next, rows) : next;
}

/** A type box's state: its rows' checks; with no rows of that type, its filter. */
export function typeState(s: Statuses, items: PickItem[], types: DestType[], d: PickerState): "all" | "some" | "none" {
  const rows = items.filter((i) => (types as string[]).includes(i.group));
  if (rows.length) return checkState(s, rows);
  return types.every((t) => d.typesOff.includes(t)) ? "none" : "all";
}

/** Clicking a type box: unchecked shows the type, checked or partly checked hides it. */
export function toggleTypes(env: PickerEnv, d: PickerState, types: DestType[], s: Statuses = pickerStatus(env, d)): PickerState {
  return setTypes(env, d, types, typeState(s, pickerItems(env.graph), types, d) === "none");
}

/** The overrides of one filter dropped (that filter just changed: the newer choice wins). `s`: the statuses before. */
export function dropOverrides(d: PickerState, s: Statuses, reason: Hidden): PickerState {
  const forced = d.forced.filter((id) => s.get(id)?.manual !== reason);
  return forced.length === d.forced.length ? d : { ...d, forced };
}

/** A quick toggle: set, and its overrides dropped. */
export function setQuick(env: PickerEnv, d: PickerState, k: "hideEmpty" | "googleApis", v: boolean): PickerState {
  if (d[k] === v) return d;
  return { ...dropOverrides(d, pickerStatus(env, d), k === "hideEmpty" ? "noGrants" : "google"), [k]: v };
}

/** "Only this": uncheck every other row (it's forced on if a filter hides it); a caller is then the only one
 *  selected, and stays with what its lines reach (its gateway, the destinations Show and the type filters leave it):
 *  a hidden object takes its lines off the map, so a caller alone would have none. */
export function onlyThis(env: PickerEnv, d: PickerState, items: PickItem[], id: string): PickerState {
  const item = items.find((i) => i.id === id);
  const keep = new Set([id]);
  if (item?.source) {
    const v = viewOf(env.graph, filtersOf(env.tools, { ...d, off: [], forced: [id] }), [id], { changesOnly: env.changesOnly, active: env.active ?? null });
    for (const e of v.edges) for (const x of [e.source, e.target, ...(e.members ?? []).map((m) => m.target)]) keep.add(x);
  }
  const next: PickerState = { ...d, off: items.filter((i) => !keep.has(i.id)).map((i) => i.id), forced: [], selected: item?.source ? [id] : [] };
  return item && !pickerStatus(env, next).get(id)?.on ? { ...next, forced: [id] } : next;
}

/** A checked caller's own "lines" toggle in its row (select or deselect it without hiding it). */
export function toggleSelected(d: PickerState, id: string): PickerState {
  if (!isChecked(d, id)) return d;
  return { ...d, selected: d.selected.includes(id) ? d.selected.filter((x) => x !== id) : [...d.selected, id] };
}

/** Clicking an agent on the canvas: select it, or deselect it (it stays checked). */
export function toggleAgent(d: PickerState, id: string): PickerState {
  return d.selected.includes(id) ? { ...d, selected: d.selected.filter((x) => x !== id) } : { ...d, off: d.off.filter((x) => x !== id), selected: [...d.selected, id] };
}

/** Apply: the draft becomes the state (deduplicated; the selection only keeps callers not unchecked by hand). */
export function applyDraft(d: PickerState): PickerState {
  const off = uniq(d.off);
  return { ...d, off, forced: uniq(d.forced).filter((x) => !off.includes(x)), typesOff: uniq(d.typesOff), selected: uniq(d.selected).filter((x) => !off.includes(x)) };
}

/** Enter in the text filter: with exactly one match, "Only this" and Apply; otherwise just Apply. */
export function enterInFilter(env: PickerEnv, d: PickerState, items: PickItem[], query: string): PickerState {
  const m = filterItems(items, query);
  return applyDraft(query.trim() && m.length === 1 ? onlyThis(env, d, items, m[0].id) : d);
}

/** The state changed elsewhere while the picker is open (a canvas click, auto-select, Show on map): the draft takes
 *  the new state, except where the person already changed it (each object's membership in off / forced / typesOff /
 *  selected, and each quick toggle, compared with the state the draft started from). */
export function rebaseDraft(base: PickerState, draft: PickerState, next: PickerState): PickerState {
  const merge = <T>(k: "off" | "forced" | "typesOff" | "selected"): T[] => {
    const b = new Set(base[k] as T[]);
    const dr = new Set(draft[k] as T[]);
    const keep = (next[k] as T[]).filter((x) => b.has(x) !== dr.has(x) ? dr.has(x) : true);
    const added = (draft[k] as T[]).filter((x) => !b.has(x) && !keep.includes(x));
    return [...keep, ...added];
  };
  return {
    off: merge<string>("off"),
    forced: merge<string>("forced"),
    typesOff: merge<DestType>("typesOff"),
    selected: merge<string>("selected"),
    hideEmpty: draft.hideEmpty !== base.hideEmpty ? draft.hideEmpty : next.hideEmpty,
    googleApis: draft.googleApis !== base.googleApis ? draft.googleApis : next.googleApis,
  };
}

/** Same choices (the order of the lists aside). */
export function samePicker(a: PickerState, b: PickerState): boolean {
  const eq = (x: string[], y: string[]) => x.length === y.length && x.every((v) => y.includes(v));
  return eq(a.off, b.off) && eq(a.forced, b.forced) && eq(a.typesOff, b.typesOff) && eq(a.selected, b.selected) && a.hideEmpty === b.hideEmpty && a.googleApis === b.googleApis;
}

// ---------- the affiliation shortcut: it pre-sets the agents' (and gateways') checks ----------
type AffNode = Pick<PNode, "id" | "kind" | "column" | "gateway">;
/** Whether a caller or gateway is on under an affiliation: Behind a gateway leaves out unbound agents; No gateway
 *  leaves out bound agents, pseudo callers and the gateways. */
function affiliationOn(n: AffNode, a: Affiliation): boolean {
  if (a === "all") return true;
  if (n.kind === "gateway" || n.kind === "principal_group") return a !== "none";
  return a === "none" ? !n.gateway : !!n.gateway;
}
const affected = (n: AffNode, direction: Direction) => n.kind === "gateway" || isSource(n, direction);

/** The picker after an affiliation shortcut: agents, pseudo callers and gateways checked as it says (other rows
 *  untouched); hidden callers leave the selection. */
export function presetAffiliation(d: PickerState, g: Pick<PolicyGraph, "nodes" | "direction">, a: Affiliation): PickerState {
  const ns = g.nodes.filter((n) => affected(n, g.direction));
  const ids = new Set(ns.map((n) => n.id));
  const off = uniq([...d.off.filter((x) => !ids.has(x)), ...ns.filter((n) => !affiliationOn(n, a)).map((n) => n.id)]);
  return { ...d, off, forced: d.forced.filter((x) => !ids.has(x)), selected: d.selected.filter((x) => !off.includes(x)) };
}

/** The affiliation the picker's caller and gateway checks match, or null (a custom choice). */
export function affiliationOf(d: PickerState, g: Pick<PolicyGraph, "nodes" | "direction">): Affiliation | null {
  const ns = g.nodes.filter((n) => affected(n, g.direction));
  const off = new Set(d.off);
  return (["all", "gateway", "none"] as const).find((a) => ns.every((n) => affiliationOn(n, a) !== off.has(n.id))) ?? null;
}

// ---------- auto-select, Reset view, "Show on map" ----------
/** With nothing selected and exactly one agent in view, that agent (so the map doesn't open empty); else null. */
export function autoSelect(agentsInView: string[], selected: string[]): string[] | null {
  return !selected.length && agentsInView.length === 1 ? [agentsInView[0]] : null;
}

/** Reset view: everything visible, nothing selected (then auto-select, when the graph has only one agent). */
export function resetPicker(g: Pick<PolicyGraph, "nodes" | "direction">): PickerState {
  const engines = g.nodes.filter((n) => n.kind === "engine" && isSource(n, g.direction)).map((n) => n.id);
  return { ...DEFAULT_PICKER, selected: autoSelect(engines, []) ?? [] };
}

/** "Show on map" from another step: the node and the target checked; an agent (or pseudo caller) node selected.
 *  With `env`, one a type filter, the gateway filter or Changes only would still hide is forced on (the groups that
 *  hide one are expanded after, revealPatch). */
export function focusPicker(d: PickerState, f: Pick<MapFocus, "node" | "target">, isCaller: (id: string) => boolean, env?: PickerEnv): PickerState {
  const ids = [f.node, f.target].filter((x): x is string => !!x);
  const off = d.off.filter((x) => !ids.includes(x));
  const next = { ...d, off, selected: f.node && isCaller(f.node) ? [f.node] : d.selected.filter((x) => !off.includes(x)) };
  if (!env) return next;
  const s = pickerStatus(env, next);
  const force = ids.filter((id) => ["type", "otherGateway", "changes"].includes(s.get(id)?.hidden ?? ""));
  return force.length ? { ...next, forced: uniq([...next.forced, ...force]) } : next;
}

// ---------- saved per project, region and direction ----------
/** Next to the pins' `studio.map.v1:…` key; bumping the version drops every saved picker. */
export const pickerKey = (project: string, region: string, direction: Direction) => `studio.map.picker.v1:${project}:${region}:${direction}`;

/** The saved picker, without ids that aren't known any more; the default when nothing (or junk) is saved. */
export function loadPicker(store: PinStore | null, key: string, known: (id: string) => boolean): PickerState {
  if (!store) return DEFAULT_PICKER;
  try {
    const raw = JSON.parse(store.getItem(key) ?? "null") as Partial<PickerState> | null;
    if (!raw || typeof raw !== "object") return DEFAULT_PICKER;
    const ids = (xs: unknown) => (Array.isArray(xs) ? uniq(xs.filter((x): x is string => typeof x === "string" && known(x))) : []);
    // v1 as first saved (off, selected and the quick toggles) loads as is: no overrides, no type filters
    const off = ids(raw.off);
    return {
      off,
      forced: ids(raw.forced).filter((x) => !off.includes(x)),
      typesOff: Array.isArray(raw.typesOff) ? uniq(raw.typesOff.filter((t): t is DestType => (DEST_TYPES as readonly unknown[]).includes(t))) : [],
      selected: ids(raw.selected).filter((x) => !off.includes(x)),
      hideEmpty: typeof raw.hideEmpty === "boolean" ? raw.hideEmpty : DEFAULT_PICKER.hideEmpty,
      googleApis: typeof raw.googleApis === "boolean" ? raw.googleApis : DEFAULT_PICKER.googleApis,
    };
  } catch {
    return DEFAULT_PICKER;
  }
}

/** Saved, or the key cleared when it's the default. */
export function savePicker(store: PinStore | null, key: string, d: PickerState) {
  if (!store) return;
  try {
    const plain = !d.off.length && !d.forced.length && !d.typesOff.length && !d.selected.length && d.hideEmpty === DEFAULT_PICKER.hideEmpty && d.googleApis === DEFAULT_PICKER.googleApis;
    if (plain) store.removeItem(key);
    else store.setItem(key, JSON.stringify(d));
  } catch {
    /* storage full or disabled: the choice lives until reload */
  }
}
