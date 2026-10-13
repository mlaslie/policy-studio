// The map's object picker (docs/VISUALIZATION_PLAN.md §5.1): which objects are on the map and which agents' lines are
// drawn. Pure; ObjectPicker.tsx draws it and MapStep keeps one state per project, region and direction, saved in
// localStorage next to the pins (usePositions.ts). Every storage access is wrapped: private windows and disabled
// storage just don't remember.
//
// Checked objects are visible, unchecked ones hidden. Checking an agent (or a pseudo caller) one by one also selects
// it, so its lines draw; a group checkbox, Select all and the affiliation shortcut only show or hide. Clicking an agent
// on the canvas toggles its selection. The picker edits a draft: Apply commits it, Cancel and Esc drop it.
import type { Direction, PNode, PolicyGraph } from "./graph";
import { isSource, type Affiliation } from "./view";
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
  /** Unchecked (hidden) objects. */
  off: string[];
  /** Selected callers, in selection order: their lines are drawn. */
  selected: string[];
  /** Quick toggles. */
  hideEmpty: boolean;
  googleApis: boolean;
}
export const DEFAULT_PICKER: PickerState = { off: [], selected: [], hideEmpty: true, googleApis: false };

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

const uniq = (xs: string[]) => [...new Set(xs)];

export const isChecked = (d: PickerState, id: string) => !d.off.includes(id);

/** One row's checkbox: checking a caller also selects it; unchecking hides it and drops it from the selection. */
export function toggleItem(d: PickerState, item: PickItem): PickerState {
  if (isChecked(d, item.id)) return { ...d, off: uniq([...d.off, item.id]), selected: d.selected.filter((x) => x !== item.id) };
  return { ...d, off: d.off.filter((x) => x !== item.id), selected: item.source ? uniq([...d.selected, item.id]) : d.selected };
}

/** A group checkbox (or Select all / Clear over the filtered rows): show or hide them all. Showing doesn't select. */
export function setItems(d: PickerState, items: PickItem[], on: boolean): PickerState {
  const ids = new Set(items.map((i) => i.id));
  if (on) return { ...d, off: d.off.filter((x) => !ids.has(x)) };
  return { ...d, off: uniq([...d.off, ...ids]), selected: d.selected.filter((x) => !ids.has(x)) };
}

/** "all" / "some" / "none" of these rows checked (a group checkbox's state). */
export function checkState(d: PickerState, items: PickItem[]): "all" | "some" | "none" {
  const n = items.filter((i) => isChecked(d, i.id)).length;
  return n === 0 ? "none" : n === items.length ? "all" : "some";
}

/** "Only this": uncheck every other row; a caller is then the only one selected. */
export function onlyThis(d: PickerState, items: PickItem[], id: string): PickerState {
  const item = items.find((i) => i.id === id);
  return { ...d, off: items.filter((i) => i.id !== id).map((i) => i.id), selected: item?.source ? [id] : [] };
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

/** Apply: the draft becomes the state (deduplicated; the selection only keeps checked callers). */
export function applyDraft(d: PickerState): PickerState {
  const off = uniq(d.off);
  return { ...d, off, selected: uniq(d.selected).filter((x) => !off.includes(x)) };
}

/** Enter in the text filter: with exactly one match, "Only this" and Apply; otherwise just Apply. */
export function enterInFilter(d: PickerState, items: PickItem[], query: string): PickerState {
  const m = filterItems(items, query);
  return applyDraft(query.trim() && m.length === 1 ? onlyThis(d, items, m[0].id) : d);
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
  return { ...d, off, selected: d.selected.filter((x) => !off.includes(x)) };
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

/** "Show on map" from another step: the node and the target checked; an agent (or pseudo caller) node selected. */
export function focusPicker(d: PickerState, f: Pick<MapFocus, "node" | "target">, isCaller: (id: string) => boolean): PickerState {
  const ids = [f.node, f.target].filter((x): x is string => !!x);
  const off = d.off.filter((x) => !ids.includes(x));
  return { ...d, off, selected: f.node && isCaller(f.node) ? [f.node] : d.selected.filter((x) => !off.includes(x)) };
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
    const off = ids(raw.off);
    return {
      off,
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
    const plain = !d.off.length && !d.selected.length && d.hideEmpty === DEFAULT_PICKER.hideEmpty && d.googleApis === DEFAULT_PICKER.googleApis;
    if (plain) store.removeItem(key);
    else store.setItem(key, JSON.stringify(d));
  } catch {
    /* storage full or disabled: the choice lives until reload */
  }
}
