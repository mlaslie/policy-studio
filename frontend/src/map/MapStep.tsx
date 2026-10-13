// Policy map step (lazy-loaded chunk with React Flow): who can reach what, and why, drawn from the policy state Policy
// Studio already reads (docs/VISUALIZATION_PLAN.md). The canvas (zoom, pan, drag), the object picker (picker.ts,
// ObjectPicker.tsx), lines only for the selected agents (each agent's own, never combined), the Allows / Denies
// choice, the legend as a verdict filter and the table view; the policy panel (PolicyPanel.tsx) whose actions only
// stage into the cart; the staged-change view (Today / With staged changes / Changes only: simulate.ts, diff.ts);
// saved positions for dragged nodes (usePositions.ts) and the picker per project, region and direction; keyboard use
// and "Show on map" focus.
import {
  Background,
  BackgroundVariant,
  Controls,
  ReactFlow,
  ReactFlowProvider,
  applyNodeChanges,
  useNodesInitialized,
  useReactFlow,
  type NodeChange,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore, type KeyboardEvent as ReactKeyboardEvent, type RefObject } from "react";
import type { GatewaysResp, Inventory } from "../api/types";
import { Callout, Disclosure, Load, StepHeader } from "../components/ui";
import { Tip } from "../components/Tooltip";
import { ClockIcon, CloseIcon, ExpandIcon, ShieldIcon } from "../components/Icons";
import { useStudio } from "../store";
import { plural } from "../lib/util";
import { buildPolicyGraph, type Direction, type PEdge, type PolicyGraph, type Verdict } from "./graph";
import { DEFAULT_DIRECTION, TOO_MANY_LINES, expandGroup, isSource, revealPatch, type Affiliation, type DestType, type MapFilters, viewOf } from "./view";
import { fontEpoch, onFontEpoch } from "./fit";
import { GAP_Y, HEADER_H, freeSpot, layoutView } from "./layout";
import { VERDICT_LABEL, edgeAria, expandedMcp, toFlow, type MNode } from "./toFlow";
import { nodeTypes, MapActions } from "./nodes";
import { EdgeMarkers, edgeTypes } from "./edges";
import MapTable from "./MapTable";
import PolicyPanel from "./PolicyPanel";
import ObjectPicker from "./ObjectPicker";
import { simulate } from "./simulate";
import { diffGraphs, mergeStaged, pairKey, pendingCount } from "./diff";
import { placeNodes, posKey, storage, usePositions } from "./usePositions";
import { findFocusEdge, type MapFocus } from "./focus";
import {
  DEFAULT_TOOLS,
  PICKER_KEYS,
  affiliationOf,
  autoSelect,
  checkRows,
  dropOverrides,
  filtersOf,
  focusPicker,
  loadPicker,
  pickerItems,
  pickerKey,
  pickerStatus,
  presetAffiliation,
  resetPicker,
  savePicker,
  toggleAgent,
  toggleTypes,
  typeState,
  type PickerEnv,
  type PickerState,
  type Tools,
} from "./picker";

const PAD = { top: "40px", bottom: "40px", left: "24px", right: "40px" } as const;
/** Low enough for Fit to show a map of the §7 scale (about 100 destinations) whole. */
const MIN_ZOOM = 0.08;

/** The toolbar's destination type boxes (restored 2026-10-12): each mirrors the picker's group of that type, so they
 *  can't disagree; APIs covers the API endpoints and the Google APIs groups. */
const TYPE_BOXES: { label: string; types: DestType[] }[] = [
  { label: "A2A agents", types: ["a2a"] },
  { label: "Agent Runtime", types: ["runtime"] },
  { label: "MCP servers", types: ["mcp"] },
  { label: "APIs", types: ["api", "google"] },
];
const AFFILIATION: { id: Affiliation; label: string; tip: string }[] = [
  { id: "all", label: "All agents", tip: "Check every Agent Runtime agent in the picker, with or without a gateway." },
  { id: "gateway", label: "Behind a gateway", tip: "Check only the agents bound to a gateway: their connections are checked by policy." },
  { id: "none", label: "No gateway", tip: "Check only the agents with no gateway: no policy applies, their traffic goes straight out (or straight in)." },
];
const LEGEND: Record<Direction, Verdict[]> = {
  egress: ["allowed", "partial", "conditional", "would_deny", "blocked", "unchecked", "dormant", "direct"],
  ingress: ["screened", "unscreened", "direct"],
};
/** A filter change, split into the picker's part and the toolbar's. */
function splitPatch(p: Partial<MapFilters>): { picker: Partial<PickerState>; tools: Partial<Tools> } {
  const picker: Partial<PickerState> = {};
  const tools: Partial<Tools> = {};
  for (const [k, v] of Object.entries(p)) {
    if ((PICKER_KEYS as readonly string[]).includes(k)) (picker as Record<string, unknown>)[k] = v;
    else (tools as Record<string, unknown>)[k] = v;
  }
  return { picker, tools };
}

export default function MapStep() {
  const { inventory, gateways } = useStudio();
  return (
    <>
      <StepHeader
        title="Policy map"
        lead={<>Who can reach what: your agents, the gateways their traffic goes through, and the destinations their grants allow. Every line comes from policy in your project; nothing changes from here.</>}
      />
      <Load l={inventory} what="the Agent Registry inventory">
        {(inv) => (
          <Load l={gateways} what="gateways">
            {(gw) => (
              <ReactFlowProvider>
                <PolicyMap inv={inv} gw={gw} />
              </ReactFlowProvider>
            )}
          </Load>
        )}
      </Load>
    </>
  );
}

function usePrefersReducedMotion() {
  const [r, setR] = useState(() => typeof window !== "undefined" && !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const m = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!m) return;
    const on = () => setR(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return r;
}

type Bounds = { x: number; y: number; width: number; height: number };
/** Fit the map's bounds in the canvas, never past 1.15× zoom. */
function fitMap(rf: ReturnType<typeof useReactFlow>, b: Bounds | null, el: HTMLElement | null, duration: number) {
  if (!b || !el) return void rf.fitView({ padding: PAD, duration, maxZoom: 1.15 });
  const w = Math.max(b.width, el.clientWidth / 1.15);
  const h = Math.max(b.height, el.clientHeight / 1.15);
  void rf.fitBounds({ x: b.x - (w - b.width) / 2, y: b.y - (h - b.height) / 2, width: w, height: h }, { padding: 0.06, duration });
}
/** Fit on open and whenever the filters change, and on resize (the Learn rail, the window); from the demo. It fits the
 *  layout's own bounds (positions and sizes), not React Flow's measured nodes: with onlyRenderVisibleElements, nodes off
 *  screen aren't rendered, so aren't measured, and fitView would leave them out (after "Only this", Reset view would
 *  stay zoomed on the one node). */
function Fitter({ fitKey, wrap, bounds }: { fitKey: string; wrap: RefObject<HTMLDivElement | null>; bounds: Bounds | null }) {
  const rf = useReactFlow();
  const init = useNodesInitialized();
  const boundsRef = useRef(bounds);
  boundsRef.current = bounds;
  const fit = useCallback((duration: number) => fitMap(rf, boundsRef.current, wrap.current, duration), [rf, wrap]);
  useEffect(() => {
    if (!init) return;
    const t = setTimeout(() => fit(350), 220);
    return () => clearTimeout(t);
  }, [fitKey, init, fit]);
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    let t: ReturnType<typeof setTimeout> | undefined;
    const ro = new ResizeObserver(() => {
      clearTimeout(t);
      t = setTimeout(() => fit(200), 160);
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      clearTimeout(t);
    };
  }, [fit, wrap]);
  return null;
}

type Show = "today" | "staged" | "changes";
const SHOW: { id: Show; label: string; tip: string }[] = [
  { id: "today", label: "Today", tip: "The policy in your project now." },
  { id: "staged", label: "With staged changes", tip: "Today's policy with the cart applied: pending lines have a clock. A preview; Review's diff is the authority." },
  { id: "changes", label: "Changes only", tip: "Only the lines and nodes the cart changes (with no agent selected, of every agent they change)." },
];
/** Node and line descriptions read by screen readers when they get focus (React Flow's ariaLabelConfig). */
const ARIA = {
  "node.a11yDescription.default": "Press Enter or Space to select it (an agent: to draw or hide its lines) and show its details. Arrow keys then move it (its place is saved); Escape closes the details, then clears the selection.",
  "node.a11yDescription.keyboardDisabled": "Press Enter or Space to select it and show its details.",
  "node.a11yDescription.ariaLiveMessage": ({ direction }: { direction: string; x: number; y: number }) => `Moved ${direction}. Its place is saved.`,
  "edge.a11yDescription.default": "Press Enter or Space to show the policy behind this line; Escape closes it.",
};

/** The line now: a selected line is re-found in the current view (its lines and the table's rows; by id, then as the
 *  same caller and destination), so the panel follows it into the staged-change view after something is staged, and
 *  shows it as Show: Allows / Denies draws it. null once it's off the map (its object hidden, or Show leaves it out). */
function resolveEdge(edges: PEdge[], e: PEdge): PEdge | null {
  const all = edges.flatMap((x) => [x, ...(x.members ?? [])]);
  return all.find((x) => x.id === e.id) ?? all.find((x) => pairKey(x) === pairKey(e)) ?? null;
}

function PolicyMap({ inv, gw }: { inv: Inventory; gw: GatewaysResp }) {
  const { modelArmor, ctxInfo, ctx, cart, mapFocus, clearMapFocus } = useStudio();
  const rf = useReactFlow();
  const [direction, setDirection] = useState<Direction>(DEFAULT_DIRECTION);
  const [tools, setTools] = useState<Tools>(DEFAULT_TOOLS);
  /** The node in the details panel (an agent there is also selected). */
  const [active, setActive] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<PEdge | null>(null);
  const [table, setTable] = useState(false);
  const [hit, setHit] = useState<string | null>(null);
  const [announce, setAnnounce] = useState("");
  const [measured, setMeasured] = useState<Record<string, number>>({});
  const [widths, setWidths] = useState<Record<string, number>>({});
  const [showPref, setShowPref] = useState<Show | null>(null);
  const [focusReq, setFocusReq] = useState<(MapFocus & { picked?: boolean }) | null>(null);
  const [glide, setGlide] = useState(false);
  const [hover, setHover] = useState<string | null>(null);
  const [fitSeq, setFitSeq] = useState(0);
  /** Bumped to open the picker (an agent's "N lines to hidden objects" note). */
  const [pickerReq, setPickerReq] = useState(0);
  const wrap = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const reduced = usePrefersReducedMotion();
  // With staged changes is the default while the cart isn't empty; a choice you make sticks.
  const show: Show = cart.length ? (showPref ?? "staged") : "today";

  // ---------- graph (today, and with the cart applied) ----------
  const base = useMemo(
    () => buildPolicyGraph({ inventory: inv, gateways: gw.gateways, modelArmor: modelArmor.data, context: ctxInfo.data, ctx, direction, inherited: tools.inherited }),
    [inv, gw, modelArmor.data, ctxInfo.data, ctx, direction, tools.inherited],
  );
  const graph: PolicyGraph = useMemo(() => {
    if (show === "today" || !cart.length) return base;
    const sim = simulate({ inventory: inv, gateways: gw.gateways, modelArmor: modelArmor.data }, cart);
    const after = buildPolicyGraph({ inventory: sim.inventory, gateways: sim.gateways, modelArmor: sim.modelArmor, context: ctxInfo.data, ctx, direction, inherited: tools.inherited });
    return mergeStaged(base, after, diffGraphs(base, after), cart, inv, sim.effects);
  }, [base, show, cart, inv, gw, modelArmor.data, ctxInfo.data, ctx, direction, tools.inherited]);
  const staged = show !== "today" ? pendingCount(graph) + graph.nodes.filter((n) => n.pending).length : 0;
  const known = useMemo(() => new Set(base.nodes.map((n) => n.id)), [base]);

  // ---------- the picker: one per project, region and direction, saved next to the pins ----------
  const pkey = pickerKey(ctx.project, ctx.region, direction);
  const loaded = useMemo(() => loadPicker(storage(), pkey, (id) => known.has(id)), [pkey, known]);
  const [pickers, setPickers] = useState<Record<string, PickerState>>({});
  const pk = pickers[pkey] ?? loaded;
  const pkRef = useRef(pk);
  pkRef.current = pk;
  const setPk = useCallback(
    (next: PickerState) => {
      pkRef.current = next;
      savePicker(storage(), pkey, next);
      setPickers((p) => ({ ...p, [pkey]: next }));
    },
    [pkey],
  );
  const filters: MapFilters = useMemo(() => filtersOf(tools, pk), [tools, pk]);
  /** A filter change: the picker's part saved with the picker, the rest to the toolbar. */
  const set = (p: Partial<MapFilters>) => {
    const { picker, tools: t } = splitPatch(p);
    if (Object.keys(picker).length) setPk({ ...pkRef.current, ...picker });
    if (Object.keys(t).length) setTools((x) => ({ ...x, ...t }));
  };
  const items = useMemo(() => pickerItems(graph), [graph]);
  const sourceIds = useMemo(() => new Set(graph.nodes.filter((n) => isSource(n, direction)).map((n) => n.id)), [graph, direction]);

  // ---------- view → layout → React Flow ----------
  const view = useMemo(() => viewOf(graph, filters, pk.selected, { changesOnly: show === "changes", active }), [graph, filters, pk.selected, show, active]);
  // The picker's rows, read off this view: checked = on the map, unchecked with the filter that hides it.
  const env: PickerEnv = useMemo(() => ({ graph, tools, changesOnly: show === "changes", active }), [graph, tools, show, active]);
  const statuses = useMemo(() => pickerStatus(env, pk, view), [env, pk, view]);
  const envRef = useRef(env);
  envRef.current = env;
  const expanded = useMemo(() => expandedMcp(view, active), [view, active]);
  // A measured height holds for the card as drawn: expanded or not, how many tool rows, with the hidden-lines note or not.
  const looks = useMemo(() => new Map(view.nodes.map((n) => [n.id, `${expanded.has(n.id) ? 1 : 0}|${n.shownTools?.length ?? "all"}|${n.hiddenLines ? 1 : 0}`])), [view, expanded]);
  const hkey = useCallback((id: string) => `${id}|${looks.get(id) ?? ""}`, [looks]);
  const heights = useMemo(() => Object.fromEntries(view.nodes.map((n) => [n.id, measured[hkey(n.id)]]).filter(([, h]) => h !== undefined)), [view, measured, hkey]);
  // estimates measure chip text (fit.ts); they're measured again once web fonts load
  const fonts = useSyncExternalStore(onFontEpoch, fontEpoch, fontEpoch);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const layout = useMemo(() => layoutView(view, { expanded, heights }), [view, expanded, heights, fonts]);

  // Auto-select: with nothing selected and exactly one agent in view, select it (so the map doesn't open empty). Once
  // per set of agents in view, so deselecting it sticks.
  const inView = useMemo(() => view.nodes.filter((n) => n.kind === "engine" && isSource(n, direction)).map((n) => n.id), [view, direction]);
  const autoKey = `${pkey}|${inView.join(",")}`;
  useEffect(() => {
    const s = autoSelect(inView, pkRef.current.selected);
    if (s) setPk({ ...pkRef.current, selected: s });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoKey]);

  // Saved positions: only dragged nodes, per project, region and direction. Ids are checked against today's graph
  // (and the "no grants" groups), so ids that left the project are dropped on load.
  const { pins, pin, unpin, reset } = usePositions(posKey(ctx.project, ctx.region, direction), (id) => known.has(id) || id.startsWith("group:"), true);
  const pinned = useMemo(() => new Set(Object.keys(pins)), [pins]);
  const flow = useMemo(() => toFlow(view, layout, { node: active, edge: selEdge?.id ?? null, hit }, expanded, reduced, pinned), [view, layout, active, selEdge, hit, expanded, reduced, pinned]);

  // Nodes are controlled so they can be dragged: a pinned node takes its saved place, the rest the auto layout, moved
  // down their column off any pinned node they'd sit under (resolveOverlaps). Sizes: measured by React Flow where known
  // (heights reach the layout through `heights`), else the layout's estimates; section titles are HEADER_H tall.
  // Measured sizes are kept so nodes don't flash while React Flow re-measures.
  const sizes = useMemo(() => {
    const out: Record<string, { w: number; h: number }> = {};
    for (const [id, z] of Object.entries(layout.size)) out[id] = { w: widths[id] ?? z.w, h: z.h };
    for (const h of layout.headers) out[h.id] = { w: h.w, h: HEADER_H };
    return out;
  }, [layout, widths]);
  const placed = useMemo(
    () => placeNodes(Object.fromEntries(flow.nodes.map((n) => [n.id, n.position])), pins, { size: sizes, column: layout.column }),
    [flow.nodes, pins, sizes, layout],
  );
  /** The whole map's box (every node where it's placed, with its size), for Fit and the automatic fits. */
  const bounds = useMemo(() => {
    const ids = Object.keys(placed);
    if (!ids.length) return null;
    const xs = ids.map((id) => placed[id].x);
    const ys = ids.map((id) => placed[id].y);
    const x = Math.min(...xs);
    const y = Math.min(...ys);
    return { x, y, width: Math.max(...ids.map((id) => placed[id].x + (sizes[id]?.w ?? 0))) - x, height: Math.max(...ids.map((id) => placed[id].y + (sizes[id]?.h ?? 0))) - y };
  }, [placed, sizes]);
  const [rfNodes, setRfNodes] = useState<MNode[]>([]);
  useEffect(() => {
    setRfNodes((prev) => {
      const old = new Map(prev.map((n) => [n.id, n]));
      return flow.nodes.map((n) => ({ ...n, measured: old.get(n.id)?.measured, position: placed[n.id] ?? n.position }));
    });
  }, [flow.nodes, placed]);
  const hkeyRef = useRef(hkey);
  hkeyRef.current = hkey;
  const measuredRef = useRef(measured);
  measuredRef.current = measured;
  const placedRef = useRef<Record<string, { x: number; y: number }>>({});
  // where each node sits before a drag (its pin, or the auto layout off the pins): a drop elsewhere pins it
  placedRef.current = placed;
  const dropRef = useRef({ pins, sizes });
  dropRef.current = { pins, sizes };
  const onNodesChange = useCallback(
    (changes: NodeChange<MNode>[]) => {
      // Drops and arrow-key moves (dragging false) pin the node where it is; a click that didn't move it doesn't.
      for (const c of changes)
        if (c.type === "position" && c.position && c.dragging === false && !c.id.startsWith("hdr:")) {
          const was = placedRef.current[c.id];
          if (!was || Math.abs(was.x - c.position.x) > 0.5 || Math.abs(was.y - c.position.y) > 0.5) {
            // A drop onto another pinned node slides down to the nearest free spot below it (pinned nodes never move);
            // unpinned nodes under the drop make way themselves (placeNodes).
            const { pins: ps, sizes: sz } = dropRef.current;
            const box = (id: string, p: { x: number; y: number }) => ({ id, ...p, w: sz[id]?.w ?? 0, h: sz[id]?.h ?? 0 });
            const others = Object.entries(ps).map(([id, p]) => ({ ...box(id, p), pinned: true }));
            pin(c.id, freeSpot(box(c.id, c.position), others, GAP_Y));
          }
        }
      setRfNodes((ns) => applyNodeChanges(changes.filter((c) => c.type !== "remove"), ns));
      const upd: Record<string, number> = {};
      for (const c of changes) {
        if (c.type === "dimensions" && c.dimensions && !c.id.startsWith("hdr:")) {
          const w = Math.round(c.dimensions.width);
          if (w > 0) setWidths((m) => (m[c.id] === w ? m : { ...m, [c.id]: w }));
          const k = hkeyRef.current(c.id);
          if (Math.abs((measuredRef.current[k] ?? -99) - c.dimensions.height) > 1) upd[k] = Math.round(c.dimensions.height);
        }
      }
      if (Object.keys(upd).length) setMeasured((m) => ({ ...m, ...upd }));
    },
    [pin],
  );
  // Lane moves (a staged bind or unbind, a change of view) glide; drags never do, nor anything under reduced motion.
  const cartKey = `${show}|${cart.length}`;
  const firstCart = useRef(true);
  useEffect(() => {
    if (firstCart.current) {
      firstCart.current = false;
      return;
    }
    if (reduced) return;
    setGlide(true);
    const t = setTimeout(() => setGlide(false), 650);
    return () => clearTimeout(t);
  }, [cartKey, reduced]);

  // ---------- selection ----------
  // the graph's nodes, plus the view's group nodes (lines into the Google APIs group need its label)
  const nodeById = useMemo(() => new Map([...view.nodes, ...graph.nodes].map((n) => [n.id, n])), [graph, view]);
  const label = useCallback((id: string) => nodeById.get(id)?.label ?? id.split("/").pop() ?? id, [nodeById]);
  const nodeOf = useCallback((id: string) => nodeById.get(id), [nodeById]);
  const edgeNow = useMemo(() => (selEdge ? resolveEdge([...view.edges, ...view.rows], selEdge) : null), [selEdge, view]);
  // its line left the map: the panel closes
  useEffect(() => {
    if (selEdge && !edgeNow) setSelEdge(null);
  }, [selEdge, edgeNow]);
  /** Remember what had focus, so closing the panel can return there. */
  const remember = () => {
    const a = document.activeElement as HTMLElement | null;
    opener.current = a && a !== document.body ? a : null;
  };
  /** Click (or Enter on) a node: an agent's selection toggles (its lines drawn or not) and its details open; any other
   *  node opens its details. */
  const selectNode = useCallback(
    (id: string) => {
      const n = nodeById.get(id);
      setSelEdge(null);
      if (sourceIds.has(id)) {
        const next = toggleAgent(pkRef.current, id);
        setPk(next);
        const on = next.selected.includes(id);
        setActive((a) => (on ? id : a === id ? null : a));
        if (n) setAnnounce(on ? `${n.label} selected: its lines are drawn and its details are in the panel after the map.` : `${n.label} deselected: its lines are hidden.`);
        return;
      }
      setActive(id);
      if (n) setAnnounce(`${n.label}: its details are in the panel after the map. Arrow keys move it; Escape closes the details.`);
    },
    [nodeById, sourceIds, setPk],
  );
  const selectEdge = useCallback(
    (e: PEdge) => {
      setSelEdge(e);
      setAnnounce(`Policy details: ${edgeAria(e, label)}.`);
    },
    [label],
  );
  // after the panel's own effects (it focuses itself when it switches to the node that stays selected)
  const returnFocus = (id: string) =>
    setTimeout(() => {
      const el = opener.current && document.contains(opener.current) ? opener.current : wrap.current?.querySelector<HTMLElement>(`[data-id="${CSS.escape(id)}"]`);
      el?.focus({ preventScroll: true });
      opener.current = null;
    }, 60);
  /** Clear: no agent selected, no details open. */
  const clear = useCallback(() => {
    setPk({ ...pkRef.current, selected: [] });
    setActive(null);
    setSelEdge(null);
    setAnnounce("Selection cleared: no lines are drawn.");
  }, [setPk]);
  const closePanel = () => {
    if (selEdge) {
      const id = selEdge.id;
      setSelEdge(null);
      returnFocus(id);
    } else if (active) {
      const id = active;
      setActive(null);
      returnFocus(id);
    }
  };
  const changeDirection = (d: Direction) => {
    if (d === direction) return;
    setDirection(d);
    setTools((f) => ({ ...f, gateway: "all", expanded: [], hidden: [] }));
    setActive(null);
    setSelEdge(null);
    setHover(null);
  };

  // ---------- centering on a node (the picker's "Only this", "Show on map", the same-agent link) ----------
  const center = useCallback(
    (id: string) => {
      const n = rf.getNode(id);
      if (!n) return false;
      const w = n.measured?.width ?? 240;
      const h = n.measured?.height ?? 80;
      void rf.setCenter(n.position.x + w / 2, n.position.y + h / 2, { zoom: Math.max(rf.getZoom(), 0.9), duration: reduced ? 0 : 450 });
      return true;
    },
    [rf, reduced],
  );
  const pendingCenter = useRef<string | null>(null);
  useEffect(() => {
    const id = pendingCenter.current;
    if (!id || !rfNodes.some((n) => n.id === id && n.measured)) return;
    pendingCenter.current = null;
    center(id);
  }, [rfNodes, center]);
  useEffect(() => {
    if (!hit) return;
    const t = setTimeout(() => setHit(null), 2600);
    return () => clearTimeout(t);
  }, [hit]);
  const jump = useCallback(
    (id: string) => {
      // The same agent in the other column: Agent Runtime agents appear as callers and as registry entries.
      // checked (forced on if a filter hides it) and, an agent, selected
      const item = items.find((i) => i.id === id);
      const st = pkRef.current;
      setPk(item ? checkRows(envRef.current, st, [item], true) : { ...st, off: st.off.filter((x) => x !== id) });
      setActive(id);
      setSelEdge(null);
      setHit(id);
      pendingCenter.current = id;
    },
    [items, setPk],
  );
  const openPicker = useCallback(() => setPickerReq((k) => k + 1), []);
  const actions = useMemo(() => ({ jump, unpin, openPicker }), [jump, unpin, openPicker]);

  // ---------- the picker: Apply, the affiliation shortcut, Reset view ----------
  const applyPicker = (next: PickerState, focus: string | null) => {
    let st = next;
    let t: Tools = next.hideEmpty !== pk.hideEmpty ? { ...tools, expanded: [] } : tools;
    // "Only this" (or Enter on a single match) on an object inside a group: expand what hides it
    if (focus) {
      const patch = revealPatch(graph, filtersOf(t, st), st.selected, focus, { changesOnly: show === "changes", active });
      if (patch) {
        const sp = splitPatch(patch);
        st = { ...st, ...sp.picker };
        t = { ...t, ...sp.tools };
      }
      setHit(focus);
      pendingCenter.current = focus;
    } else setFitSeq((k) => k + 1);
    setPk(st);
    setTools(t);
    if (active && st.off.includes(active)) setActive(null);
    const on = [...pickerStatus({ ...env, tools: t }, st).values()].filter((x) => x.on).length;
    setAnnounce(`${on} of ${items.length} objects on the map${st.selected.length ? `, lines of ${plural(st.selected.length, "selected agent")}` : ", no agent selected"}.`);
  };
  const affiliation = affiliationOf(pk, graph);
  const presetAff = (a: Affiliation) => {
    setPk(presetAffiliation(pk, graph, a));
    setFitSeq((k) => k + 1);
  };
  /** A toolbar type box: the same as the picker's group checkbox of that type. */
  const toggleType = (types: DestType[]) => {
    setPk(toggleTypes(env, pk, types, statuses));
    setFitSeq((k) => k + 1);
  };
  /** The gateway filter: a new choice drops the overrides of the old one. */
  const setGateway = (gateway: string) => {
    setPk(dropOverrides(pk, statuses, "otherGateway"));
    setTools((x) => ({ ...x, gateway }));
  };
  /** Reset view: groups collapsed, pins cleared, every object visible and nothing selected (then auto-select), fit.
   *  Direction, Allows / Denies and Inherited grants stay. */
  const resetView = () => {
    reset();
    setPk(resetPicker(base));
    setTools((t) => ({ ...DEFAULT_TOOLS, allows: t.allows, denies: t.denies, inherited: t.inherited }));
    setActive(null);
    setSelEdge(null);
    setHover(null);
    setHit(null);
    pendingCenter.current = null;
    setFitSeq((k) => k + 1);
    setAnnounce("View reset: every object on the map, groups collapsed, nothing pinned.");
  };

  // ---------- "Show on map" from another step: direction, the picker, the groups that hide it, then the line ----------
  useEffect(() => {
    if (!mapFocus) return;
    clearMapFocus();
    const f: MapFocus = { direction: mapFocus.direction, node: mapFocus.node, target: mapFocus.target };
    if (f.direction) setDirection(f.direction);
    setTools((x) => ({ ...x, gateway: "all", hidden: [], expanded: [] }));
    setTable(false);
    setSelEdge(null);
    setFocusReq(f);
  }, [mapFocus, clearMapFocus]);
  useEffect(() => {
    if (!focusReq || (focusReq.direction && focusReq.direction !== direction)) return;
    if (!focusReq.picked) {
      // the node and the target checked in the picker; an agent (or pseudo caller) selected, so its lines draw
      setPk(focusPicker(pkRef.current, focusReq, (id) => sourceIds.has(id), envRef.current));
      setActive(focusReq.node ?? focusReq.target ?? null);
      setFocusReq({ ...focusReq, picked: true });
      return;
    }
    const id = focusReq.target && !focusReq.node ? focusReq.target : focusReq.node;
    // a destination grouped under "Google APIs" or "+N with no grants" is shown first
    const grouped = [focusReq.node, focusReq.target].find((x) => x && view.nodes.some((n) => n.grouped?.includes(x)));
    const patch = grouped ? revealPatch(graph, filters, pk.selected, grouped, { changesOnly: show === "changes", active }) : null;
    if (patch && Object.keys(patch).length) return set(patch);
    setFocusReq(null);
    const e = findFocusEdge(view.edges, focusReq);
    if (e) {
      opener.current = null;
      selectEdge(e);
    } else if (id) {
      const n = nodeById.get(id);
      setAnnounce(n ? `${n.label} selected.` : "Not on the map with these filters.");
    }
    if (id) {
      setHit(id);
      pendingCenter.current = id;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusReq, view, direction]);

  // ---------- keyboard: Enter / Space select (and open the panel), Esc closes the panel, then clears ----------
  const onKey = (e: ReactKeyboardEvent) => {
    const t = e.target as HTMLElement;
    if ((e.key === "Enter" || e.key === " ") && (t.classList.contains("react-flow__node") || t.classList.contains("react-flow__edge"))) {
      const id = t.getAttribute("data-id") ?? "";
      e.preventDefault();
      opener.current = t;
      if (t.classList.contains("react-flow__edge")) {
        const ed = flow.edges.find((x) => x.id === id)?.data?.edge;
        if (ed) selectEdge(ed);
        return;
      }
      const n = rfNodes.find((x) => x.id === id);
      if (n?.type === "nogrants" || n?.type === "google") return set(expandGroup(n.data.node, filters));
      if (n && n.type !== "section") selectNode(id);
      return;
    }
    if (e.key === "Escape" && (active || selEdge)) {
      e.stopPropagation();
      closePanel();
    } else if (e.key === "Escape" && pk.selected.length && t.closest(".pmap-canvas")) {
      e.stopPropagation();
      clear();
    }
  };

  // ---------- toolbar data ----------
  const dirGws = gw.gateways.filter((g) => g.type === direction);
  const selNode = active ? nodeById.get(active) : undefined;
  const legend = LEGEND[direction].filter((v) => v !== "unchecked" || dirGws.some((g) => !g.enforcement?.mode));
  // Not refit when a group is expanded (a click, or "Only this" that centers on its match) or an agent is selected.
  const fitKey = `${direction}|${tools.gateway}|${pk.hideEmpty}|${table}|${show === "changes"}|${fitSeq}`;
  const counts = {
    agents: view.nodes.filter((n) => n.kind === "engine").length,
    // the collapsed Google APIs node counts its endpoints
    dests: view.nodes.filter((n) => n.column === "dests" && n.kind !== "endpoint_group" && n.kind !== "engine").reduce((k, n) => k + (n.kind === "google_apis" ? (n.grouped?.length ?? 0) : 1), 0),
  };
  const hoverIdx = hover ? view.agents.indexOf(hover) : -1;
  const egress = direction === "egress";

  return (
    <MapActions.Provider value={actions}>
      <div className="pmap" onKeyDown={onKey}>
        <EdgeMarkers />
        {hoverIdx >= 0 && view.agents.length > 1 && (
          // hovering a selected agent (or one of its lines): its path stands out, the other agents' lines fade
          <style>{`.pmap-canvas .react-flow__edge:not(.ag${hoverIdx}), .pmap-canvas .edge-badge-wrap:not(.ag${hoverIdx}) { opacity: 0.12; } .pmap-canvas .react-flow__edge.ag${hoverIdx} .edge-path { stroke-width: 3px; }`}</style>
        )}
        <div className="pmap-toolbar" role="toolbar" aria-label="Policy map filters">
          <div className="pmap-tools-row">
            <div className="seg" role="group" aria-label="Direction">
              {(
                [
                  ["egress", "Agent-to-Anywhere", "Agents calling out: A2A agents, MCP servers, APIs. Checked against roles/iap.egressor grants."],
                  ["ingress", "Client-to-Agent", "Clients calling your agents. The gateway screens content; it doesn't check who the caller is."],
                ] as const
              ).map(([d, l, tip]) => (
                <Tip key={d} tip={tip} placement="bottom">
                  <button type="button" className={`seg-btn ${direction === d ? "on" : ""}`} aria-pressed={direction === d} onClick={() => changeDirection(d)}>
                    {l}
                  </button>
                </Tip>
              ))}
            </div>
            <div className="seg" role="group" aria-label="Agents in the picker">
              {AFFILIATION.map((a) => (
                <Tip key={a.id} tip={a.tip} placement="bottom">
                  <button type="button" className={`seg-btn ${affiliation === a.id ? "on" : ""}`} aria-pressed={affiliation === a.id} onClick={() => presetAff(a.id)}>
                    {a.label}
                  </button>
                </Tip>
              ))}
            </div>
            {dirGws.length > 1 && (
              <select className="pmap-select" value={tools.gateway} onChange={(e) => setGateway(e.target.value)} aria-label="Gateway">
                <option value="all">All gateways</option>
                {dirGws.map((g) => (
                  <option key={g.name} value={g.name}>
                    {g.id}
                  </option>
                ))}
              </select>
            )}
            <ObjectPicker items={items} value={pk} env={env} statuses={statuses} google={egress} onApply={applyPicker} openReq={pickerReq} />
            <span className="pmap-tools-end">
              <Tip tip="Zoom to fit the whole map." placement="bottom">
                <button type="button" className="btn btn-tonal btn-small" onClick={() => fitMap(rf, bounds, wrap.current, reduced ? 0 : 300)} disabled={table}>
                  <ExpandIcon size={14} /> Fit
                </button>
              </Tip>
              <Tip tip={`Collapse the expanded groups, ${pinned.size ? `put the ${plural(pinned.size, "node")} you dragged back in place, ` : ""}show every object with no agent selected, and fit. Direction and Show stay.`} placement="bottom">
                <button type="button" className="btn btn-tonal btn-small" onClick={resetView}>
                  Reset view
                </button>
              </Tip>
              <button type="button" className={`btn btn-small ${table ? "btn-primary" : "btn-tonal"}`} aria-pressed={table} onClick={() => setTable(!table)}>
                Table view
              </button>
            </span>
          </div>
          <div className="pmap-tools-row">
            {egress && (
              <div className="pmap-types" role="group" aria-label="Destination types (the picker's groups of these types)">
                {TYPE_BOXES.map((b) => {
                  const st = typeState(statuses, items, b.types, pk);
                  return (
                    <Tip key={b.label} tip={
                        st === "all"
                          ? `On the map. Click to hide them (the picker's group unchecks too).`
                          : st === "some"
                            ? `Some are only in a group (Google APIs, no grants), hidden by another filter or by hand (the picker says why). Click to hide them all.`
                            : b.types.every((t) => pk.typesOff.includes(t))
                              ? `Hidden by this type filter. Click to show them again.`
                              : `None is on the map: another filter hides them (the picker says why). Click to show them anyway.`
                      } placement="bottom">
                      <label className={`pmap-check ${st !== "none" ? "on" : ""}`}>
                        <input
                          type="checkbox"
                          checked={st === "all"}
                          ref={(el) => {
                            if (el) el.indeterminate = st === "some";
                          }}
                          onChange={() => toggleType(b.types)}
                        />
                        {b.label}
                      </label>
                    </Tip>
                  );
                })}
              </div>
            )}
            <div className="seg seg-small" role="group" aria-label="Show staged changes">
              {SHOW.map((o) => (
                <Tip key={o.id} tip={!cart.length && o.id !== "today" ? "The cart is empty: nothing is staged." : o.tip} placement="bottom">
                  <button type="button" className={`seg-btn ${show === o.id ? "on" : ""}`} aria-pressed={show === o.id} disabled={!cart.length && o.id !== "today"} onClick={() => {
                      if (o.id !== show) setPk(dropOverrides(pkRef.current, statuses, "changes"));
                      setShowPref(o.id);
                    }}
                  >
                    {o.label}
                  </button>
                </Tip>
              ))}
            </div>
            {show !== "today" && (
              <span className="pmap-more">
                <ClockIcon size={12} /> {staged ? `${plural(staged, "staged change")} on the map` : "Nothing in the cart changes this view"}
              </span>
            )}
          </div>
          {/* always there, so selecting the first agent doesn't push the canvas down under the pointer */}
          <div className="pmap-tools-row pmap-selbar">
            {!view.agents.length && !selNode && <span className="small muted">No agent selected: the map shows no lines.</span>}
            {view.agents.length > 0 && (
              <span className="small pmap-sel-names">
                {view.agents.length === 1 ? "Lines of " : `Lines of ${view.agents.length} agents: `}
                {view.agents.map((id, i) => (
                  <span key={id}>
                    {i > 0 && ", "}
                    <b>{label(id)}</b>
                  </span>
                ))}
              </span>
            )}
            {egress && view.agents.length > 0 && (
              <div className="pmap-show" role="group" aria-label="Show lines">
                <span className="small muted">Show:</span>
                <Tip tip="Allowed, partly allowed and conditional lines, inherited ones and grants that aren't enforced. On an MCP server: the tools a grant allows." placement="bottom">
                  <label className="pmap-check plain">
                    <input type="checkbox" checked={tools.allows} onChange={(e) => setTools((x) => ({ ...x, allows: e.target.checked }))} />
                    Allows
                  </label>
                </Tip>
                <Tip tip="Default-deny lines: denied (enforce) or would be denied (dry run) for want of a grant. On an MCP server: the tools no grant allows." placement="bottom">
                  <label className="pmap-check plain">
                    <input type="checkbox" checked={tools.denies} onChange={(e) => setTools((x) => ({ ...x, denies: e.target.checked }))} />
                    Denies
                  </label>
                </Tip>
                <Tip tip="Add the grants each agent gets from project-wide, public, group or registry-wide bindings." placement="bottom">
                  <label className="pmap-check plain">
                    <input type="checkbox" checked={tools.inherited} onChange={(e) => setTools((x) => ({ ...x, inherited: e.target.checked }))} />
                    Inherited grants
                  </label>
                </Tip>
              </div>
            )}
            {view.more > 0 && <span className="pmap-more">+{view.more} more default-deny lines not drawn</span>}
            {selNode && !view.agents.includes(selNode.id) && (
              <span className="small">
                Details: <b>{selNode.label}</b>
              </span>
            )}
            {(view.agents.length > 0 || selNode) && (
              <button type="button" className="btn btn-text btn-small" onClick={clear}>
                Clear
              </button>
            )}
          </div>
        </div>

        {direction === "ingress" && (
          <Callout tone="info" title="Client-to-Agent doesn't check who calls">
            The gateway screens content with Model Armor. Who may call an agent is decided by the agent's Agent Runtime IAM, which Policy Studio doesn't read, so callers are shown as “Any allowed caller”.
          </Callout>
        )}
        {view.lines > TOO_MANY_LINES && (
          <Callout tone="warn" title={`${view.lines} lines on the map`}>
            Select fewer agents{egress ? ", or untick Show: Denies," : ""} to keep it readable.
          </Callout>
        )}

        <div className={`pmap-stage ${table ? "is-table" : ""}`}>
          {table ? (
            <MapTable
              view={view}
              nodes={graph.nodes}
              selected={edgeNow?.id ?? null}
              onSelect={(e) => {
                remember();
                selectEdge(e);
              }}
            />
          ) : (
            <div className={`pmap-canvas ${glide ? "glide" : ""}`} ref={wrap}>
              {!view.agents.length && (
                <p className="pmap-hint" role="note">
                  Select an agent (click it, or use the picker) to see what it can reach.
                </p>
              )}
              <ReactFlow
                nodes={rfNodes}
                edges={flow.edges}
                nodeTypes={nodeTypes}
                edgeTypes={edgeTypes}
                onNodesChange={onNodesChange}
                onNodeClick={(_, n) => {
                  if (n.type === "section") return;
                  if (n.type === "nogrants" || n.type === "google") return set(expandGroup(n.data.node, filters));
                  remember();
                  selectNode(n.id);
                }}
                onNodeMouseEnter={(_, n) => setHover(view.agents.includes(n.id) ? n.id : null)}
                onNodeMouseLeave={() => setHover(null)}
                onEdgeMouseEnter={(_, e) => setHover(e.data?.edge.caller && view.agents.includes(e.data.edge.caller) ? e.data.edge.caller : null)}
                onEdgeMouseLeave={() => setHover(null)}
                onEdgeClick={(_, e) => {
                  if (!e.data?.edge) return;
                  remember();
                  selectEdge(e.data.edge);
                }}
                onPaneClick={() => setSelEdge(null)}
                nodesConnectable={false}
                nodesDraggable
                nodesFocusable
                edgesFocusable
                elementsSelectable
                deleteKeyCode={null}
                ariaLabelConfig={ARIA}
                fitView
                fitViewOptions={{ padding: PAD, maxZoom: 1.15 }}
                minZoom={MIN_ZOOM}
                maxZoom={2}
                zoomOnDoubleClick={false}
                onlyRenderVisibleElements
                colorMode="system"
                proOptions={{ hideAttribution: true }}
              >
                <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} className="diagram-bg" />
                <Controls showInteractive={false} position="bottom-right" />
                <Fitter fitKey={fitKey} wrap={wrap} bounds={bounds} />
              </ReactFlow>
            </div>
          )}
          {(edgeNow || selNode) && <PolicyPanel edge={edgeNow} node={edgeNow ? null : (selNode ?? null)} inv={inv} gateways={gw.gateways} nodeOf={nodeOf} label={label} onClose={closePanel} />}
          <div className="legend" role="group" aria-label="Legend: click to hide or show a kind of line">
            {legend.map((v) => {
              const off = tools.hidden.includes(v);
              return (
                <button
                  key={v}
                  type="button"
                  className={`legend-item ${off ? "off" : ""}`}
                  aria-pressed={!off}
                  title={off ? `Show “${VERDICT_LABEL[v]}” lines` : `Hide “${VERDICT_LABEL[v]}” lines`}
                  onClick={() => setTools((x) => ({ ...x, hidden: off ? x.hidden.filter((y) => y !== v) : [...x.hidden, v] }))}
                >
                  <svg width="30" height="10" className="legend-line" aria-hidden="true">
                    <line x1="1" y1="5" x2="29" y2="5" className={`edge-path st-${v}`} />
                  </svg>
                  {(v === "blocked" || v === "would_deny") && (
                    <span className={`legend-icon li-${v}`}>
                      <CloseIcon size={10} />
                    </span>
                  )}
                  {v === "conditional" && <span className="legend-icon li-conditional">?</span>}
                  {VERDICT_LABEL[v]}
                </button>
              );
            })}
            <span className="legend-item static">
              <span className="legend-icon li-shield">
                <ShieldIcon size={10} />
              </span>
              Model Armor screens it
            </span>
            {egress && (
              <span className="legend-item static">
                <svg width="30" height="10" className="legend-line" aria-hidden="true">
                  <line x1="1" y1="5" x2="29" y2="5" className="edge-path st-allowed inherited" />
                </svg>
                Inherited (group or registry-wide grant)
              </span>
            )}
            {show !== "today" && (
              <span className="legend-item static">
                <span className="legend-icon li-pending">
                  <ClockIcon size={10} />
                </span>
                Staged: dashed = added, red overlay = removed
              </span>
            )}
            <span className="legend-item static muted">Lines only for selected agents, one per agent</span>
          </div>
        </div>
        <p className="small muted pmap-foot" aria-live="polite">
          {counts.agents ? plural(counts.agents, "agent") : "No agents"}
          {view.agents.length ? ` (${view.agents.length} selected)` : ""} · {plural(counts.dests, "destination")} · {plural(view.lines, "line")}
          {egress && graph.stats.unreadable ? ` · ${plural(graph.stats.unreadable, "IAP policy", "IAP policies")} couldn't be read` : ""}. Click an agent to draw its lines (again to hide them). Drag nodes (or select one and use the
          arrow keys) to move them: they keep their place; scroll or pinch to zoom.
        </p>
        <div className="sr-only" role="status" aria-live="polite">
          {announce}
        </div>
        {graph.notes.length > (direction === "ingress" ? 1 : 0) && (
          <Disclosure summary={`Notes (${graph.notes.length - (direction === "ingress" ? 1 : 0)})`}>
            <ul className="plain-list small">
              {graph.notes.slice(direction === "ingress" ? 1 : 0).map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </Disclosure>
        )}
      </div>
    </MapActions.Provider>
  );
}
