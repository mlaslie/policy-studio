// Policy map step (lazy-loaded chunk with React Flow): who can reach what, and why, drawn from the policy state Policy
// Studio already reads (docs/VISUALIZATION_PLAN.md). The canvas (zoom, pan, drag), the toolbar filters, the
// selected-agent view, the legend as a verdict filter and the table view; the policy panel (PolicyPanel.tsx) whose
// actions only stage into the cart; the staged-change view (Today / With staged changes / Changes only: simulate.ts,
// diff.ts); saved positions for dragged nodes (usePositions.ts); keyboard use and "Show on map" focus.
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
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type RefObject } from "react";
import type { GatewaysResp, Inventory } from "../api/types";
import { Callout, Disclosure, Load, StepHeader } from "../components/ui";
import { Tip } from "../components/Tooltip";
import { ClockIcon, CloseIcon, ExpandIcon, SearchIcon, ShieldIcon } from "../components/Icons";
import { useStudio } from "../store";
import { plural } from "../lib/util";
import { buildPolicyGraph, type Direction, type PEdge, type PolicyGraph, type Verdict } from "./graph";
import { DEFAULT_DIRECTION, DEFAULT_FILTERS, type Affiliation, type DestType, type MapFilters, viewOf } from "./view";
import { layoutView } from "./layout";
import { VERDICT_LABEL, edgeAria, expandedMcp, toFlow, type MNode } from "./toFlow";
import { nodeTypes, MapActions } from "./nodes";
import { EdgeMarkers, edgeTypes } from "./edges";
import MapTable from "./MapTable";
import PolicyPanel from "./PolicyPanel";
import { simulate } from "./simulate";
import { diffGraphs, mergeStaged, pairKey, pendingCount } from "./diff";
import { posKey, usePositions } from "./usePositions";
import { findFocusEdge, type MapFocus } from "./focus";

const PAD = { top: "40px", bottom: "40px", left: "24px", right: "40px" } as const;
/** Combined lines past this suggest narrowing the filters (§7). */
const TOO_MANY = 400;

const DEST_TYPES: { id: DestType; label: string }[] = [
  { id: "a2a", label: "A2A agents" },
  { id: "runtime", label: "Agent Runtime" },
  { id: "mcp", label: "MCP servers" },
  { id: "api", label: "APIs" },
];
const AFFILIATION: { id: Affiliation; label: string; tip: string }[] = [
  { id: "all", label: "All agents", tip: "Every Agent Runtime agent, with or without a gateway." },
  { id: "gateway", label: "Behind a gateway", tip: "Agents bound to a gateway: their allowed connections are checked by policy." },
  { id: "none", label: "No gateway", tip: "Agents with no gateway: no policy applies, their traffic goes straight out (or straight in)." },
];
const LEGEND: Record<Direction, Verdict[]> = {
  egress: ["allowed", "partial", "conditional", "would_deny", "blocked", "unchecked", "dormant", "direct"],
  ingress: ["screened", "unscreened", "direct"],
};

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

/** Fit on open and whenever the filters change, and on resize (the Learn rail, the window); from the demo. */
function Fitter({ fitKey, wrap }: { fitKey: string; wrap: RefObject<HTMLDivElement | null> }) {
  const rf = useReactFlow();
  const init = useNodesInitialized();
  useEffect(() => {
    if (!init) return;
    const t = setTimeout(() => void rf.fitView({ padding: PAD, duration: 350, maxZoom: 1.15 }), 220);
    return () => clearTimeout(t);
  }, [fitKey, init, rf]);
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    let t: ReturnType<typeof setTimeout> | undefined;
    const ro = new ResizeObserver(() => {
      clearTimeout(t);
      t = setTimeout(() => void rf.fitView({ padding: PAD, duration: 200, maxZoom: 1.15 }), 160);
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      clearTimeout(t);
    };
  }, [rf, wrap]);
  return null;
}

type Show = "today" | "staged" | "changes";
const SHOW: { id: Show; label: string; tip: string }[] = [
  { id: "today", label: "Today", tip: "The policy in your project now." },
  { id: "staged", label: "With staged changes", tip: "Today's policy with the cart applied: pending lines have a clock. A preview; Review's diff is the authority." },
  { id: "changes", label: "Changes only", tip: "Only the lines and nodes the cart changes." },
];
/** Node and line descriptions read by screen readers when they get focus (React Flow's ariaLabelConfig). */
const ARIA = {
  "node.a11yDescription.default": "Press Enter or Space to select it and show its details. Arrow keys then move it (its place is saved); Escape clears the selection.",
  "node.a11yDescription.keyboardDisabled": "Press Enter or Space to select it and show its details.",
  "node.a11yDescription.ariaLiveMessage": ({ direction }: { direction: string; x: number; y: number }) => `Moved ${direction}. Its place is saved.`,
  "edge.a11yDescription.default": "Press Enter or Space to show the policy behind this line; Escape closes it.",
};

/** The line now: a selected line is re-found in the current view (by id, then as the same caller and destination), so
 *  the panel follows it into the staged-change view after something is staged. */
function resolveEdge(edges: PEdge[], e: PEdge): PEdge {
  const all = edges.flatMap((x) => [x, ...(x.parts ?? [])]);
  return all.find((x) => x.id === e.id) ?? all.find((x) => pairKey(x) === pairKey(e)) ?? e;
}

function PolicyMap({ inv, gw }: { inv: Inventory; gw: GatewaysResp }) {
  const { modelArmor, ctxInfo, ctx, cart, mapFocus, clearMapFocus } = useStudio();
  const rf = useReactFlow();
  const [direction, setDirection] = useState<Direction>(DEFAULT_DIRECTION);
  const [filters, setFilters] = useState<MapFilters>(DEFAULT_FILTERS);
  const [selected, setSelected] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<PEdge | null>(null);
  const [table, setTable] = useState(false);
  const [query, setQuery] = useState("");
  const [hit, setHit] = useState<string | null>(null);
  const [searchMsg, setSearchMsg] = useState("");
  const [announce, setAnnounce] = useState("");
  const [measured, setMeasured] = useState<Record<string, number>>({});
  const [showPref, setShowPref] = useState<Show | null>(null);
  const [focusReq, setFocusReq] = useState<MapFocus | null>(null);
  const [glide, setGlide] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const reduced = usePrefersReducedMotion();
  const set = (p: Partial<MapFilters>) => setFilters((f) => ({ ...f, ...p }));
  // With staged changes is the default while the cart isn't empty; a choice you make sticks.
  const show: Show = cart.length ? (showPref ?? "staged") : "today";

  // ---------- graph (today, and with the cart applied) → view → layout → React Flow ----------
  const focusEngine = direction === "egress" && selected && inv.engines.some((e) => e.name === selected) ? selected : null;
  const base = useMemo(
    () => buildPolicyGraph({ inventory: inv, gateways: gw.gateways, modelArmor: modelArmor.data, context: ctxInfo.data, ctx, direction, focus: focusEngine, inherited: filters.inherited }),
    [inv, gw, modelArmor.data, ctxInfo.data, ctx, direction, focusEngine, filters.inherited],
  );
  const graph: PolicyGraph = useMemo(() => {
    if (show === "today" || !cart.length) return base;
    const sim = simulate({ inventory: inv, gateways: gw.gateways, modelArmor: modelArmor.data }, cart);
    const after = buildPolicyGraph({ inventory: sim.inventory, gateways: sim.gateways, modelArmor: sim.modelArmor, context: ctxInfo.data, ctx, direction, focus: focusEngine, inherited: filters.inherited });
    return mergeStaged(base, after, diffGraphs(base, after), cart, inv, sim.effects);
  }, [base, show, cart, inv, gw, modelArmor.data, ctxInfo.data, ctx, direction, focusEngine, filters.inherited]);
  const staged = show !== "today" ? pendingCount(graph) + graph.nodes.filter((n) => n.pending).length : 0;
  const view = useMemo(() => viewOf(graph, filters, selected, { changesOnly: show === "changes" }), [graph, filters, selected, show]);
  const expanded = useMemo(() => expandedMcp(view, selected), [view, selected]);
  const hkey = useCallback((id: string) => `${id}|${expanded.has(id) ? 1 : 0}`, [expanded]);
  const heights = useMemo(() => Object.fromEntries(view.nodes.map((n) => [n.id, measured[hkey(n.id)]]).filter(([, h]) => h !== undefined)), [view, measured, hkey]);
  const layout = useMemo(() => layoutView(view, { expanded, heights }), [view, expanded, heights]);

  // Saved positions: only dragged nodes, per project, region and direction. Ids are checked against today's graph
  // (and the "no grants" groups), so ids that left the project are dropped on load.
  const known = useMemo(() => new Set(base.nodes.map((n) => n.id)), [base]);
  const { pins, pin, unpin, reset } = usePositions(posKey(ctx.project, ctx.region, direction), (id) => known.has(id) || id.startsWith("group:"), true);
  const pinned = useMemo(() => new Set(Object.keys(pins)), [pins]);
  const flow = useMemo(() => toFlow(view, layout, { node: selected, edge: selEdge?.id ?? null, hit }, expanded, reduced, pinned), [view, layout, selected, selEdge, hit, expanded, reduced, pinned]);

  // Nodes are controlled so they can be dragged: a pinned node takes its saved place, the rest the auto layout.
  // Measured sizes are kept so nodes don't flash while React Flow re-measures.
  const [rfNodes, setRfNodes] = useState<MNode[]>([]);
  useEffect(() => {
    setRfNodes((prev) => {
      const old = new Map(prev.map((n) => [n.id, n]));
      return flow.nodes.map((n) => ({ ...n, measured: old.get(n.id)?.measured, position: pins[n.id] ?? n.position }));
    });
  }, [flow.nodes, pins]);
  const hkeyRef = useRef(hkey);
  hkeyRef.current = hkey;
  const measuredRef = useRef(measured);
  measuredRef.current = measured;
  const placedRef = useRef<Record<string, { x: number; y: number }>>({});
  // where each node sits before a drag (its pin, or the auto layout): a drop elsewhere pins it
  placedRef.current = Object.fromEntries(flow.nodes.map((n) => [n.id, pins[n.id] ?? n.position]));
  const onNodesChange = useCallback(
    (changes: NodeChange<MNode>[]) => {
      // Drops and arrow-key moves (dragging false) pin the node where it is; a click that didn't move it doesn't.
      for (const c of changes)
        if (c.type === "position" && c.position && c.dragging === false && !c.id.startsWith("hdr:")) {
          const was = placedRef.current[c.id];
          if (!was || Math.abs(was.x - c.position.x) > 0.5 || Math.abs(was.y - c.position.y) > 0.5) pin(c.id, c.position);
        }
      setRfNodes((ns) => applyNodeChanges(changes.filter((c) => c.type !== "remove"), ns));
      const upd: Record<string, number> = {};
      for (const c of changes) {
        if (c.type === "dimensions" && c.dimensions && !c.id.startsWith("hdr:")) {
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
  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const label = useCallback((id: string) => nodeById.get(id)?.label ?? id.split("/").pop() ?? id, [nodeById]);
  const nodeOf = useCallback((id: string) => nodeById.get(id), [nodeById]);
  const edgeNow = useMemo(() => (selEdge ? resolveEdge(view.edges, selEdge) : null), [selEdge, view]);
  /** Remember what had focus, so closing the panel can return there. */
  const remember = () => {
    const a = document.activeElement as HTMLElement | null;
    opener.current = a && a !== document.body ? a : null;
  };
  const selectNode = useCallback(
    (id: string) => {
      setSelected(id);
      setSelEdge(null);
      const n = nodeById.get(id);
      if (n) setAnnounce(`${n.label} selected: its details are in the panel after the map. Arrow keys move it; Escape clears.`);
    },
    [nodeById],
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
  const clear = useCallback(() => {
    setSelected(null);
    setSelEdge(null);
  }, []);
  const closePanel = () => {
    if (selEdge) {
      const id = selEdge.id;
      setSelEdge(null);
      returnFocus(id);
    } else if (selected) {
      const id = selected;
      clear();
      returnFocus(id);
    }
  };
  const changeDirection = (d: Direction) => {
    if (d === direction) return;
    setDirection(d);
    setFilters((f) => ({ ...f, gateway: "all", expanded: [], hidden: [] }));
    clear();
  };

  // ---------- search: center on the match and highlight it ----------
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
  const focusOn = (id: string) => {
    const inView = view.nodes.find((n) => n.id === id);
    if (!inView) {
      const grp = view.nodes.find((n) => n.grouped?.includes(id));
      if (!grp) return false;
      set({ expanded: [...filters.expanded, grp.section] });
    }
    if (table) setTable(false);
    setHit(id);
    pendingCenter.current = id;
    if (inView) center(id);
    return true;
  };
  const runSearch = () => {
    const q = query.trim().toLowerCase();
    setSearchMsg("");
    if (!q) return;
    const matches = graph.nodes.filter((n) => n.search.includes(q)).sort((a, b) => Number(!a.label.toLowerCase().startsWith(q)) - Number(!b.label.toLowerCase().startsWith(q)) || a.label.localeCompare(b.label));
    if (!matches.length) return setSearchMsg(`No match for “${query.trim()}”.`);
    const m = matches.find((x) => view.nodes.some((n) => n.id === x.id || n.grouped?.includes(x.id))) ?? matches[0];
    if (!focusOn(m.id)) setSearchMsg(`${m.label} is hidden by the filters.`);
    else setSearchMsg(matches.length > 1 ? `${m.label} (1 of ${matches.length} matches)` : m.label);
  };
  const jump = useCallback((id: string) => {
    // The same agent in the other column: Agent Runtime agents appear as callers and as registry entries.
    setSelected(id);
    setSelEdge(null);
    setHit(id);
    pendingCenter.current = id;
  }, []);
  const actions = useMemo(() => ({ jump, unpin }), [jump, unpin]);

  // ---------- "Show on map" from another step: direction, filters that show it, the node, then the line ----------
  useEffect(() => {
    if (!mapFocus) return;
    clearMapFocus();
    const f: MapFocus = { direction: mapFocus.direction, node: mapFocus.node, target: mapFocus.target };
    if (f.direction) setDirection(f.direction);
    setFilters((x) => ({ ...x, affiliation: "all", gateway: "all", types: DEFAULT_FILTERS.types, hidden: [], expanded: [] }));
    setTable(false);
    setSelected(f.node ?? f.target ?? null);
    setSelEdge(null);
    setFocusReq(f);
  }, [mapFocus, clearMapFocus]);
  useEffect(() => {
    if (!focusReq) return;
    const id = focusReq.target && !focusReq.node ? focusReq.target : focusReq.node;
    // a destination grouped under "+N with no grants" is shown first
    const grouped = [focusReq.node, focusReq.target].map((x) => x && view.nodes.find((n) => n.grouped?.includes(x))).find(Boolean);
    if (grouped) return set({ expanded: [...filters.expanded, grouped.section] });
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
  }, [focusReq, view]);

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
      if (n?.type === "group") return set({ expanded: [...filters.expanded, n.data.node.section] });
      if (n && n.type !== "section") selectNode(id);
      return;
    }
    if (e.key === "Escape" && (selected || selEdge)) {
      e.stopPropagation();
      closePanel();
    }
  };

  // ---------- toolbar data ----------
  const dirGws = gw.gateways.filter((g) => g.type === direction);
  const selNode = selected ? nodeById.get(selected) : undefined;
  const legend = LEGEND[direction].filter((v) => v !== "unchecked" || dirGws.some((g) => !g.enforcement?.mode));
  // Not refit when a group is expanded (a click, or a search that centers on its match).
  const fitKey = `${direction}|${filters.affiliation}|${filters.gateway}|${JSON.stringify(filters.types)}|${filters.hideEmpty}|${table}|${show === "changes"}`;
  const counts = {
    agents: view.nodes.filter((n) => n.kind === "engine").length,
    dests: view.nodes.filter((n) => n.column === "dests" && n.kind !== "endpoint_group" && n.kind !== "engine").length,
  };

  return (
    <MapActions.Provider value={actions}>
      <div className="pmap" onKeyDown={onKey}>
        <EdgeMarkers />
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
            <div className="seg" role="group" aria-label="Gateway affiliation">
              {AFFILIATION.map((a) => (
                <Tip key={a.id} tip={a.tip} placement="bottom">
                  <button type="button" className={`seg-btn ${filters.affiliation === a.id ? "on" : ""}`} aria-pressed={filters.affiliation === a.id} onClick={() => set({ affiliation: a.id })}>
                    {a.label}
                  </button>
                </Tip>
              ))}
            </div>
            {dirGws.length > 1 && (
              <select className="pmap-select" value={filters.gateway} onChange={(e) => set({ gateway: e.target.value })} disabled={filters.affiliation === "none"} aria-label="Gateway">
                <option value="all">All gateways</option>
                {dirGws.map((g) => (
                  <option key={g.name} value={g.name}>
                    {g.id}
                  </option>
                ))}
              </select>
            )}
            <form
              className="pmap-search"
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                runSearch();
              }}
            >
              <SearchIcon size={15} />
              <input type="search" value={query} placeholder="Find an agent, gateway or destination" aria-label="Search the map" onChange={(e) => setQuery(e.target.value)} />
            </form>
            <span className="pmap-tools-end">
              <Tip tip="Zoom to fit the whole map." placement="bottom">
                <button type="button" className="btn btn-tonal btn-small" onClick={() => void rf.fitView({ padding: PAD, duration: reduced ? 0 : 300, maxZoom: 1.15 })} disabled={table}>
                  <ExpandIcon size={14} /> Fit
                </button>
              </Tip>
              <Tip tip={pinned.size ? `Put the ${plural(pinned.size, "node")} you dragged back in their automatic place and forget the saved layout.` : "Nothing is pinned: drag a node to keep it where you drop it."} placement="bottom">
                <button type="button" className="btn btn-tonal btn-small" disabled={table || !pinned.size} onClick={reset}>
                  Reset layout
                </button>
              </Tip>
              <button type="button" className={`btn btn-small ${table ? "btn-primary" : "btn-tonal"}`} aria-pressed={table} onClick={() => setTable(!table)}>
                Table view
              </button>
            </span>
          </div>
          <div className="pmap-tools-row">
            {direction === "egress" && (
              <div className="pmap-types" role="group" aria-label="Destination types">
                {DEST_TYPES.map((t) => (
                  <label key={t.id} className={`pmap-check ${filters.types[t.id] ? "on" : ""}`}>
                    <input type="checkbox" checked={filters.types[t.id]} onChange={(e) => set({ types: { ...filters.types, [t.id]: e.target.checked } })} />
                    {t.label}
                  </label>
                ))}
                <label className="pmap-check plain">
                  <input type="checkbox" checked={filters.hideEmpty} onChange={(e) => set({ hideEmpty: e.target.checked, expanded: [] })} />
                  Hide destinations with no grants
                </label>
              </div>
            )}
            <div className="seg seg-small" role="group" aria-label="Show staged changes">
              {SHOW.map((o) => (
                <Tip key={o.id} tip={!cart.length && o.id !== "today" ? "The cart is empty: nothing is staged." : o.tip} placement="bottom">
                  <button type="button" className={`seg-btn ${show === o.id ? "on" : ""}`} aria-pressed={show === o.id} disabled={!cart.length && o.id !== "today"} onClick={() => setShowPref(o.id)}>
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
            {searchMsg && (
              <span className="small muted" role="status">
                {searchMsg}
              </span>
            )}
          </div>
          {selNode && (
            <div className="pmap-tools-row pmap-selbar">
              <span className="small">
                Selected: <b>{selNode.label}</b>
                {view.focus && selNode.kind === "engine" && <> · showing this agent's own lines</>}
              </span>
              {view.focus && selNode.kind === "engine" && (
                <>
                  <label className="pmap-check plain">
                    <input type="checkbox" checked={filters.inherited} onChange={(e) => set({ inherited: e.target.checked })} />
                    Inherited grants
                  </label>
                  {selNode.gateway && (
                    <label className="pmap-check plain">
                      <input type="checkbox" checked={filters.implicit} onChange={(e) => set({ implicit: e.target.checked })} />
                      Implicit denies
                    </label>
                  )}
                  {view.more > 0 && <span className="pmap-more">+{view.more} more default-deny lines not drawn</span>}
                </>
              )}
              <button type="button" className="btn btn-text btn-small" onClick={clear}>
                Clear
              </button>
            </div>
          )}
        </div>

        {direction === "ingress" && (
          <Callout tone="info" title="Client-to-Agent doesn't check who calls">
            The gateway screens content with Model Armor. Who may call an agent is decided by the agent's Agent Runtime IAM, which Policy Studio doesn't read, so callers are shown as “Any allowed caller”.
          </Callout>
        )}
        {view.lines > TOO_MANY && (
          <Callout tone="warn" title={`${view.lines} lines on the map`}>
            Narrow the filters (a gateway, fewer destination types, or one agent) to keep it readable.
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
              <ReactFlow
                nodes={rfNodes}
                edges={flow.edges}
                nodeTypes={nodeTypes}
                edgeTypes={edgeTypes}
                onNodesChange={onNodesChange}
                onNodeClick={(_, n) => {
                  if (n.type === "section") return;
                  if (n.type === "group") return set({ expanded: [...filters.expanded, n.data.node.section] });
                  remember();
                  selectNode(n.id);
                }}
                onNodeDoubleClick={clear}
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
                minZoom={0.2}
                maxZoom={2}
                zoomOnDoubleClick={false}
                onlyRenderVisibleElements
                colorMode="system"
                proOptions={{ hideAttribution: true }}
              >
                <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} className="diagram-bg" />
                <Controls showInteractive={false} position="bottom-right" />
                <Fitter fitKey={fitKey} wrap={wrap} />
              </ReactFlow>
            </div>
          )}
          {(edgeNow || selNode) && <PolicyPanel edge={edgeNow} node={edgeNow ? null : (selNode ?? null)} inv={inv} gateways={gw.gateways} nodeOf={nodeOf} label={label} onClose={closePanel} />}
          <div className="legend" role="group" aria-label="Legend: click to hide or show a kind of line">
            {legend.map((v) => {
              const off = filters.hidden.includes(v);
              return (
                <button
                  key={v}
                  type="button"
                  className={`legend-item ${off ? "off" : ""}`}
                  aria-pressed={!off}
                  title={off ? `Show “${VERDICT_LABEL[v]}” lines` : `Hide “${VERDICT_LABEL[v]}” lines`}
                  onClick={() => set({ hidden: off ? filters.hidden.filter((x) => x !== v) : [...filters.hidden, v] })}
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
            {direction === "egress" && (
              <span className="legend-item static">
                <svg width="30" height="10" className="legend-line" aria-hidden="true">
                  <line x1="1" y1="5" x2="29" y2="5" className="edge-path st-allowed inherited" />
                </svg>
                Inherited (selected agent)
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
          </div>
        </div>
        <p className="small muted pmap-foot" aria-live="polite">
          {counts.agents ? plural(counts.agents, "agent") : "No agents"} · {plural(counts.dests, "destination")} · {plural(view.lines, "line")}
          {direction === "egress" && graph.stats.unreadable ? ` · ${plural(graph.stats.unreadable, "IAP policy", "IAP policies")} couldn't be read` : ""}. Drag nodes (or select one and use the arrow keys) to move them: they keep
          their place; scroll or pinch to zoom.
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
