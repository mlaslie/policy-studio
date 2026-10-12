// Policy map step (lazy-loaded chunk with React Flow): who can reach what, and why, drawn from the policy state Policy
// Studio already reads (docs/VISUALIZATION_PLAN.md). Phases 1–2: the read-only canvas (zoom, pan, drag), the toolbar
// filters, the selected-agent view, the legend as a verdict filter, the table view and Client-to-Agent basics. The
// policy panel and its actions (revoke, change access, allow), staged changes and saved positions come later; a click
// on a line shows a read-only summary.
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
import { CloseIcon, ExpandIcon, SearchIcon, ShieldIcon } from "../components/Icons";
import { useStudio } from "../store";
import { plural } from "../lib/util";
import { buildPolicyGraph, type Direction, type PEdge, type PNode, type Verdict } from "./graph";
import { DEFAULT_DIRECTION, DEFAULT_FILTERS, type Affiliation, type DestType, type MapFilters, viewOf } from "./view";
import { layoutView } from "./layout";
import { VERDICT_LABEL, expandedMcp, toFlow, type MNode } from "./toFlow";
import { nodeTypes, MapActions } from "./nodes";
import { EdgeMarkers, edgeTitle, edgeTypes, viaText } from "./edges";
import MapTable from "./MapTable";

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

function PolicyMap({ inv, gw }: { inv: Inventory; gw: GatewaysResp }) {
  const { modelArmor, ctxInfo, ctx } = useStudio();
  const rf = useReactFlow();
  const [direction, setDirection] = useState<Direction>(DEFAULT_DIRECTION);
  const [filters, setFilters] = useState<MapFilters>(DEFAULT_FILTERS);
  const [selected, setSelected] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<PEdge | null>(null);
  const [table, setTable] = useState(false);
  const [query, setQuery] = useState("");
  const [hit, setHit] = useState<string | null>(null);
  const [searchMsg, setSearchMsg] = useState("");
  const [measured, setMeasured] = useState<Record<string, number>>({});
  const [moved, setMoved] = useState(0);
  const dragged = useRef<Record<string, { x: number; y: number }>>({});
  const wrap = useRef<HTMLDivElement>(null);
  const reduced = usePrefersReducedMotion();
  const set = (p: Partial<MapFilters>) => setFilters((f) => ({ ...f, ...p }));

  // ---------- graph → view → layout → React Flow ----------
  const focusEngine = direction === "egress" && selected && inv.engines.some((e) => e.name === selected) ? selected : null;
  const graph = useMemo(
    () => buildPolicyGraph({ inventory: inv, gateways: gw.gateways, modelArmor: modelArmor.data, context: ctxInfo.data, ctx, direction, focus: focusEngine, inherited: filters.inherited }),
    [inv, gw, modelArmor.data, ctxInfo.data, ctx, direction, focusEngine, filters.inherited],
  );
  const view = useMemo(() => viewOf(graph, filters, selected), [graph, filters, selected]);
  const expanded = useMemo(() => expandedMcp(view, selected), [view, selected]);
  const hkey = useCallback((id: string) => `${id}|${expanded.has(id) ? 1 : 0}`, [expanded]);
  const heights = useMemo(() => Object.fromEntries(view.nodes.map((n) => [n.id, measured[hkey(n.id)]]).filter(([, h]) => h !== undefined)), [view, measured, hkey]);
  const layout = useMemo(() => layoutView(view, { expanded, heights }), [view, expanded, heights]);
  const flow = useMemo(() => toFlow(view, layout, { node: selected, edge: selEdge?.id ?? null, hit }, expanded, reduced), [view, layout, selected, selEdge, hit, expanded, reduced]);

  // Nodes are controlled so they can be dragged; a dragged node keeps its place until Reset layout or a direction
  // change (saving positions is phase 4). Measured sizes are kept so nodes don't flash while React Flow re-measures.
  const [rfNodes, setRfNodes] = useState<MNode[]>([]);
  useEffect(() => {
    setRfNodes((prev) => {
      const old = new Map(prev.map((n) => [n.id, n]));
      return flow.nodes.map((n) => ({ ...n, measured: old.get(n.id)?.measured, position: dragged.current[n.id] ?? n.position }));
    });
  }, [flow.nodes, moved]);
  const hkeyRef = useRef(hkey);
  hkeyRef.current = hkey;
  const measuredRef = useRef(measured);
  measuredRef.current = measured;
  const onNodesChange = useCallback((changes: NodeChange<MNode>[]) => {
    setRfNodes((ns) => applyNodeChanges(changes, ns));
    const upd: Record<string, number> = {};
    for (const c of changes) {
      if (c.type === "dimensions" && c.dimensions && !c.id.startsWith("hdr:")) {
        const k = hkeyRef.current(c.id);
        if (Math.abs((measuredRef.current[k] ?? -99) - c.dimensions.height) > 1) upd[k] = Math.round(c.dimensions.height);
      }
      if (c.type === "position" && c.position) dragged.current[c.id] = c.position;
    }
    if (Object.keys(upd).length) setMeasured((m) => ({ ...m, ...upd }));
  }, []);

  // ---------- selection ----------
  const clear = useCallback(() => {
    setSelected(null);
    setSelEdge(null);
  }, []);
  const changeDirection = (d: Direction) => {
    if (d === direction) return;
    setDirection(d);
    setFilters((f) => ({ ...f, gateway: "all", expanded: [], hidden: [] }));
    clear();
    dragged.current = {};
  };
  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const label = useCallback((id: string) => nodeById.get(id)?.label ?? id.split("/").pop() ?? id, [nodeById]);

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
  const actions = useMemo(() => ({ jump }), [jump]);

  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key === "Escape" && (selected || selEdge)) {
      e.stopPropagation();
      clear();
    }
  };

  // ---------- toolbar data ----------
  const dirGws = gw.gateways.filter((g) => g.type === direction);
  const selNode = selected ? nodeById.get(selected) : undefined;
  const legend = LEGEND[direction].filter((v) => v !== "unchecked" || dirGws.some((g) => !g.enforcement?.mode));
  // Not refit when a group is expanded (a click, or a search that centers on its match).
  const fitKey = `${direction}|${filters.affiliation}|${filters.gateway}|${JSON.stringify(filters.types)}|${filters.hideEmpty}|${table}`;
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
                <button type="button" className="btn btn-tonal btn-small" onClick={() => void rf.fitView({ padding: PAD, duration: 300, maxZoom: 1.15 })} disabled={table}>
                  <ExpandIcon size={14} /> Fit
                </button>
              </Tip>
              <Tip tip="Put dragged nodes back in their automatic place." placement="bottom">
                <button
                  type="button"
                  className="btn btn-tonal btn-small"
                  disabled={table}
                  onClick={() => {
                    dragged.current = {};
                    setMoved((m) => m + 1);
                  }}
                >
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
            <Tip tip="Before / after with the cart's staged changes: coming in the next phase." placement="bottom">
              <label className="pmap-check plain disabled">
                <input type="checkbox" disabled checked={false} readOnly />
                Show staged changes
              </label>
            </Tip>
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
            <MapTable view={view} nodes={graph.nodes} selected={selEdge?.id ?? null} onSelect={(e) => setSelEdge(e)} />
          ) : (
            <div className="pmap-canvas" ref={wrap}>
              <ReactFlow
                nodes={rfNodes}
                edges={flow.edges}
                nodeTypes={nodeTypes}
                edgeTypes={edgeTypes}
                onNodesChange={onNodesChange}
                onNodeClick={(_, n) => {
                  if (n.type === "section") return;
                  if (n.type === "group") return set({ expanded: [...filters.expanded, n.data.node.section] });
                  setSelected(n.id);
                  setSelEdge(null);
                }}
                onNodeDoubleClick={clear}
                onEdgeClick={(_, e) => setSelEdge(e.data?.edge ?? null)}
                onPaneClick={() => setSelEdge(null)}
                nodesConnectable={false}
                nodesDraggable
                nodesFocusable
                edgesFocusable
                elementsSelectable
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
          {(selEdge || selNode) && <DetailsStub edge={selEdge} node={selEdge ? undefined : selNode} label={label} onClose={selEdge ? () => setSelEdge(null) : clear} />}
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
          </div>
        </div>
        <p className="small muted pmap-foot" aria-live="polite">
          {counts.agents ? plural(counts.agents, "agent") : "No agents"} · {plural(counts.dests, "destination")} · {plural(view.lines, "line")}
          {direction === "egress" && graph.stats.unreadable ? ` · ${plural(graph.stats.unreadable, "IAP policy", "IAP policies")} couldn't be read` : ""}. Drag nodes to move them; scroll or pinch to zoom.
        </p>
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

/** Read-only details of a clicked line or node. The full policy panel with its actions is phase 3. */
function DetailsStub({ edge, node, label, onClose }: { edge: PEdge | null; node?: PNode; label: (id: string) => string; onClose: () => void }) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => ref.current?.focus({ preventScroll: true }), [edge, node]);
  const parts = edge?.parts ?? (edge ? [edge] : []);
  return (
    <aside className="pmap-panel glass" ref={ref} tabIndex={-1} aria-label="Details">
      <div className="pmap-panel-head">
        <div className="grow">
          {edge ? (
            <>
              <div className="small muted">{edge.direction === "egress" ? "Line" : "Client-to-Agent line"}</div>
              <h3>
                {label(edge.caller && edge.caller !== edge.target ? edge.caller : edge.source)} → {label(edge.target)}
              </h3>
            </>
          ) : (
            node && (
              <>
                <div className="small muted">Selected</div>
                <h3>{node.label}</h3>
              </>
            )
          )}
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close details">
          <CloseIcon size={16} />
        </button>
      </div>
      {edge && (
        <>
          <p>
            <span className={`pmap-verdict st-${edge.verdict}`}>{VERDICT_LABEL[edge.verdict]}</span>
          </p>
          <p className="small muted">{edgeTitle(edge)}</p>
          {edge.gateway && (
            <p className="small">
              Gateway <b>{label(edge.gateway)}</b>
              {edge.mode === "DRY_RUN" ? " · dry run: nothing is blocked" : edge.mode === "ENFORCE" ? " · enforcing" : edge.direction === "egress" ? " · no IAP policy" : ""}
            </p>
          )}
          {edge.implicit && (
            <p className="small">
              No grant names this agent on {label(edge.target)}, so the gateway denies it by default{edge.mode === "DRY_RUN" ? " (once it enforces; in dry run the call passes and is logged)" : ""}.
            </p>
          )}
          {edge.direction === "ingress" && <p className="small">There's no allow policy to show: a Client-to-Agent gateway screens content, it doesn't check who calls.</p>}
          {parts.length > 1 && <div className="small muted">{plural(parts.length, "agent")} on this line:</div>}
          <ul className="pmap-reasons">
            {parts.flatMap((p) =>
              p.reasons.map((r, i) => (
                <li key={`${p.caller}|${i}|${r.binding.member}`}>
                  {parts.length > 1 && <div className="small muted">{label(p.caller ?? p.source)}</div>}
                  <div>{r.binding.english || `${r.binding.member_label} holds ${r.binding.role}`}</div>
                  <div className="tiny muted">
                    {r.binding.member_label || r.binding.member} · {r.resourceKind === "registry" ? "registry-wide" : r.resourceLabel} ·{" "}
                    {r.binding.condition ? `condition: ${r.binding.condition.title || "custom"}` : "no condition"}
                    {p.inherited && viaText(p) ? ` · via ${viaText(p)} grant` : ""}
                  </div>
                  {p.tools && (
                    <div className="tiny">
                      Tools: {p.tools.allowed.length} allowed
                      {p.tools.denied.length ? `, ${p.tools.denied.length} denied` : ""}
                      {p.tools.unknown.length ? `, ${p.tools.unknown.length} can't be told here` : ""}
                    </div>
                  )}
                </li>
              )),
            )}
          </ul>
        </>
      )}
      {!edge && node && (
        <div className="small">
          <p className="muted">{node.sub}</p>
          {node.kind === "engine" && (
            <p>
              {node.gateway ? (
                <>
                  Behind <b>{label(node.gateway)}</b>.
                </>
              ) : (
                <>No gateway: {node.bindable ? "it can be bound to one." : (node.bindableReason ?? "it can't be bound.")}</>
              )}
              {node.identityType ? ` Identity: ${node.identityType === "AGENT_IDENTITY" ? "Agent Identity" : "service account"}.` : ""}
            </p>
          )}
          {node.unreadable && <p className="warn-text">IAP policy couldn't be read: {node.unreadable}</p>}
          {node.members?.length ? (
            <ul className="plain-list">
              {node.members.map((m) => (
                <li key={m.member}>{m.label}</li>
              ))}
            </ul>
          ) : null}
          {node.chips.length > 0 && <p className="muted">{node.chips.map((c) => c.text).join(" · ")}</p>}
        </div>
      )}
      <p className="tiny muted pmap-panel-foot">Read-only. Policy details and actions (revoke, change access, allow) come in the next phase.</p>
    </aside>
  );
}
