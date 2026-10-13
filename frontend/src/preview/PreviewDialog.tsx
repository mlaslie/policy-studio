// The Build step's Add to cart preview (lazy-loaded with React Flow, like the map step; preview/flow.ts has the
// transitions): a small read-only map of the one change (the source agent, its gateway or the no-gateway lane, and the
// destination; MCP tool rows today → after), the change list (per tool, or the destination, today and after with the
// grants behind each), the bindings it replaces or removes and the one it adds, and the warnings. Approve / Modify /
// Cancel; Esc, the close button and a click outside are Modify (nothing is lost). A modal dialog: aria-modal, a
// labelled title, focus kept inside, focus back to the opener on close.
import "@xyflow/react/dist/style.css";
import { Handle, Position, ReactFlow, ReactFlowProvider, type NodeProps } from "@xyflow/react";
import { memo, useEffect, useId, useMemo, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { Intent } from "../api/types";
import { useStudio } from "../store";
import { CheckIcon, CloseIcon, CloudIcon, PencilIcon, ServerIcon, WarnIcon } from "../components/Icons";
import { ToolKindIcon, ToolStateLabel } from "../components/ToolMarks";
import { Badge } from "../components/ui";
import { accessFromCondition, accessWords, conditionFor } from "../lib/policy";
import { buildPolicyGraph } from "../map/graph";
import { simulate } from "../map/simulate";
import { diffGraphs, mergeStaged } from "../map/diff";
import { layoutView, toolLabelW, toolRoom } from "../map/layout";
import { toFlow, type MNode } from "../map/toFlow";
import { ToolName, nodeTypes } from "../map/nodes";
import { EdgeMarkers, edgeTypes } from "../map/edges";
import { previewGraph } from "./graph";
import { previewModel, type ChangeRow, type PreviewModel, type ToolState } from "./changes";
import { TOOL_STATE_TEXT, TOOL_STATE_WORDS, toolRowLabel } from "../lib/toolMarks";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

const STATE_LABEL: Record<ToolState, string> = { allowed: "Allowed", denied: "Denied", unknown: "Can't tell" };

/** An MCP server card for the preview: each tool today → after (the map's card shows one state). */
const PreviewMcpNode = memo(({ data }: NodeProps<MNode>) => {
  const n = data.node;
  const rows = (data.previewRows as ChangeRow[] | undefined) ?? [];
  return (
    <div className="node node-mcp pv-mcp" style={{ width: 290 }}>
      <Handle type="target" position={Position.Left} id="in" isConnectable={false} className="hnd" />
      <Handle type="source" position={Position.Right} id="out" isConnectable={false} className="hnd" />
      <div className="node-badge badge-cloudrun">
        <CloudIcon size={12} /> MCP
      </div>
      <div className="node-head">
        <span className="node-icon icon-mcp">
          <ServerIcon size={20} />
        </span>
        <div className="node-titles">
          <div className="node-title" title={n.label}>
            {n.label}
          </div>
          <div className="node-sub mono" title={n.sub}>
            {n.sub}
          </div>
        </div>
      </div>
      <div className="tools" role="list">
        {rows.map((r) => {
          const label = `${toolRowLabel(r.name, { readOnly: !!r.readOnly })}, today ${TOOL_STATE_WORDS[r.today]}, after ${TOOL_STATE_WORDS[r.after]}`;
          const end = [toolLabelW(TOOL_STATE_TEXT[r.today]), toolLabelW("→"), toolLabelW(TOOL_STATE_TEXT[r.after])];
          return (
            <div key={r.name} role="listitem" className={`tool-row st-${r.after} ${r.change !== "same" ? "pv-changed" : ""}`} aria-label={label} title={label}>
              <ToolKindIcon readOnly={!!r.readOnly} />
              <ToolName name={r.name} room={toolRoom(end) + 4} title={label} />
              <span className="pv-states" aria-hidden="true">
                <ToolStateLabel st={r.today} />
                <span className="pv-arrow">→</span>
                <ToolStateLabel st={r.after} />
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
});
const previewNodeTypes = { ...nodeTypes, previewMcp: PreviewMcpNode };

function PreviewMap({ intent, model }: { intent: Intent; model: PreviewModel }) {
  const { inventory, gateways, modelArmor, ctxInfo, ctx } = useStudio();
  const inv = inventory.data!;
  const gws = gateways.data?.gateways ?? [];
  const flow = useMemo(() => {
    const input = { context: ctxInfo.data, ctx, direction: "egress" as const, inherited: true };
    const base = buildPolicyGraph({ inventory: inv, gateways: gws, modelArmor: modelArmor.data, ...input });
    const sim = simulate({ inventory: inv, gateways: gws, modelArmor: modelArmor.data }, [intent]);
    const after = buildPolicyGraph({ inventory: sim.inventory, gateways: sim.gateways, modelArmor: sim.modelArmor, ...input });
    const merged = mergeStaged(base, after, diffGraphs(base, after), [intent], inv, sim.effects);
    const { view, dest } = previewGraph(merged, intent, inv.project_agents_principal ?? null);
    const expanded = new Set(view.nodes.filter((n) => n.kind === "mcp").map((n) => n.id));
    const layout = layoutView(view, { expanded });
    const f = toFlow(view, layout, { node: null, edge: null, hit: null }, expanded, true);
    const nodes = f.nodes.map((n): MNode => ({ ...n, draggable: false, selectable: false, ...(n.id === dest && n.type === "mcp" ? { type: "previewMcp", data: { ...n.data, previewRows: model.rows } } : {}) }));
    return { nodes, edges: f.edges.map((e) => ({ ...e, selectable: false, focusable: false })) };
  }, [inv, gws, modelArmor.data, ctxInfo.data, ctx, intent, model]);
  return (
    <div className="pmap pv-map" role="img" aria-label={`Map of the change: ${model.sentence}`}>
      <EdgeMarkers />
      <div className="pv-canvas">
        <ReactFlowProvider>
          <ReactFlow
            nodes={flow.nodes}
            edges={flow.edges}
            nodeTypes={previewNodeTypes}
            edgeTypes={edgeTypes}
            nodesDraggable={false}
            nodesConnectable={false}
            nodesFocusable={false}
            edgesFocusable={false}
            elementsSelectable={false}
            panOnDrag={false}
            zoomOnScroll={false}
            zoomOnPinch={false}
            zoomOnDoubleClick={false}
            preventScrolling={false}
            fitView
            fitViewOptions={{ padding: 0.08, maxZoom: 1 }}
            minZoom={0.2}
            colorMode="system"
            proOptions={{ hideAttribution: true }}
          />
        </ReactFlowProvider>
      </div>
    </div>
  );
}

function State({ s, by }: { s: ToolState; by: string[] }) {
  return (
    <span className="pv-state">
      <span className={`badge tool-state-badge ts-${s}`}>{STATE_LABEL[s]}</span>
      {by.length > 0 && <span className="muted tiny"> by {by.join(" + ")}</span>}
    </span>
  );
}

function Cond({ c }: { c: { title?: string; expression?: string } | null | undefined }) {
  if (!c?.expression) return <span className="muted small">no condition (everything)</span>;
  return (
    <span className="pv-cond">
      {c.title && <span className="small">“{c.title}” </span>}
      <span className="mono tiny pv-expr">{c.expression}</span>
    </span>
  );
}

export interface PreviewDialogProps {
  intent: Intent;
  extras: number;
  approveLabel: string;
  onApprove: () => void;
  onModify: () => void;
  onCancel: () => void;
}

export default function PreviewDialog({ intent, extras, approveLabel, onApprove, onModify, onCancel }: PreviewDialogProps) {
  const { inventory, cart } = useStudio();
  const inv = inventory.data!;
  const panel = useRef<HTMLDivElement>(null);
  const first = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const descId = useId();
  const engine = intent.source?.engine ? inv.engines.find((e) => e.name === intent.source!.engine) : undefined;
  const model = useMemo(() => previewModel({ intent, inv, engine, cart }), [intent, inv, engine, cart]);
  const mcp = intent.destination?.kind === "mcp_server";
  const removing = model.kind === "revoke" || model.kind === "remove_all";
  const modifyRef = useRef(onModify);
  modifyRef.current = onModify;

  // Focus inside on open (Approve, or Modify when access is removed), kept inside (Tab wraps), back to the opener on
  // close; Esc = Modify.
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    first.current?.focus({ preventScroll: true });
    // the first open loads this chunk behind a Suspense fallback: make sure focus lands inside once it's painted
    const raf = requestAnimationFrame(() => {
      if (!panel.current?.contains(document.activeElement)) first.current?.focus({ preventScroll: true });
    });
    const onKey = (e: KeyboardEvent) => {
      const el = panel.current;
      if (!el) return;
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        modifyRef.current();
        return;
      }
      if (e.key !== "Tab") return;
      const items = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null);
      if (!items.length) return;
      const a = items[0];
      const z = items[items.length - 1];
      const active = document.activeElement;
      if (!el.contains(active)) {
        e.preventDefault();
        a.focus();
      } else if (e.shiftKey && (active === a || active === el)) {
        e.preventDefault();
        z.focus();
      } else if (!e.shiftKey && active === z) {
        e.preventDefault();
        a.focus();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("keydown", onKey, true);
      if (prev && document.contains(prev)) prev.focus({ preventScroll: true });
    };
  }, []);

  const added = model.added[0];
  const addedAccess = added ? accessFromCondition(added.binding.condition?.expression) : undefined;
  const section = (title: string, body: ReactNode) => (
    <section className="pv-section">
      <h3 className="pv-h">{title}</h3>
      {body}
    </section>
  );

  return createPortal(
    <div className="glass-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onModify()}>
      <div ref={panel} className="glass glass-sheet pv-sheet" role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descId} tabIndex={-1}>
        <div className="sheet-head">
          <div className="sheet-titles">
            <h2 id={titleId}>{model.title}</h2>
            <div className="sheet-sub" id={descId}>
              {model.sentence} Nothing changes in Google Cloud until you apply.
            </div>
          </div>
          <div className="sheet-actions">
            <button className="glass-btn" onClick={onModify} aria-label="Close and go back to the builder (Modify)" title="Back to the builder (Esc)">
              <CloseIcon size={16} />
            </button>
          </div>
        </div>
        <div className="sheet-body pv-body">
          <PreviewMap intent={intent} model={model} />
          {model.warnings.length > 0 && (
            <div className="checks pv-warnings" role="list" aria-label="Warnings">
              {model.warnings.map((w) => (
                <div key={w.id} role="listitem" className={`check-chip chip-${w.tone}`}>
                  <WarnIcon size={14} />
                  <span className="grow">{w.text}</span>
                </div>
              ))}
            </div>
          )}
          {section(
            "What changes",
            <table className="pv-table">
              <caption className="sr-only">Each {mcp ? "tool" : "destination"} today and after this change</caption>
              <thead>
                <tr>
                  <th scope="col">{mcp ? "Tool" : "Destination"}</th>
                  <th scope="col">Today</th>
                  <th scope="col">After</th>
                </tr>
              </thead>
              <tbody>
                {model.rows.map((r) => (
                  <tr key={r.name} className={`pv-row pv-${r.change}`}>
                    <th scope="row" className="mono small">
                      {r.name}
                      {r.change !== "same" && <span className="sr-only"> (changes)</span>}
                    </th>
                    <td>
                      <State s={r.today} by={r.todayBy} />
                    </td>
                    <td>
                      <State s={r.after} by={r.afterBy} />
                      {r.change === "added" && <span className="pv-delta add"> added</span>}
                      {r.change === "removed" && <span className="pv-delta remove"> removed</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>,
          )}
          {section(
            "Bindings",
            <ul className="pv-bindings">
              {model.removed.map((l) => (
                <li key={`r-${l.binding.condition?.expression ?? ""}`} className="pv-binding remove">
                  <Badge tone="red">{removing ? "Removed" : "Replaced"}</Badge> <span className="small">{l.text}</span>
                  <div>
                    <Cond c={l.binding.condition} />
                  </div>
                </li>
              ))}
              {added && (
                <li className="pv-binding add">
                  <Badge tone="green">{model.kind === "grant" ? "New" : "New (replaces the above)"}</Badge> <span className="small">{accessWords(addedAccess)}</span>
                  <div>
                    <Cond c={conditionFor(addedAccess) ?? added.binding.condition} />
                  </div>
                </li>
              )}
              {!added && !model.removed.length && <li className="muted small">No binding changes.</li>}
              <li className="muted tiny">
                {model.removed.length + (added ? 1 : 0) > 1 ? "One read-modify-write: a single setIamPolicy with the etag, so there's no moment with partial access." : "A single setIamPolicy with the etag."}
              </li>
            </ul>,
          )}
        </div>
        <div className="pv-foot">
          <button className="btn btn-text" onClick={onCancel}>
            Cancel
          </button>
          <span className="grow muted small">Cancel discards this change and resets “How much of it?”; Modify (Esc) goes back with your choices.</span>
          <button className="btn btn-tonal" onClick={onModify} ref={removing ? first : undefined}>
            <PencilIcon size={14} /> Modify
          </button>
          <button className={`btn ${removing ? "btn-danger" : "btn-primary"}`} onClick={onApprove} ref={removing ? undefined : first}>
            <CheckIcon size={14} /> {approveLabel}
            {extras > 0 && ` (+${extras} fix)`}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
