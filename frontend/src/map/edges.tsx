// Policy map lines, ported from the demo's diagram/edges.tsx (bezier path with a halo, arrowhead, badge ~80% along,
// particles). One line type, styled by verdict (VISUALIZATION_PLAN §5.2): dash patterns, the ✕ / "?" badges, the
// half-filled arrow for partial access and the Model Armor shield at the gateway end, so color is never the only cue.
// Staged changes (§8) add a clock badge and a word: a pending add is dashed (animated unless reduced motion), a pending
// remove keeps today's style under a red dashed overlay, a pending change is drawn as it will be.
import { BaseEdge, EdgeLabelRenderer, getBezierPath, type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import { ClockIcon, CloseIcon, ShieldIcon } from "../components/Icons";
import type { PEdge, Verdict } from "./graph";
import { PENDING_WORD, VERDICT_LABEL, viaText, type MEdge } from "./toFlow";
import { pendingText } from "./diff";

export { viaText };

/** Verdicts drawn with a plain arrowhead (blocked and would-deny lines have a ✕ instead; partial a half arrow). */
const ARROWS: Verdict[] = ["allowed", "conditional", "unchecked", "dormant", "direct", "screened", "unscreened", "path"];

/** Shared arrowhead markers, rendered once next to the canvas (one per verdict, not one per line). */
export function EdgeMarkers() {
  return (
    <svg className="pm-defs" width="0" height="0" aria-hidden="true" focusable="false">
      <defs>
        {ARROWS.map((v) => (
          <marker key={v} id={`pm-arrow-${v}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" className={`edge-arrow st-${v}`} />
          </marker>
        ))}
        {/* partial: the arrowhead's outline, filled only on one side */}
        <marker id="pm-arrow-partial" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
          <path d="M1,1 L11,6 L1,11 z" className="edge-arrow-outline st-partial" />
          <path d="M1,1 L11,6 L1,6 z" className="edge-arrow st-partial" />
        </marker>
      </defs>
    </svg>
  );
}

export function edgeTitle(e: PEdge): string {
  const via = viaText(e);
  return [
    VERDICT_LABEL[e.verdict],
    e.label && !/^\?$/.test(e.label) ? e.label : "",
    via ? `via ${via} grant` : "",
    e.mode === "DRY_RUN" && e.verdict !== "path" ? "gateway in dry run" : "",
    e.modelArmor ? (e.modelArmorDryRun ? "Model Armor screening (dry run)" : "Model Armor screening") : "",
    e.note ?? "",
    e.pending ? `Staged: ${PENDING_WORD[e.pending]}. ${pendingText(e)}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
}

function PolicyEdgeImpl({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps<MEdge>) {
  const e = data!.edge;
  const v = e.verdict;
  const [path] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, curvature: 0.35 });
  // Points along an approximation of the bezier: badges ~78% along (so converging lines don't stack them), the
  // Model Armor shield just after the gateway.
  const mx = (sourceX + targetX) / 2;
  const bz = (t: number, a: number, b: number, c: number, d: number) => (1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t ** 2 * c + t ** 3 * d;
  const at = (t: number) => [bz(t, sourceX, mx, mx, targetX), bz(t, sourceY, sourceY, targetY, targetY)] as const;
  const [bx, by] = at(0.78);
  const [sx, sy] = at(Math.min(0.3, 30 / Math.max(1, Math.hypot(targetX - sourceX, targetY - sourceY))));
  const marker = v === "partial" ? "url(#pm-arrow-partial)" : v === "blocked" || v === "would_deny" ? undefined : `url(#pm-arrow-${v})`;
  const via = viaText(e);
  const text = [e.pending ? `staged: ${PENDING_WORD[e.pending]}` : "", e.label && e.label !== "?" ? e.label : "", via ?? ""].filter(Boolean).join(" · ");
  const badge =
    v === "blocked" ? (
      <span className="edge-badge badge-denied">
        <CloseIcon size={13} />
      </span>
    ) : v === "would_deny" ? (
      <span className="edge-badge badge-would-deny">
        <CloseIcon size={12} />
      </span>
    ) : v === "conditional" ? (
      <span className="edge-badge badge-conditional">?</span>
    ) : null;
  const title = edgeTitle(e);
  return (
    <>
      <path d={path} className="edge-halo" />
      <BaseEdge
        id={id}
        path={path}
        className={`edge-path st-${v} ${e.inherited ? "inherited" : ""} ${e.pending === "add" ? `pending-add${data!.reducedMotion ? " still" : ""}` : ""}`}
        markerEnd={marker}
        interactionWidth={18}
      />
      {e.pending === "remove" && <path d={path} className="edge-pending-remove" fill="none" />}
      <path d={path} className="edge-hit" fill="none">
        <title>{title}</title>
      </path>
      {e.modelArmor && v !== "path" && (
        <g transform={`translate(${sx - 6.5}, ${sy - 6.5})`} className={`edge-shield ${e.modelArmorDryRun ? "outlined" : ""}`}>
          <title>{e.modelArmorDryRun ? "Model Armor screens this line (dry run: not blocking)" : "Model Armor screens this line"}</title>
          <circle cx="6.5" cy="6.5" r="6.5" />
          <ShieldIcon size={9} x={2} y={2} />
        </g>
      )}
      {data!.animate && (
        <g className={`edge-particles st-${v}`}>
          {[0, 0.4, 0.8].map((d) => (
            <circle key={d} r={d === 0 ? 5 : 3.5} className="edge-particle">
              <animateMotion dur="1.2s" begin={`${d}s`} repeatCount="indefinite" path={path} />
            </circle>
          ))}
        </g>
      )}
      {(badge || text || e.pending) && (
        <EdgeLabelRenderer>
          <div className={`edge-badge-wrap ${data!.dim ? "dim" : ""}`} style={{ transform: `translate(-50%, -50%) translate(${bx}px, ${by}px)` }} title={title}>
            {e.pending && (
              <span className={`edge-badge badge-pending pending-${e.pending}`}>
                <ClockIcon size={12} />
              </span>
            )}
            {badge}
            {text && <span className={`edge-label st-${v}`}>{text}</span>}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const edgeTypes = { policy: memo(PolicyEdgeImpl) };
