// The map as a table (VISUALIZATION_PLAN §10): the visible lines, one row per agent of a combined line. Built from the
// same MapView as the canvas, so the filters apply; also the screen-reader alternative to the canvas.
import { useMemo, useState } from "react";
import { NOGW, type PEdge, type PNode } from "./graph";
import { PENDING_WORD, VERDICT_LABEL, VIA_LABEL, viaText } from "./toFlow";
import { tableRows, type MapView } from "./view";

type Key = "caller" | "gateway" | "dest" | "verdict" | "via" | "condition" | "pending";
const COLS: { key: Key; label: string }[] = [
  { key: "caller", label: "Caller" },
  { key: "gateway", label: "Gateway" },
  { key: "dest", label: "Destination" },
  { key: "verdict", label: "Verdict" },
  { key: "via", label: "Via" },
  { key: "condition", label: "Condition" },
  { key: "pending", label: "Staged" },
];

/** A row of a combined line: the agent's own part, with the combined line's pending mark when it has none. */
export function rowCells(e: PEdge, label: (id: string) => string, line?: PEdge): Record<Key, string> {
  const ingress = e.direction === "ingress";
  // A pseudo caller (project-wide, public, other principals) isn't behind one gateway: each agent's own is used.
  const pseudo = e.source.startsWith("pseudo:");
  const conds = [...new Set(e.reasons.map((r) => r.binding.condition?.title || (r.binding.condition ? "Custom condition" : "None (full access)")))];
  return {
    caller: ingress ? (e.caller ? "Clients" : label(e.source)) : label(e.caller ?? e.source),
    gateway: e.gateway ? label(e.gateway) : pseudo ? "Each agent's own" : ingress && !e.caller ? label(e.target) : "No gateway",
    dest: ingress && !e.caller ? "(all agents behind it)" : e.target === NOGW.egress ? "Anywhere" : label(e.target),
    verdict: VERDICT_LABEL[e.verdict] + (e.label && e.label !== "?" && !e.parts ? ` (${e.label})` : ""),
    via: e.implicit ? "No grant" : pseudo ? [...new Set(e.reasons.map((r) => VIA_LABEL[r.via] ?? r.via))].join(", ") : (viaText(e) ?? (e.reasons.length ? "Direct grant" : "")),
    condition: e.implicit ? "" : conds.join("; "),
    pending: (e.pending ?? line?.pending) ? `Will ${PENDING_WORD[(e.pending ?? line!.pending)!].replace(/^will /, "")}` : "",
  };
}

export default function MapTable({ view, nodes, selected, onSelect }: { view: MapView; nodes: PNode[]; selected: string | null; onSelect: (e: PEdge) => void }) {
  const [sort, setSort] = useState<{ key: Key; dir: 1 | -1 }>({ key: "caller", dir: 1 });
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  // endpoint labels are the map's (labels.ts: the host when the display name only repeats it), shown in full here
  const label = useMemo(() => (id: string) => byId.get(id)?.label ?? id.split("/").pop() ?? id, [byId]);
  const rows = useMemo(() => {
    // a row's combined line (for its pending mark): through the Google APIs group's merged lines too
    const lineOf = new Map(view.edges.flatMap((l) => l.members ?? [l]).flatMap((l) => (l.parts ?? []).map((p) => [p.id, l] as const)));
    const rs = tableRows(view).map((e, i) => ({ e, i, c: rowCells(e, label, lineOf.get(e.id)) }));
    return rs.sort((a, b) => sort.dir * a.c[sort.key].localeCompare(b.c[sort.key]) || a.c.dest.localeCompare(b.c.dest) || a.i - b.i);
  }, [view, label, sort]);
  return (
    <div className="pmap-table-wrap">
      <table className="grants-table pmap-table">
        <caption className="sr-only">Lines on the policy map ({rows.length})</caption>
        <thead>
          <tr>
            {COLS.map((c) => (
              <th key={c.key} aria-sort={sort.key === c.key ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
                <button type="button" className="th-sort" onClick={() => setSort((s) => ({ key: c.key, dir: s.key === c.key ? (-s.dir as 1 | -1) : 1 }))}>
                  {c.label}
                  {sort.key === c.key && <span aria-hidden="true">{sort.dir === 1 ? " ▲" : " ▼"}</span>}
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map(({ e, c }) => (
            // a staged bind can show the same agent's line twice (removed from one lane, added on another)
            <tr key={`${e.id}|${e.caller ?? ""}|${e.source}`} className={selected === e.id ? "sel" : ""} onClick={() => onSelect(e)}>
              <td>
                <button type="button" className="link-btn" onClick={(ev) => (ev.stopPropagation(), onSelect(e))}>
                  {c.caller}
                </button>
              </td>
              <td>{c.gateway}</td>
              <td>
                {(() => {
                  const d = byId.get(e.target);
                  return (
                    <span title={d?.kind === "endpoint" ? [d.displayName, d.url].filter(Boolean).join("\n") : undefined}>
                      {c.dest}
                      {d?.googleApi && <span className="chip chip-neutral pmap-tag">Google API</span>}
                    </span>
                  );
                })()}
              </td>
              <td>
                <span className={`pmap-verdict st-${e.verdict}`}>{c.verdict}</span>
              </td>
              <td>{c.via}</td>
              <td className="small">{c.condition}</td>
              <td className="small">{c.pending}</td>
            </tr>
          ))}
          {!rows.length && (
            <tr>
              <td colSpan={COLS.length} className="muted">
                No lines with these filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
