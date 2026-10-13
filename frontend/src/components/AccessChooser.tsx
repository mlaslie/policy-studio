// "How much of it?": the access choice for a grant (pulled out of the builder so the policy map's panel uses the same
// one for Change access and Allow…). MCP servers: read-only by hint, specific tools (checklist), all tools, or a
// custom CEL condition with lint hints. A2A agents and APIs are all-or-nothing.
import type { ReactNode } from "react";
import type { Access, AccessMode, McpServer } from "../api/types";
import { READ_ONLY_EXPR, accessFromCondition, lintExpression, readOnlyTools } from "../lib/policy";
import { ToolBadge } from "../steps/InventoryStep";
import { Badge, Term } from "./ui";
import { Tip } from "./Tooltip";
import { CheckIcon, LockIcon, WarnIcon } from "./Icons";

export function Choice({ name, checked, onChange, title, desc, badge, disabled, children, label }: { label?: string; name: string; checked: boolean; onChange: () => void; title: ReactNode; desc?: ReactNode; badge?: ReactNode; disabled?: boolean; children?: ReactNode }) {
  return (
    <label className={`choice ${checked ? "checked" : ""} ${disabled ? "disabled" : ""}`}>
      <input type="radio" name={name} checked={checked} onChange={onChange} disabled={disabled} aria-label={label ?? (typeof title === "string" ? title : undefined)} />
      <span className="choice-body">
        <span className="choice-title">
          {title} {badge}
        </span>
        {desc && <span className="choice-desc">{desc}</span>}
        {checked && children && <span className="choice-extra" onClick={(e) => e.stopPropagation()}>{children}</span>}
      </span>
    </label>
  );
}

/** The chooser's state: the mode plus the tool checklist and the custom expression (kept while switching modes);
 *  `remove`: "Remove access" on a destination that isn't an MCP server (the builder's change mode). */
export type AccessDraft = { mode: AccessMode; tools: string[]; expr: string; remove?: boolean };

/** The builder's "change existing access" extras: which choices to offer, a note per tool (which grant allows it
 *  today), locked tools (an inherited grant allows them: checked, can't be unchecked here), a note under the read-only
 *  hint, and on other destinations All / Custom / Remove with the existing condition shown. */
export type ChooserExtras = {
  modes?: AccessMode[];
  toolNotes?: Record<string, string>;
  locked?: Map<string, { text: string; action?: ReactNode }>;
  hintNote?: ReactNode;
  /** Other destinations in change mode: offer Custom and "Remove access", and show today's access. */
  change?: { current: ReactNode; who: string };
};
type Dest = { kind: string; label: string };

/** A draft from an existing access (or the default: read-only hint for MCP servers, full access otherwise). */
export function draftOf(a: Access | undefined, destKind: string): AccessDraft {
  const acc = a?.mode === "custom" ? accessFromCondition(a.expression) : a;
  if (!acc) return { mode: destKind === "mcp_server" ? "read_only_hint" : "all", tools: [], expr: READ_ONLY_EXPR };
  return { mode: acc.mode, tools: acc.tools ?? [], expr: acc.mode === "custom" ? (acc.expression ?? "") : READ_ONLY_EXPR };
}

/** The effective mode: only MCP servers can be limited (the builder's effMode rule). */
export const effectiveMode = (d: AccessDraft, destKind: string): AccessMode => (destKind !== "mcp_server" ? "all" : d.mode);

/** The access a draft stands for, or null while it's incomplete (no tool picked, an empty expression). */
export function accessOf(d: AccessDraft, destKind: string): Access | null {
  const m = effectiveMode(d, destKind);
  if (m === "tools") return d.tools.length ? { mode: "tools", tools: d.tools } : null;
  if (m === "custom") return d.expr.trim() ? { mode: "custom", expression: d.expr.trim() } : null;
  return { mode: m };
}

/** Lint hints for a custom expression; `blocking` = ones that stop staging. */
export const draftLint = (d: AccessDraft, destKind: string, change = false) =>
  (change && destKind !== "mcp_server" ? d.mode === "custom" && !d.remove : effectiveMode(d, destKind) === "custom") ? lintExpression(d.expr) : [];
export const blocking = (lint: string[]) => lint.some((l) => /unbalanced|not closed|empty/.test(l));

export function AccessChooser({ name, dest, mcp, value, onChange, compact, extras }: { name: string; dest: Dest; mcp?: McpServer; value: AccessDraft; onChange: (d: AccessDraft) => void; compact?: boolean; extras?: ChooserExtras }) {
  const { mode: access, tools, expr } = value;
  const set = (p: Partial<AccessDraft>) => onChange({ ...value, ...p });
  const lint = draftLint(value, dest.kind, !!extras?.change);
  const offered = (m: AccessMode) => !extras?.modes || extras.modes.includes(m);
  const locked = extras?.locked ?? new Map<string, { text: string; action?: ReactNode }>();
  if (dest.kind !== "mcp_server" && extras?.change)
    return (
      <div className="choices">
        <div className="existing-now small">
          <span className="muted">Today: </span>
          {extras.change.current}
        </div>
        <Choice name={name} checked={access !== "custom" && !value.remove} onChange={() => set({ mode: "all", remove: false })} title="Full access" desc={compact ? undefined : `The gateway checks who calls ${dest.label}, not which ${dest.kind === "agent" ? "skill" : "path"} they use: no condition.`} />
        <Choice name={name} checked={access === "custom" && !value.remove} onChange={() => set({ mode: "custom", remove: false })} title="Custom expression" badge={<Badge tone="neutral">Advanced</Badge>} desc={compact ? undefined : <>An <Term k="iam-condition">IAM condition</Term> (CEL), e.g. a time limit.</>}>
          <CustomExpr expr={expr} lint={lint} set={set} />
        </Choice>
        <Choice name={name} checked={!!value.remove} onChange={() => set({ remove: true })} title="Remove access" desc={compact ? undefined : `Remove ${extras.change.who}'s access to ${dest.label}.`} />
      </div>
    );
  if (dest.kind !== "mcp_server")
    return (
      <div className="choices">
        <Choice name={name} checked onChange={() => undefined} title="Full access" desc={compact ? undefined : `The gateway checks who calls ${dest.label}, not which ${dest.kind === "agent" ? "skill" : "path"} they use, so access is all or nothing.`} />
      </div>
    );
  const shown = (mcp?.tools ?? []).filter((t) => tools.includes(t.name) || locked.has(t.name)).length;
  return (
    <div className={`choices ${compact ? "choices-compact" : ""}`}>
      {offered("read_only_hint") && (
        <Choice name={name} checked={access === "read_only_hint"} onChange={() => set({ mode: "read_only_hint" })} title={extras?.modes ? "Read-only (hint)" : "Read-only tools (by MCP hint)"} badge={extras?.modes ? <Badge tone="neutral">today</Badge> : <Badge tone="green">Recommended</Badge>} desc={compact ? undefined : <>Allows tools the server marks <Term k="mcp-hints">readOnlyHint</Term>. New read-only tools are covered automatically; new write tools are not.</>}>
          <div className="tool-preview">
            Today that's: {readOnlyTools(mcp).map((t) => <span key={t} className="mono-chip">{t}</span>)}
          </div>
        </Choice>
      )}
      {extras?.hintNote && <div className="hint-note small">{extras.hintNote}</div>}
      <Choice name={name} checked={access === "tools"} onChange={() => set({ mode: "tools" })} title="Specific tools" desc={compact ? undefined : "Pick tools by name. Tools added later are not included."}>
        {mcp && (
          <div className="tool-check">
            <div className="tool-check-bar">
              <Tip tip="Tick every tool this MCP server marks readOnlyHint.">
                <button type="button" className="link-btn" onClick={() => set({ tools: readOnlyTools(mcp) })}>
                  Select all read-only
                </button>
              </Tip>
              <Tip tip={locked.size ? "Untick every tool you can change here (locked tools stay allowed by their own grant)." : "Untick every tool."}>
                <button type="button" className="link-btn" onClick={() => set({ tools: [] })}>
                  Clear
                </button>
              </Tip>
              <span className="muted small">{shown} selected</span>
            </div>
            {mcp.tools.map((t) => {
              const lock = locked.get(t.name);
              const note = extras?.toolNotes?.[t.name];
              const noteId = `${name}-note-${t.name}`;
              return (
                <div key={t.name} className={`tool-row-wrap ${lock ? "locked" : ""}`}>
                  <label className="tool-row">
                    <input
                      type="checkbox"
                      checked={!!lock || tools.includes(t.name)}
                      disabled={!!lock}
                      aria-describedby={lock || note ? noteId : undefined}
                      onChange={(e) => set({ tools: e.target.checked ? [...tools, t.name] : tools.filter((x) => x !== t.name) })}
                    />
                    <span className="mono small">{t.name}</span>
                    {!compact && <span className="muted small grow">{t.description}</span>}
                    <ToolBadge t={t} />
                  </label>
                  {(lock || note) && (
                    <div className="tool-note muted tiny" id={noteId}>
                      {lock ? (
                        <>
                          <LockIcon size={11} /> {lock.text} {lock.action}
                        </>
                      ) : (
                        note
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Choice>
      <Choice name={name} checked={access === "all"} onChange={() => set({ mode: "all" })} title="All tools" desc={compact ? undefined : "Everything the server offers, including write and destructive tools."} />
      <Choice name={name} checked={access === "custom"} onChange={() => set({ mode: "custom" })} title="Custom expression" badge={<Badge tone="neutral">Advanced</Badge>} desc={compact ? undefined : <>Write your own <Term k="iam-condition">IAM condition</Term> (CEL).</>}>
        <CustomExpr expr={expr} lint={lint} set={set} mcp />
      </Choice>
    </div>
  );
}

function CustomExpr({ expr, lint, set, mcp }: { expr: string; lint: string[]; set: (p: Partial<AccessDraft>) => void; mcp?: boolean }) {
  return (
    <>
      <textarea className="mono expr" rows={4} value={expr} onChange={(e) => set({ expr: e.target.value })} spellCheck={false} aria-label="Custom condition" />
      {lint.length > 0 ? (
        <ul className="lint">
          {lint.map((l) => (
            <li key={l}>
              <WarnIcon size={13} /> {l}
            </li>
          ))}
        </ul>
      ) : (
        <div className="small ok-text">
          <CheckIcon size={13} /> Looks well-formed. IAM validates it for real when it's applied.
        </div>
      )}
      {mcp && (
        <div className="muted tiny">
          Attributes: <span className="mono">iap.googleapis.com/mcp.toolName</span>, <span className="mono">iap.googleapis.com/mcp.tool.isReadOnly</span>
        </div>
      )}
    </>
  );
}
