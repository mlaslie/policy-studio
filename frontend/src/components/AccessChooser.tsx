// "How much of it?": the access choice for a grant (pulled out of the builder so the policy map's panel uses the same
// one for Change access and Allow…). MCP servers: read-only by hint, specific tools (checklist), all tools, or a
// custom CEL condition with lint hints. A2A agents and APIs are all-or-nothing.
import type { ReactNode } from "react";
import type { Access, AccessMode, McpServer } from "../api/types";
import { READ_ONLY_EXPR, accessFromCondition, lintExpression, readOnlyTools } from "../lib/policy";
import { ToolBadge } from "../steps/InventoryStep";
import { Badge, Term } from "./ui";
import { Tip } from "./Tooltip";
import { CheckIcon, WarnIcon } from "./Icons";

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

/** The chooser's state: the mode plus the tool checklist and the custom expression (kept while switching modes). */
export type AccessDraft = { mode: AccessMode; tools: string[]; expr: string };
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
export const draftLint = (d: AccessDraft, destKind: string) => (effectiveMode(d, destKind) === "custom" ? lintExpression(d.expr) : []);
export const blocking = (lint: string[]) => lint.some((l) => /unbalanced|not closed|empty/.test(l));

export function AccessChooser({ name, dest, mcp, value, onChange, compact }: { name: string; dest: Dest; mcp?: McpServer; value: AccessDraft; onChange: (d: AccessDraft) => void; compact?: boolean }) {
  const { mode: access, tools, expr } = value;
  const set = (p: Partial<AccessDraft>) => onChange({ ...value, ...p });
  const lint = draftLint(value, dest.kind);
  if (dest.kind !== "mcp_server")
    return (
      <div className="choices">
        <Choice name={name} checked onChange={() => undefined} title="Full access" desc={compact ? undefined : `The gateway checks who calls ${dest.label}, not which ${dest.kind === "agent" ? "skill" : "path"} they use, so access is all or nothing.`} />
      </div>
    );
  return (
    <div className={`choices ${compact ? "choices-compact" : ""}`}>
      <Choice name={name} checked={access === "read_only_hint"} onChange={() => set({ mode: "read_only_hint" })} title="Read-only tools (by MCP hint)" badge={<Badge tone="green">Recommended</Badge>} desc={compact ? undefined : <>Allows tools the server marks <Term k="mcp-hints">readOnlyHint</Term>. New read-only tools are covered automatically; new write tools are not.</>}>
        <div className="tool-preview">
          Today that's: {readOnlyTools(mcp).map((t) => <span key={t} className="mono-chip">{t}</span>)}
        </div>
      </Choice>
      <Choice name={name} checked={access === "tools"} onChange={() => set({ mode: "tools" })} title="Specific tools" desc={compact ? undefined : "Pick tools by name. Tools added later are not included."}>
        {mcp && (
          <div className="tool-check">
            <div className="tool-check-bar">
              <Tip tip="Tick every tool this MCP server marks readOnlyHint.">
                <button type="button" className="link-btn" onClick={() => set({ tools: readOnlyTools(mcp) })}>
                  Select all read-only
                </button>
              </Tip>
              <Tip tip="Untick every tool.">
                <button type="button" className="link-btn" onClick={() => set({ tools: [] })}>
                  Clear
                </button>
              </Tip>
              <span className="muted small">{tools.length} selected</span>
            </div>
            {mcp.tools.map((t) => (
              <label key={t.name} className="tool-row">
                <input type="checkbox" checked={tools.includes(t.name)} onChange={(e) => set({ tools: e.target.checked ? [...tools, t.name] : tools.filter((x) => x !== t.name) })} />
                <span className="mono small">{t.name}</span>
                {!compact && <span className="muted small grow">{t.description}</span>}
                <ToolBadge t={t} />
              </label>
            ))}
          </div>
        )}
      </Choice>
      <Choice name={name} checked={access === "all"} onChange={() => set({ mode: "all" })} title="All tools" desc={compact ? undefined : "Everything the server offers, including write and destructive tools."} />
      <Choice name={name} checked={access === "custom"} onChange={() => set({ mode: "custom" })} title="Custom expression" badge={<Badge tone="neutral">Advanced</Badge>} desc={compact ? undefined : <>Write your own <Term k="iam-condition">IAM condition</Term> (CEL).</>}>
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
        <div className="muted tiny">
          Attributes: <span className="mono">iap.googleapis.com/mcp.toolName</span>, <span className="mono">iap.googleapis.com/mcp.tool.isReadOnly</span>
        </div>
      </Choice>
    </div>
  );
}
