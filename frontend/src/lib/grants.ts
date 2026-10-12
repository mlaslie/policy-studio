// Turn a current grant (from /audit) back into an intent: for "Edit in builder", "Revoke" and Export.
import type { Engine, Grant, Intent, SourceType } from "../api/types";
import { READ_ONLY_EXPR, TOOL_ATTR, conditionFor, newId } from "./policy";

export function accessFromCondition(expr: string | undefined): Intent["access"] {
  if (!expr) return { mode: "all" };
  const e = expr.replace(/\s+/g, " ").trim();
  if (e === READ_ONLY_EXPR) return { mode: "read_only_hint" };
  const m = new RegExp(`^api\\.getAttribute\\('${TOOL_ATTR.replace(/\./g, "\\.")}', ''\\) in \\[(.*)\\]$`).exec(e);
  if (m) {
    const tools = [...m[1].matchAll(/'((?:[^'\\]|\\.)*)'/g)].map((x) => x[1]).filter(Boolean);
    return { mode: "tools", tools };
  }
  return { mode: "custom", expression: expr };
}

/** An existing binding's condition, verbatim (mode "custom" with its exact expression and title; none = "all").
 *  A revoke must carry it: IAM matches the binding by its exact expression, and a revoke without access means the
 *  unconditional binding. Regenerating it from accessFromCondition could differ (a tools list gains '', quotes). */
export function exactAccess(cond: Grant["condition"]): NonNullable<Intent["access"]> {
  return cond?.expression?.trim() ? { mode: "custom", expression: cond.expression, title: cond.title || undefined } : { mode: "all" };
}

export function grantToIntent(g: Grant, engineByPrincipal: Map<string, Engine>, kind: "grant" | "revoke"): Intent {
  const e = engineByPrincipal.get(g.member);
  const type: SourceType = e ? "engine" : g.member.startsWith("principalSet://") ? "project_agents" : "custom";
  const registry = g.resource_kind === "registry";
  return {
    id: newId(),
    kind,
    source: { type, principal: g.member, label: e?.display_name ?? (type === "project_agents" ? "All agents in this project" : g.member_label.replace(/ \(Agent Identity\)$/, "")), engine: e?.name },
    // registry = a registry-wide grant: id "", name projects/P/locations/R (API.md)
    destination: { kind: g.resource_kind, id: registry ? "" : (g.resource.split("/").pop() ?? g.resource), name: g.resource, label: g.resource_label },
    access: kind === "grant" ? accessFromCondition(g.condition?.expression) : exactAccess(g.condition),
  };
}

/** Is `i` the revoke of exactly this grant (member, resource and condition expression)? */
export function revokesGrant(i: Partial<Intent>, g: Grant): boolean {
  const norm = (e: string | undefined) => (e ?? "").replace(/\s+/g, " ").trim();
  return i.kind === "revoke" && i.source?.principal === g.member && i.destination?.name === g.resource && norm(conditionFor(i.access)?.expression) === norm(g.condition?.expression);
}
