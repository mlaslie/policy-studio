// Turn a current grant (from /audit) back into an intent: for "Edit in builder", "Revoke" and Export.
import type { Access, Engine, Grant, Intent, SourceType } from "../api/types";
import { accessFromCondition, conditionFor, newId } from "./policy";

export { accessFromCondition };

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

/** One `modify` intent that changes this grant's access to `access`: access_from is the grant's exact condition (as
 *  a revoke carries it), so the backend replaces exactly that binding, in one read-modify-write. */
export function grantToModify(g: Grant, engineByPrincipal: Map<string, Engine>, access: Access): Intent {
  return { ...grantToIntent(g, engineByPrincipal, "revoke"), kind: "modify", access_from: exactAccess(g.condition), access };
}

/** Is `i` the revoke of exactly this grant (member, resource and condition expression)? */
export function revokesGrant(i: Partial<Intent>, g: Grant): boolean {
  const norm = (e: string | undefined) => (e ?? "").replace(/\s+/g, " ").trim();
  return i.kind === "revoke" && i.source?.principal === g.member && i.destination?.name === g.resource && norm(conditionFor(i.access)?.expression) === norm(g.condition?.expression);
}
