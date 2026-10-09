// Turn a current grant (from /audit) back into an intent: for "Edit in builder", "Revoke" and Export.
import type { Engine, Grant, Intent, SourceType } from "../api/types";
import { READ_ONLY_EXPR, TOOL_ATTR, newId } from "./policy";

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

export function grantToIntent(g: Grant, engineByPrincipal: Map<string, Engine>, kind: "grant" | "revoke"): Intent {
  const e = engineByPrincipal.get(g.member);
  const type: SourceType = e ? "engine" : g.member.startsWith("principalSet://") ? "project_agents" : "custom";
  const destKind = g.resource_kind === "registry" ? "endpoint" : g.resource_kind;
  return {
    id: newId(),
    kind,
    source: { type, principal: g.member, label: e?.display_name ?? (type === "project_agents" ? "All agents in this project" : g.member_label.replace(/ \(Agent Identity\)$/, "")), engine: e?.name },
    destination: { kind: destKind, id: g.resource.split("/").pop() ?? g.resource, name: g.resource, label: g.resource_label },
    ...(kind === "grant" ? { access: accessFromCondition(g.condition?.expression) } : {}),
  };
}
