// "Change existing access" in the Build step: what the selected source already holds on the selected destination
// (read from the inventory), each MCP tool's state today and why, and the one change that replaces it. Pure, small
// (no map code): the builder imports it on first load.
//
// A source's own grants are its direct roles/iap.egressor bindings on the destination (exact member match). With one
// or more of them the builder is in "change" mode and stages ONE intent: a modify (one binding → the new one; several
// → access_from_list → the new one), a revoke (one binding, nothing left), or the modify's remove-all form (several
// bindings, nothing left; one setIamPolicy). Inherited grants (project-wide principalSet, allUsers /
// allAuthenticatedUsers, groups, registry-wide) can't be changed here: their tools show checked and locked, and they're
// never part of the change.
import type { Access, AccessMode, Binding, Intent, Inventory, McpServer } from "../api/types";
import { EVERYONE, PROJECT_AGENTS_RE, conditionAllows, isReadOnlyHint, parseTools, memberMatches } from "../map/evaluate";
import { exactAccess } from "./grants";
import { READ_ONLY_EXPR, ROLE, accessFromCondition, conditionFor } from "./policy";

/** Registry-wide IAM key: projects/<GP>/locations/<R> (as graph.ts REGISTRY_KEY_RE, without importing the map). */
const REGISTRY_KEY_RE = /^projects\/[^/]+\/locations\/[^/]+$/;

export type Via = "project_agents" | "public" | "registry_wide" | "group";
export const VIA_GRANT: Record<Via, string> = { project_agents: "project-wide grant", public: "public grant", registry_wide: "registry-wide grant", group: "group grant" };

/** A grant the source inherits: `resource` is the destination, or the registry key for a registry-wide one. */
export interface Inherited {
  binding: Binding;
  resource: string;
  via: Via;
}
export interface Existing {
  /** The source's own egressor bindings on the destination, in policy order. */
  own: Binding[];
  inherited: Inherited[];
}

export type BuildMode = "new" | "change";
export const buildModeOf = (ex: Existing): BuildMode => (ex.own.length ? "change" : "new");

function viaOf(member: string): Via | null {
  if (EVERYONE.includes(member)) return "public";
  if (PROJECT_AGENTS_RE.test(member)) return "project_agents";
  if (member.startsWith("group:") || member.startsWith("domain:")) return "group";
  return null;
}

/** What `principal` holds on `destName` today: its own bindings, and the ones it inherits (a group member can't be
 *  told here: counted as inherited, as the map's "conditional" line does). */
export function existingFor(inv: Inventory | null | undefined, principal: string | undefined, destName: string | undefined): Existing {
  if (!inv || !principal || !destName) return { own: [], inherited: [] };
  const on = (inv.access[destName] ?? []).filter((b) => b.role === ROLE);
  const own = on.filter((b) => b.member === principal);
  const inherited: Inherited[] = [];
  for (const b of on) {
    if (b.member === principal || memberMatches(b.member, principal) === false) continue;
    const via = viaOf(b.member);
    if (via) inherited.push({ binding: b, resource: destName, via });
  }
  for (const key of Object.keys(inv.access).filter((k) => REGISTRY_KEY_RE.test(k) && k !== destName))
    for (const b of inv.access[key].filter((x) => x.role === ROLE))
      if (memberMatches(b.member, principal) !== false) inherited.push({ binding: b, resource: key, via: "registry_wide" });
  return { own, inherited };
}

/** "read-only grant", "tools grant", "full-access grant", "custom grant": what an own binding is, in the tool notes. */
export function grantLabel(b: Pick<Binding, "condition">): string {
  const e = b.condition?.expression?.trim() ?? "";
  if (!e) return "full-access grant";
  if (isReadOnlyHint(e)) return "read-only grant";
  return parseTools(e) !== null ? "tools grant" : "custom grant";
}
export const inheritedLabel = (h: Inherited) => VIA_GRANT[h.via];

export interface ToolToday {
  name: string;
  readOnly: boolean;
  destructive: boolean;
  /** Labels of the own grants that allow it (deduplicated, in policy order). */
  own: string[];
  /** Inherited grants that allow it: locked in the builder. */
  inherited: Inherited[];
}

const toolCall = (name: string) => ({ mcp_method: "tools/call", mcp_tool: name });

/** Each MCP tool today: which own grants allow it, and which inherited ones. */
export function toolsToday(mcp: McpServer | undefined, ex: Existing): ToolToday[] {
  if (!mcp) return [];
  const map = Object.fromEntries(mcp.tools.map((t) => [t.name, t.read_only]));
  return mcp.tools.map((t) => ({
    name: t.name,
    readOnly: t.read_only,
    destructive: t.destructive,
    own: [...new Set(ex.own.filter((b) => conditionAllows(b.condition, toolCall(t.name), map) === true).map(grantLabel))],
    inherited: ex.inherited.filter((h) => conditionAllows(h.binding.condition, toolCall(t.name), map) === true),
  }));
}

/** "allowed today by: read-only grant" (+ another own grant), or null. */
export const toolNote = (t: ToolToday): string | null => (t.own.length ? `allowed today by: ${t.own.join(" + ")}` : null);
/** Tools an inherited grant allows: locked (checked, can't be unchecked here), with the first grant that allows it. */
export const lockedTools = (today: ToolToday[]): Map<string, Inherited> => new Map(today.filter((t) => t.inherited.length).map((t) => [t.name, t.inherited[0]]));

/** Does an own binding use the read-only hint? (Only then the builder offers "Read-only (hint)" in change mode.) */
export const usesHint = (ex: Existing) => ex.own.some((b) => isReadOnlyHint(b.condition?.expression ?? ""));

/** The access choices offered: MCP new grants all four; MCP changes Specific tools / All tools / Custom, plus the
 *  read-only hint only when an existing binding uses it; other destinations All (new) or All / Custom (change; "Remove
 *  access" is offered separately). */
export function modeOptions(destKind: string, mode: BuildMode, ex: Existing): AccessMode[] {
  if (destKind !== "mcp_server") return mode === "change" ? ["all", "custom"] : ["all"];
  if (mode === "new") return ["read_only_hint", "tools", "all", "custom"];
  return [...(usesHint(ex) ? (["read_only_hint"] as const) : []), "tools", "all", "custom"];
}

/** The builder's access state: the chooser's draft plus, on non-MCP destinations in change mode, "remove access". */
export interface BuildChoice {
  mode: AccessMode;
  tools: string[];
  expr: string;
  remove?: boolean;
}

/** Where the builder starts for a destination: the default for a new grant (read-only hint on MCP servers, full
 *  access elsewhere), or today's access in change mode. Change mode, MCP: one binding keeps its mode (a custom one its
 *  expression); several start on Specific tools. The tool checklist starts with the tools the own grants allow today
 *  (it's what Specific tools shows when picked). Other destinations: All when an own binding is unconditional, else
 *  Custom with its expression. */
export function initialChoice(destKind: string, ex: Existing, mcp?: McpServer): BuildChoice {
  const mcpDest = destKind === "mcp_server";
  if (!ex.own.length) return { mode: mcpDest ? "read_only_hint" : "all", tools: [], expr: READ_ONLY_EXPR };
  const accs = ex.own.map((b) => accessFromCondition(b.condition?.expression));
  if (!mcpDest) {
    const cond = ex.own.find((b) => b.condition?.expression?.trim());
    return accs.some((a) => a.mode === "all") || !cond ? { mode: "all", tools: [], expr: READ_ONLY_EXPR } : { mode: "custom", tools: [], expr: cond.condition!.expression };
  }
  const allowed = toolsToday(mcp, ex).filter((t) => t.own.length).map((t) => t.name);
  if (accs.length > 1) return { mode: "tools", tools: allowed, expr: READ_ONLY_EXPR };
  const a = accs[0];
  return { mode: a.mode, tools: allowed, expr: a.mode === "custom" ? (a.expression ?? "") : READ_ONLY_EXPR };
}

/** The access a choice asks for: an Access, "remove" (change mode: no tool left, or "Remove access"), or null while
 *  it's incomplete. Locked (inherited) tools are left out of a tools list: they stay allowed by their own grant. */
export function targetOf(c: BuildChoice, destKind: string, mode: BuildMode, locked: Set<string> = new Set()): Access | "remove" | null {
  if (destKind !== "mcp_server") {
    if (mode === "new") return { mode: "all" };
    if (c.remove) return "remove";
    return c.mode === "custom" ? (c.expr.trim() ? { mode: "custom", expression: c.expr.trim() } : null) : { mode: "all" };
  }
  if (c.mode === "tools") {
    const tools = c.tools.filter((t) => !locked.has(t));
    return tools.length ? { mode: "tools", tools } : mode === "change" ? "remove" : null;
  }
  if (c.mode === "custom") return c.expr.trim() ? { mode: "custom", expression: c.expr.trim() } : null;
  return { mode: c.mode };
}

const normExpr = (e: string | undefined | null) => (e ?? "").replace(/\s+/g, " ").trim();
/** One own binding, and the target is exactly its condition: nothing to change. */
export const isSame = (own: Binding[], target: Access | "remove" | null) =>
  own.length === 1 && !!target && target !== "remove" && normExpr(conditionFor(target)?.expression) === normExpr(own[0].condition?.expression);

/** The one intent the builder stages (null: incomplete, or no change). No own binding: a grant. One: a modify of it
 *  (access_from exact), or its revoke. Several: a modify with access_from_list (every one, exact) → the new access, or
 *  its remove-all form (access_list []), both one setIamPolicy. */
export function changeIntent(p: { id: string; source: NonNullable<Intent["source"]>; destination: NonNullable<Intent["destination"]>; own: Binding[]; target: Access | "remove" | null }): Intent | null {
  const { id, source, destination, own, target } = p;
  if (!target) return null;
  if (!own.length) return target === "remove" ? null : { id, kind: "grant", source, destination, access: target };
  if (isSame(own, target)) return null;
  if (own.length === 1)
    return target === "remove"
      ? { id, kind: "revoke", source, destination, access: exactAccess(own[0].condition) }
      : { id, kind: "modify", source, destination, access_from: exactAccess(own[0].condition), access: target };
  const froms = own.map((b) => exactAccess(b.condition));
  return target === "remove" ? { id, kind: "modify", source, destination, access_from_list: froms, access_list: [] } : { id, kind: "modify", source, destination, access_from_list: froms, access: target };
}
