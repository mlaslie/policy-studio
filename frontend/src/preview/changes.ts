// The Add to cart preview's change list (the Build step): for the one change the builder stages, each MCP tool (or the
// destination, for A2A agents, endpoints and Agent Runtime agents) today and after it, with the grants behind each
// side; the bindings it replaces or removes and the one it adds; and the warnings. Pure: today is the inventory, after
// is the inventory with the change applied (map/simulate.ts, the same as the map's staged view).
import type { Binding, Engine, Intent, Inventory } from "../api/types";
import { simulate } from "../map/simulate";
import { conditionAllows } from "../map/evaluate";
import { existingFor, grantLabel, inheritedLabel, type Existing } from "../lib/existing";
import { accessFroms, accessFromCondition, accessWords, intentEnglish, removesAll } from "../lib/policy";

export type ToolState = "allowed" | "denied" | "unknown";
export interface ChangeRow {
  /** Tool name, or the destination's label (not an MCP server). */
  name: string;
  tool: boolean;
  readOnly?: boolean;
  today: ToolState;
  /** The grants that allow it today ("read-only grant", "project-wide grant", ...). */
  todayBy: string[];
  after: ToolState;
  afterBy: string[];
  /** Allowed after only through inherited grants (it can't be removed here). */
  inheritedOnly: boolean;
  change: "added" | "removed" | "same" | "unknown";
}
export interface PreviewWarning {
  id: "widen" | "remove_all" | "inherited" | "hint" | "hint_new" | "no_gateway" | "unknown" | "new_entry" | "no_tools";
  tone: "red" | "amber" | "info";
  text: string;
}
export interface BindingLine {
  binding: Binding;
  /** "read-only grant: only read-only tools" */
  text: string;
}
export type PreviewKind = "grant" | "change" | "revoke" | "remove_all";
export interface PreviewModel {
  kind: PreviewKind;
  title: string;
  sentence: string;
  rows: ChangeRow[];
  /** Own bindings the change removes (replaced, or removed for good). */
  removed: BindingLine[];
  /** Own bindings it adds (one; none for a revoke or the remove-all form). */
  added: BindingLine[];
  warnings: PreviewWarning[];
}

export interface PreviewInput {
  intent: Intent;
  inv: Inventory;
  /** The source agent, when it's an Agent Runtime agent (for the no-gateway warning). */
  engine?: Engine;
  /** The cart: a gateway bind staged there counts (the no-gateway warning then says so). */
  cart?: Intent[];
  /** Staged with the change: a registry_service create of the destination it grants on (destination.pending_service). */
  extras?: Intent[];
}

const norm = (e: string | undefined | null) => (e ?? "").replace(/\s+/g, " ").trim();
const has = (bs: Binding[], b: Binding) => bs.some((x) => norm(x.condition?.expression) === norm(b.condition?.expression));
const lineOf = (b: Binding): BindingLine => ({ binding: b, text: `${grantLabel(b)}: ${accessWords(accessFromCondition(b.condition?.expression))}` });

/** One tool (or a call with no tool name: A2A, endpoints) under a set of grants: allowed if any allows it, unknown if
 *  one can't be told here (a custom condition), else denied; with the labels of the grants that allow it. */
function stateOf(ex: Existing, tool: string | null, tools: Record<string, boolean> | null): { state: ToolState; by: string[]; ownBy: string[] } {
  const call = tool === null ? {} : { mcp_method: "tools/call", mcp_tool: tool };
  const by: string[] = [];
  const ownBy: string[] = [];
  let unknown = false;
  for (const b of ex.own) {
    const ok = conditionAllows(b.condition, call, tools);
    if (ok === true) ownBy.push(grantLabel(b));
    if (ok === null) unknown = true;
  }
  const maybe: string[] = [];
  for (const h of ex.inherited) {
    const ok = conditionAllows(h.binding.condition, call, tools);
    // a group's members can't be told here (as on the map): it may allow it
    if (ok === true && h.via === "group") maybe.push(`${inheritedLabel(h)} (if a member)`);
    else if (ok === true) by.push(inheritedLabel(h));
    if (ok === null) unknown = true;
  }
  const all = [...new Set([...ownBy, ...by])];
  const state: ToolState = all.length ? "allowed" : unknown || maybe.length ? "unknown" : "denied";
  return { state, by: [...all, ...new Set(maybe)], ownBy };
}

export function previewModel({ intent, inv, engine, cart = [], extras = [] }: PreviewInput): PreviewModel {
  const dest = intent.destination!;
  const who = intent.source?.label ?? "The agent";
  const principal = intent.source?.principal;
  const before = existingFor(inv, principal, dest.name);
  const regs = extras.filter((x) => x.kind === "registry_service" && !x.params?.delete);
  const afterInv = simulate({ inventory: inv, gateways: [] }, [...regs, intent]).inventory;
  const after = existingFor(afterInv, principal, dest.name);
  // a new entry (registered with this change) is only in the after state
  const mcp = dest.kind === "mcp_server" ? (inv.mcp_servers.find((m) => m.name === dest.name) ?? afterInv.mcp_servers.find((m) => m.name === dest.name)) : undefined;
  const toolMap = mcp ? Object.fromEntries(mcp.tools.map((t) => [t.name, t.read_only])) : null;

  const row = (name: string, tool: string | null, readOnly?: boolean): ChangeRow => {
    const t = stateOf(before, tool, toolMap);
    const a = stateOf(after, tool, toolMap);
    const change = t.state === a.state ? "same" : a.state === "allowed" && t.state !== "allowed" ? "added" : t.state === "allowed" && a.state === "denied" ? "removed" : "unknown";
    return { name, tool: tool !== null, readOnly, today: t.state, todayBy: t.by, after: a.state, afterBy: a.by, inheritedOnly: a.state === "allowed" && !a.ownBy.length, change };
  };
  const rows = mcp && mcp.tools.length ? mcp.tools.map((t) => row(t.name, t.name, t.read_only)) : [row(dest.label, null)];

  const removed = before.own.filter((b) => !has(after.own, b)).map(lineOf);
  const added = after.own.filter((b) => !has(before.own, b)).map(lineOf);
  const kind: PreviewKind = intent.kind === "grant" ? "grant" : intent.kind === "revoke" ? "revoke" : removesAll(intent) ? "remove_all" : "change";

  // ---------- warnings ----------
  const warnings: PreviewWarning[] = [];
  const names = (rs: ChangeRow[]) => rs.map((r) => r.name).join(", ");
  const widened = rows.filter((r) => r.change === "added");
  if (kind === "change" && widened.length)
    warnings.push({ id: "widen", tone: "amber", text: mcp ? `This widens access: ${names(widened)} ${widened.length === 1 ? "becomes" : "become"} allowed.` : `This widens access to ${dest.label}.` });
  const anyToday = rows.some((r) => r.today === "allowed");
  const grants = kind === "remove_all" ? ` (${accessFroms(intent).length} grants, in one change)` : "";
  if (anyToday && rows.every((r) => r.after === "denied")) warnings.push({ id: "remove_all", tone: "red", text: `This removes all of ${who}'s access to ${dest.label}${grants}.` });
  // removing every own grant while an inherited one still allows something: say both
  else if (kind === "revoke" || kind === "remove_all") warnings.push({ id: "remove_all", tone: "red", text: `This removes all of ${who}'s own access to ${dest.label}${grants}. Inherited grants still allow some of it (below).` });
  const kept = rows.filter((r) => r.inheritedOnly);
  if (kept.length) {
    const via = [...new Set(kept.flatMap((r) => r.afterBy))].join(" / ");
    warnings.push({ id: "inherited", tone: "info", text: mcp ? `${names(kept)} ${kept.length === 1 ? "stays" : "stay"} allowed by the ${via}: change it there.` : `${dest.label} stays allowed by the ${via}: change it there.` });
  }
  const hintBefore = removed.some((l) => grantLabel(l.binding) === "read-only grant") && !after.own.some((b) => grantLabel(b) === "read-only grant");
  if (mcp && kind === "change" && hintBefore)
    warnings.push({ id: "hint", tone: "amber", text: "Today's read-only grant also covers read-only tools added to the server later. After this change only the tools listed are allowed: future read-only tools are dropped." });
  else if (mcp && added.some((l) => grantLabel(l.binding) === "read-only grant") && !before.own.some((b) => grantLabel(b) === "read-only grant"))
    warnings.push({ id: "hint_new", tone: "info", text: "The read-only hint also allows read-only tools added to the server later." });
  if (engine && !engine.gateways.egress) {
    const staged = cart.some((i) => i.kind === "bind_gateway" && i.engine === engine.name && i.gateway?.direction === "egress");
    warnings.push({
      id: "no_gateway",
      tone: staged ? "info" : "amber",
      text: staged
        ? `${engine.display_name} isn't behind an egress gateway yet (a bind is in your cart): until it is, nothing is enforced.`
        : `${engine.display_name} isn't behind an egress gateway: its calls go straight out and nothing is enforced, so this change has no effect until it's bound.`,
    });
  }
  if (dest.pending_service) {
    const reg = regs.find((x) => x.params?.service_id === dest.pending_service);
    const n = reg?.params?.interfaces?.length ?? 0;
    warnings.push({ id: "new_entry", tone: "info", text: `${dest.label} is registered with this change (${n} URL${n === 1 ? "" : "s"}), then granted: Apply registers it first and grants on the id the registry gives it.` });
    if (mcp && !mcp.tools.length && intent.access && intent.access.mode !== "all")
      warnings.push({ id: "no_tools", tone: "amber", text: `${dest.label} is registered without a tool list, so this tool condition only lets MCP setup calls through. Grant full access, or add the tools/list response to the registration.` });
  }
  if (rows.some((r) => r.today === "unknown" || r.after === "unknown"))
    warnings.push({ id: "unknown", tone: "info", text: "A custom or group condition can't be evaluated here: those rows show “can't tell”." });

  const title = kind === "grant" ? `Add access: ${who} → ${dest.label}` : kind === "change" ? `Change access: ${who} → ${dest.label}` : `Remove access: ${who} → ${dest.label}`;
  return { kind, title, sentence: intentEnglish(intent), rows, removed, added, warnings };
}
