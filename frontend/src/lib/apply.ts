// Apply (P3) helpers shared by the store, the Apply step and Review: run state types, which kinds are
// destructive, typical durations (from lib/timing.ts) and plain-English labels.
import type { Access, ApplyState, AuthInfo, DiffStatus, Intent } from "../api/types";
import { TIMING } from "./timing";
import { accessFromCondition, accessFroms, accessTos, conditionFor, intentKey, modifyChange, removesAll, shortName } from "./policy";

export type RunItemState = ApplyState | "queued";
export type RunItem = {
  intent: Intent;
  state: RunItemState;
  detail?: string;
  operation?: string;
  undo: Intent[];
  /** Raw Google Cloud error when `detail` is a friendlier translation. */
  rawError?: string;
  startedAt?: number;
  endedAt?: number;
};
export type ApplyRun = {
  id: string;
  project: string;
  region: string;
  startedAt: number;
  endedAt?: number;
  items: RunItem[];
  done: boolean;
  /** Whole-request failure (403, network, aborted). */
  error?: string;
  summary?: unknown;
};

export const DESTRUCTIVE_KINDS = new Set<Intent["kind"]>(["revoke", "unbind_gateway", "model_armor_off"]);
export const SETUP_KINDS = new Set<Intent["kind"]>(["model_armor_template", "model_armor_extension", "iam_project_grant"]);
/** Revokes, unbinds, Model Armor off, the delete (undo) form of the Model Armor setup kinds, dry run (stops
 *  blocking), reverting a dedicated IAP extension (deletes it) and the remove-all form of modify. */
export const isDestructive = (i: Intent) =>
  DESTRUCTIVE_KINDS.has(i.kind) ||
  removesAll(i) ||
  (SETUP_KINDS.has(i.kind) && !!i.params?.delete) ||
  (i.kind === "set_enforcement" && i.mode === "DRY_RUN") ||
  (i.kind === "dedicate_extension" && !!i.revert);

/** How a modify changes access, like the backend's conditions.compare_access: "same" | "narrower" | "broader" |
 *  "unknown". `readOnly`: the MCP server's read-only tool names (undefined = not known). */
export function compareAccess(from: Access | undefined, to: Access | undefined, readOnly?: Set<string>): "same" | "narrower" | "broader" | "unknown" {
  const eff = (x: Access | undefined): Access => (x?.mode === "custom" ? accessFromCondition(x.expression?.trim() ? x.expression : undefined) : (x ?? { mode: "all" }));
  const a = eff(from);
  const b = eff(to);
  const norm = (x: Access) => (conditionFor(x)?.expression ?? "").replace(/\s+/g, " ").trim();
  if (norm(a) === norm(b)) return "same";
  if (b.mode === "all") return "broader";
  if (a.mode === "all") return "narrower";
  const added = (xs: string[], have: Set<string>) => xs.some((t) => !have.has(t));
  if (a.mode === "tools" && b.mode === "tools") return added(b.tools ?? [], new Set(a.tools)) ? "broader" : "narrower";
  if (a.mode === "read_only_hint" && b.mode === "tools" && readOnly) return added(b.tools ?? [], readOnly) ? "broader" : "narrower";
  if (a.mode === "tools" && b.mode === "read_only_hint" && readOnly) return added([...readOnly], new Set(a.tools)) ? "broader" : "unknown";
  return "unknown";
}

/** compareAccess for a modify of several bindings, like the backend's conditions.compare_access_many: IAM ORs a
 *  member's bindings, so today is the union of `from` and after the union of `to`; [] after = "narrower". */
export function compareAccessMany(from: Access[], to: Access[], readOnly?: Set<string>): "same" | "narrower" | "broader" | "unknown" {
  if (from.length === 1 && to.length === 1) return compareAccess(from[0], to[0], readOnly);
  if (!to.length) return "narrower";
  const eff = (x: Access): Access => (x.mode === "custom" ? accessFromCondition(x.expression?.trim() ? x.expression : undefined) : x);
  const a = from.map(eff);
  const b = to.map(eff);
  const norm = (xs: Access[]) => [...new Set(xs.map((x) => (conditionFor(x)?.expression ?? "").replace(/\s+/g, " ").trim()))].sort().join("\n");
  if (norm(a) === norm(b)) return "same";
  // the tools each allows (null = every tool); undefined = can't be told here
  const set = (x: Access): Set<string> | null | undefined => (x.mode === "all" ? null : x.mode === "tools" ? new Set((x.tools ?? []).filter(Boolean)) : x.mode === "read_only_hint" && readOnly ? new Set(readOnly) : undefined);
  const sa = a.map(set);
  const sb = b.map(set);
  if (sa.includes(undefined) || sb.includes(undefined)) {
    const all = from.flatMap((x) => to.map((y) => compareAccess(x, y, readOnly)));
    return all.every((v) => v === "broader") ? "broader" : "unknown";
  }
  const union = (xs: (Set<string> | null | undefined)[]) => (xs.some((x) => x === null) ? null : new Set(xs.flatMap((x) => [...(x as Set<string>)])));
  const ua = union(sa);
  const ub = union(sb);
  if (ub === null) return ua === null ? "same" : "broader";
  if (ua === null) return "narrower";
  if ([...ub].some((t) => !ua.has(t))) return "broader";
  return b.some((x) => x.mode === "read_only_hint") && !a.some((x) => x.mode === "read_only_hint") ? "unknown" : "narrower";
}

/** A modify isn't destructive (except its remove-all form), but widening access deserves a warning (as the backend's
 *  preflight gives); so does removing all access. */
export function modifyWarning(i: Intent, readOnly?: Set<string>): string | null {
  if (i.kind !== "modify") return null;
  if (removesAll(i)) return `This removes all access: ${modifyChange(i)}.`;
  return compareAccessMany(accessFroms(i), accessTos(i), readOnly) === "broader" ? `This widens access: ${modifyChange(i)}.` : null;
}

/** Diff badge labels that read differently for a modify (the others are shared with grant / revoke). */
export const MODIFY_STATUS: Partial<Record<DiffStatus, string>> = { replace: "Will change", absent: "Grant not found", remove: "Will remove all" };

/** What a destructive kind does, for the acknowledgement checkbox. */
export const DESTRUCTIVE_PHRASE: Partial<Record<Intent["kind"], string>> = {
  revoke: "removes access",
  unbind_gateway: "detaches an agent from a gateway",
  model_armor_off: "turns off Model Armor",
  // Setup kinds are destructive only in their delete (undo) form.
  model_armor_template: "deletes a Model Armor template",
  model_armor_extension: "deletes a Model Armor extension",
  iam_project_grant: "removes a service agent's Model Armor roles",
  // Destructive only in these forms.
  modify: "removes all of an agent's access to a destination",
  set_enforcement: "puts a gateway in dry run: nothing is blocked",
  dedicate_extension: "deletes a gateway's own IAP extension",
};

/** Typical time of the Apply call per kind, shown next to the elapsed timer (lib/timing.ts has the table, with how
 *  long each kind then takes to take effect). */
export const TYPICAL = Object.fromEntries(Object.entries(TIMING).map(([k, v]) => [k, v.apply])) as Record<Intent["kind"], { label: string; seconds: number }>;
export const isLongRunning = (i: Intent) => TYPICAL[i.kind].seconds >= 60;

export const CHANGE_KIND: Record<Intent["kind"], string> = {
  grant: "IAM grant on the registry entry",
  revoke: "IAM revoke on the registry entry",
  modify: "IAM change on the registry entry (one read-modify-write)",
  bind_gateway: "Agent update (long-running)",
  unbind_gateway: "Agent update (long-running)",
  model_armor_on: "Create authz policy (long-running)",
  model_armor_off: "Delete authz policy (long-running)",
  model_armor_template: "Model Armor template (setup)",
  model_armor_extension: "Authz extension (setup, long-running)",
  iam_project_grant: "Project IAM for the gateway's service agent (setup)",
  set_enforcement: "Update the IAP authz extension (long-running)",
  dedicate_extension: "Copy the IAP extension + update the gateway's IAP policy (long-running)",
};

export function fmtElapsed(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export const isFinal = (s: RunItemState) => s === "verified" || s === "failed" || s === "skipped";

/** Why Apply is unavailable, in one plain sentence (null when it's available). */
export function applyBlockedReason(a: AuthInfo | null, loading: boolean, error: string | null): string | null {
  if (!a) return loading ? "Checking your credentials…" : error ? `Couldn't check credentials: ${error}` : "Credentials not checked yet.";
  if (a.can_apply) return null;
  if (a.mode === "generate") return a.can_apply_reason || "Generate-only mode: copy the commands and run them yourself.";
  return a.can_apply_reason || a.checks.find((c) => c.status === "error")?.title || "A credential check failed.";
}

const KIND_NOUN: Record<Intent["kind"], string> = {
  grant: "grants",
  revoke: "revokes",
  modify: "grant changes",
  bind_gateway: "gateway bindings",
  unbind_gateway: "gateway unbindings",
  model_armor_on: "turning Model Armor on",
  model_armor_off: "turning Model Armor off",
  model_armor_template: "creating Model Armor templates",
  model_armor_extension: "creating Model Armor extensions",
  iam_project_grant: "granting the service agent roles",
  set_enforcement: "changing a gateway's enforcement mode",
  dedicate_extension: "giving a gateway its own IAP extension",
};
/** Why this kind can't be applied by the signed-in user (null when it can, or when /auth doesn't say). */
export function kindBlockedReason(a: AuthInfo | null, kind: Intent["kind"]): string | null {
  if (!a?.writable || a.writable[kind] !== false) return null;
  const fix = a.checks.find((c) => c.id === "can_write");
  return `You don't have permission to apply ${KIND_NOUN[kind]} in ${a.target_project}${fix?.fix ? " (see the “can write” check on Context for the role grant)" : ""}.`;
}

export const toList = (u: Intent | Intent[] | null | undefined): Intent[] => (!u ? [] : Array.isArray(u) ? u : [u]);

/** Do two intents make the same change? Used to tell an undo apart from an item already staged in the cart (e.g. an
 *  "enforce" staged from Gateways and the undo of the dry run just applied). An enforcement change is the same when
 *  it sets the same extension (or, without one, the same gateway) to the same mode, whatever its scope. */
export function sameChange(a: Intent, b: Intent): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "set_enforcement") {
    const target = (i: Intent) => (i.extension ? `x:${shortName(i.extension)}` : `g:${shortName(i.gateway?.name ?? "")}`);
    return a.mode === b.mode && target(a) === target(b);
  }
  return intentKey(a) === intentKey(b);
}
