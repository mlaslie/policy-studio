// Apply (P3) helpers shared by the store, the Apply step and Review: run state types, which kinds are
// destructive, typical durations and plain-English labels.
import type { ApplyState, AuthInfo, Intent } from "../api/types";
import { intentKey, shortName } from "./policy";

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
 *  blocking) and reverting a dedicated IAP extension (deletes it). */
export const isDestructive = (i: Intent) =>
  DESTRUCTIVE_KINDS.has(i.kind) ||
  (SETUP_KINDS.has(i.kind) && !!i.params?.delete) ||
  (i.kind === "set_enforcement" && i.mode === "DRY_RUN") ||
  (i.kind === "dedicate_extension" && !!i.revert);

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
  set_enforcement: "puts a gateway in dry run: nothing is blocked",
  dedicate_extension: "deletes a gateway's own IAP extension",
};

/** Typical time per kind, shown next to the elapsed timer. */
export const TYPICAL: Record<Intent["kind"], { label: string; seconds: number }> = {
  grant: { label: "a few seconds", seconds: 5 },
  revoke: { label: "a few seconds", seconds: 5 },
  bind_gateway: { label: "about 5 min", seconds: 300 },
  unbind_gateway: { label: "about 5 min", seconds: 300 },
  model_armor_on: { label: "about 4 min", seconds: 240 },
  model_armor_off: { label: "about 4 min", seconds: 240 },
  model_armor_template: { label: "a few seconds", seconds: 5 },
  model_armor_extension: { label: "about 1 min", seconds: 60 },
  iam_project_grant: { label: "a few seconds", seconds: 5 },
  set_enforcement: { label: "about 1 min (in effect in 2–3 min)", seconds: 60 },
  dedicate_extension: { label: "a few minutes", seconds: 180 },
};
export const isLongRunning = (i: Intent) => TYPICAL[i.kind].seconds >= 60;

export const CHANGE_KIND: Record<Intent["kind"], string> = {
  grant: "IAM grant on the registry entry",
  revoke: "IAM revoke on the registry entry",
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
