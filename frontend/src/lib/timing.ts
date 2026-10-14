// How long each kind of change takes: the Apply call itself (shown next to the elapsed timer), and the wait after
// Apply reports it stored (read back) until the gateway enforces it. One table for every kind; the Apply step, Review,
// the Build preview, Undo, the Gateways step and the map panel all read it. backend/policy_studio/timing.py has the
// same numbers (backend/tests/test_timing.py compares them).
//
// Verified means stored, not in effect: a grant verified at 20:12:46 UTC still got a 403 from the gateway 30 s later,
// and the same call worked a few minutes later.
import type { Intent } from "../api/types";

export type Kind = Intent["kind"];
/** measured: timed here. documented: Google's documented range (IAM), seen here too. estimate: not measured. */
export type Basis = "measured" | "documented" | "estimate";
export type Timing = {
  /** The Apply call itself: shown next to the elapsed timer. */
  apply: { label: string; seconds: number };
  /** Minutes from when Apply reports the item stored (verified) until the gateway enforces it. Apply already waits
   *  for long-running operations (a redeploy, a Model Armor policy), so they aren't counted again. */
  min: number;
  typical: number;
  max: number;
  basis: Basis;
  /** "Takes effect {after}" once it's stored. */
  after: string;
  /** Before applying: the whole wait from Apply, as a clause for "After Apply: …". */
  note: string;
  /** What happens in between, in one sentence. */
  between: string;
};

const t = (basis: Basis, min: number, typical: number, max: number, apply: [string, number], after: string, note: string, between: string): Timing => ({
  apply: { label: apply[0], seconds: apply[1] },
  min,
  typical,
  max,
  basis,
  after,
  note,
  between,
});

const IAM_AFTER = "in a few minutes (up to about 7)";
const FEW_SECONDS: [string, number] = ["a few seconds", 5];
const REDEPLOY = "within about a minute of the redeploy finishing";

// Each line: basis, min, typical, max (minutes after stored), the Apply call, after, note, between.
// (backend/tests/test_timing.py reads the basis and the three numbers from these lines.)
export const TIMING: Record<Kind, Timing> = {
  grant: t("documented", 0.5, 2, 7, FEW_SECONDS, IAM_AFTER, "IAM grants usually take effect within a few minutes (up to about 7)", "Calls may still get a 403 from the gateway until then."),
  revoke: t("documented", 0.5, 2, 7, FEW_SECONDS, IAM_AFTER, "IAM revokes usually take effect within a few minutes (up to about 7)", "Calls may still be allowed by the old grant until then."),
  modify: t("documented", 0.5, 2, 7, FEW_SECONDS, IAM_AFTER, "IAM changes usually take effect within a few minutes (up to about 7)", "Calls may still be allowed or denied by the old condition until then."),
  iam_project_grant: t("documented", 0.5, 2, 7, FEW_SECONDS, IAM_AFTER, "service agent roles usually take effect within a few minutes (up to about 7)", "Model Armor may fail to screen until the roles take effect."),
  bind_gateway: t("estimate", 0, 1, 2, ["about 5 min", 300], REDEPLOY, "binding redeploys the agent (about 5 min)", "New calls go through the gateway once the switch is done; calls in flight during the switch can fail."),
  unbind_gateway: t("estimate", 0, 1, 2, ["about 5 min", 300], REDEPLOY, "unbinding redeploys the agent (about 5 min)", "New calls stop going through the gateway once the switch is done; calls in flight during the switch can fail."),
  set_enforcement: t("measured", 0, 2, 3, ["about 1 min", 60], "about 2–3 minutes after Apply", "an enforcement change takes effect about 2–3 minutes after Apply (measured)", "Calls are still checked under the old mode until then."),
  dedicate_extension: t("estimate", 2, 2.5, 3, ["a few minutes", 180], "about 2–3 minutes after the policy update", "giving a gateway its own extension takes a policy update (about 20 s), then about 2–3 minutes (not measured)", "The gateway keeps using the shared extension until then."),
  model_armor_on: t("estimate", 1, 3, 5, ["about 4 min", 240], "usually in a few minutes", "turning Model Armor on takes about 4 min, then usually a few more (not measured)", "Prompts may still reach agents unscreened until then."),
  model_armor_off: t("estimate", 1, 3, 5, ["about 4 min", 240], "usually in a few minutes", "turning Model Armor off takes about 4 min, then usually a few more (not measured)", "Prompts may still be screened, and blocked, until then."),
  model_armor_template: t("estimate", 1, 3, 5, FEW_SECONDS, "in a few minutes", "a Model Armor template change takes a few minutes (not measured)", "Model Armor may still use the old settings until then."),
  model_armor_extension: t("estimate", 1, 3, 5, ["about 1 min", 60], "in a few minutes", "a Model Armor extension change takes a few minutes (not measured)", "Model Armor on may not find it until then."),
};

export const BASIS_LABEL: Record<Basis, string> = { measured: "measured", documented: "Google's documented range", estimate: "not measured" };
const BASIS_SOURCE: Record<Basis, string> = {
  measured: "Measured: an enforcement change took effect 2m40s, 2m08s and 2m19s after Apply, sometimes before the operation reported done.",
  documented: "Google documents that IAM changes usually propagate within about 2 minutes and can take up to 7. Seen here: not in effect 30 s after read-back, in effect a few minutes later.",
  estimate: "Not measured: an estimate.",
};

export const isMeasured = (k: Kind) => TIMING[k].basis === "measured";

/** "in a few minutes (up to about 7)", "about 2–3 minutes after Apply (measured)", "… (not measured)". */
export function effectText(k: Kind): string {
  const x = TIMING[k];
  return x.basis === "documented" ? x.after : `${x.after} (${BASIS_LABEL[x.basis]})`;
}

/** "Stored. Takes effect …" for a verified item. */
export const storedText = (k: Kind) => `Stored. Takes effect ${effectText(k)}.`;

/** The longer explanation for a tooltip: what happens in between, and where the numbers come from. */
export const effectWhy = (k: Kind) => `${TIMING[k].between} ${BASIS_SOURCE[TIMING[k].basis]}`;

/** Before applying: "After Apply: IAM grants usually take effect within a few minutes (up to about 7); binding
 *  redeploys the agent (about 5 min). Wait before testing." One clause per distinct note, in the order given. */
export function timingNote(kinds: Kind[]): string {
  const notes = [...new Set(kinds.map((k) => TIMING[k].note))];
  return notes.length ? `After Apply: ${notes.join("; ")}. Wait before testing.` : "";
}

/** One kind's note as a sentence, for tooltips and the preview: "IAM grants usually take effect …". */
export const timingSentence = (k: Kind) => `${TIMING[k].note[0].toUpperCase()}${TIMING[k].note.slice(1)}.`;

export type ReadyWindow = {
  /** Apply finished (ms). */
  from: number;
  /** finished + the largest typical time among the stored kinds. */
  at: number;
  /** finished + the largest max among them (the slowest expected case, maybe another kind). */
  latest: number;
  /** The kind with the largest typical time (the first in the list when tied). */
  slowest: Kind;
};

/** When to test: the apply finish time plus the largest typical time among the applied (stored) kinds, and the latest
 *  expected time: plus the largest max. With mixed kinds each bound takes its own largest, so a grant (typical 2,
 *  max 7) and an enforcement change (typical 2, max 3) give 2 and 7. Null when nothing was stored. */
export function readyWindow(kinds: Kind[], finishedAt: number): ReadyWindow | null {
  if (!kinds.length) return null;
  let slowest = kinds[0];
  for (const k of kinds) if (TIMING[k].typical > TIMING[slowest].typical) slowest = k;
  const max = Math.max(...kinds.map((k) => TIMING[k].max));
  return { from: finishedAt, at: finishedAt + TIMING[slowest].typical * 60_000, latest: finishedAt + max * 60_000, slowest };
}

/** waiting: before `at`. likely: past `at`, before `latest`. done: past `latest`. */
export type ReadyPhase = "waiting" | "likely" | "done";
export const readyPhase = (w: ReadyWindow, now: number): ReadyPhase => (now < w.at ? "waiting" : now < w.latest ? "likely" : "done");

/** "about 3 min left" (whole minutes, rounded up; "under a minute left" at the end). */
export function timeLeft(ms: number): string {
  if (ms <= 0) return "";
  if (ms < 60_000) return "under a minute left";
  return `about ${Math.ceil(ms / 60_000)} min left`;
}

/** 24-hour local "HH:MM", like the times in Google Cloud logs. */
export const clock = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });

/** For the tooltips of actions that stage a change (Gateways step, map panel): bind and unbind say what the redeploy
 *  means for traffic; the others give their timing sentence. */
export function stageTip(k: Kind): string {
  if (k === "bind_gateway") return "When it's applied, the agent redeploys (about 5 minutes); calls go through the gateway once that finishes, and calls in flight during the switch can fail.";
  if (k === "unbind_gateway") return "When it's applied, the agent redeploys (about 5 minutes); calls stop going through the gateway once that finishes, and calls in flight during the switch can fail.";
  return timingSentence(k);
}

/** What each Model Armor setup kind is called in the setup's timing note. */
const SETUP_NOUN: Partial<Record<Kind, string>> = {
  model_armor_template: "template",
  model_armor_extension: "extension",
  model_armor_on: "policy",
  iam_project_grant: "service-agent roles",
};
const and = (xs: string[]) => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

/** The Model Armor setup's note above "Stage all steps", from the kinds being staged: "After Apply this takes several
 *  minutes to take effect: the extension and policy need a few minutes each, and service-agent roles up to about 7.
 *  Test once the Apply page says it's ready." IAM roles give their documented max; the rest "a few minutes". */
export function setupTimingNote(kinds: Kind[]): string {
  const ks = [...new Set(kinds)].filter((k) => SETUP_NOUN[k]);
  if (!ks.length) return "";
  const few = ks.filter((k) => TIMING[k].basis !== "documented").map((k) => SETUP_NOUN[k]!);
  const iam = ks.filter((k) => TIMING[k].basis === "documented");
  const clauses = [
    ...(few.length ? [`the ${and(few)} ${few.length > 1 ? "need a few minutes each" : "needs a few minutes"}`] : []),
    ...(iam.length ? [`${and(iam.map((k) => SETUP_NOUN[k]!))} ${few.length ? "" : "need "}up to about ${Math.max(...iam.map((k) => TIMING[k].max))}`] : []),
  ];
  const max = Math.max(...ks.map((k) => TIMING[k].max));
  return `After Apply this takes ${max >= 5 ? "several" : "a few"} minutes to take effect: ${clauses.join(", and ")}. Test once the Apply page says it's ready.`;
}
