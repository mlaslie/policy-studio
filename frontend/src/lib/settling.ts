// Applies whose changes are still settling: stored (verified) but maybe not yet enforced by the gateway (lib/timing.ts
// has the table). The top bar's chip and the map's clock markers read this list from the store; it's kept in
// sessionStorage next to the Apply history, so a reload doesn't lose it. Pure: every function takes `now`.
//
// One entry per apply: when it finished, its ready window (largest typical time, largest max among the stored kinds) and
// what it changed (enough of each intent to find its line or node on the map). An entry leaves the list once its max
// time has passed.
import type { Direction, Intent } from "../api/types";
import type { ApplyRun } from "./apply";
import { KIND_LABEL } from "./policy";
import { clock, readyWindow, timeLeft, type Kind } from "./timing";

/** What an applied intent changed, as the map needs it: its source, destination, gateway, engine and tools. */
export type SettleTarget = {
  kind: Kind;
  source?: { principal: string; engine?: string };
  destination?: { name: string };
  gateway?: { name: string; direction: Direction };
  engine?: string;
  tools?: string[];
};
export type SettleEntry = {
  /** The apply's run id (its result is in the Apply history). */
  runId: string;
  project: string;
  /** Apply finished (ms). */
  appliedAt: number;
  /** Ready around (typical) and the latest expected time (max), ms. */
  at: number;
  latest: number;
  kinds: Kind[];
  targets: SettleTarget[];
};

export const SETTLING_KEY = "studio.settling";
/** "Should be in effect" stays this long after the typical time, then the chip goes (sooner if the max passes). */
export const IN_EFFECT_MS = 60_000;
const MAX_ENTRIES = 10;

const targetOf = (i: Intent): SettleTarget => {
  const tools = [...(i.access?.tools ?? []), ...(i.access_list ?? []).flatMap((a) => a.tools ?? [])].filter(Boolean);
  return {
    kind: i.kind,
    ...(i.source ? { source: { principal: i.source.principal, ...(i.source.engine ? { engine: i.source.engine } : {}) } } : {}),
    ...(i.destination ? { destination: { name: i.destination.name } } : {}),
    ...(i.gateway ? { gateway: { name: i.gateway.name, direction: i.gateway.direction } } : {}),
    ...(i.engine ? { engine: i.engine } : {}),
    ...(tools.length ? { tools: [...new Set(tools)] } : {}),
  };
};

/** The entry for a finished apply: its verified items. Null when nothing was stored. */
export function settleEntry(run: ApplyRun): SettleEntry | null {
  const stored = run.items.filter((i) => i.state === "verified").map((i) => i.intent);
  const w = readyWindow(
    stored.map((i) => i.kind),
    run.endedAt ?? Date.now(),
  );
  if (!w) return null;
  return { runId: run.id, project: run.project, appliedAt: w.from, at: w.at, latest: w.latest, kinds: [...new Set(stored.map((i) => i.kind))], targets: stored.map(targetOf) };
}

/** Entries whose max time hasn't passed (the same array when none has). */
export function pruneSettling(list: SettleEntry[], now: number): SettleEntry[] {
  const keep = list.filter((e) => now < e.latest);
  return keep.length === list.length ? list : keep;
}

/** Add an apply (replacing one with the same run id), newest first, expired ones dropped. */
export function addSettling(list: SettleEntry[], e: SettleEntry, now: number): SettleEntry[] {
  return pruneSettling([e, ...list.filter((x) => x.runId !== e.runId)], now)
    .sort((a, b) => b.appliedAt - a.appliedAt)
    .slice(0, MAX_ENTRIES);
}

/** settling: before the latest ready time. in_effect: past it, for about a minute (never past the latest max).
 *  gone: nothing to show. */
export type SettlePhase = "settling" | "in_effect" | "gone";
export type SettleSummary = {
  phase: SettlePhase;
  /** Latest ready time and latest max across the live entries (0 when there are none). */
  at: number;
  latest: number;
  /** Entries whose max hasn't passed, newest first. */
  live: SettleEntry[];
  /** The newest apply: the chip opens its result. */
  newest: SettleEntry | null;
};

export function settleSummary(list: SettleEntry[], now: number): SettleSummary {
  const live = list.filter((e) => now < e.latest).sort((a, b) => b.appliedAt - a.appliedAt);
  if (!live.length) return { phase: "gone", at: 0, latest: 0, live, newest: null };
  const at = Math.max(...live.map((e) => e.at));
  const latest = Math.max(...live.map((e) => e.latest));
  const phase: SettlePhase = now < at ? "settling" : now < Math.min(at + IN_EFFECT_MS, latest) ? "in_effect" : "gone";
  return { phase, at, latest, live, newest: live[0] };
}

/** When the summary next changes on its own (a ready time, the end of "in effect", a max): for one timer, not a tick. */
export function nextSettleChange(list: SettleEntry[], now: number): number | null {
  const ts = list.flatMap((e) => [e.at, e.at + IN_EFFECT_MS, e.latest]).filter((t) => t > now);
  return ts.length ? Math.min(...ts) : null;
}

/** The chip: "Settling · ready ~15:34", then "Should be in effect"; "" when it's gone. */
export function chipText(s: SettleSummary): string {
  if (s.phase === "settling") return `Settling · ready ~${clock(s.at)}`;
  if (s.phase === "in_effect") return "Should be in effect";
  return "";
}

/** One apply, briefly: "15:31: Grant, Bind (ready ~15:34, latest ~15:39)". */
export const entryLine = (e: SettleEntry) => `${clock(e.appliedAt)}: ${e.kinds.map((k) => KIND_LABEL[k]).join(", ")} (ready ~${clock(e.at)}, latest ~${clock(e.latest)})`;

/** The chip's tooltip, one line each: "About 2 min left; latest about 15:39. …", then each apply. */
export function chipTip(s: SettleSummary, now: number): string[] {
  if (s.phase === "gone") return [];
  const head =
    s.phase === "settling"
      ? [`${timeLeft(s.at - now) || "under a minute left"}; latest about ${clock(s.latest)}.`, "Stored, but the gateway may still enforce the old policy until then."]
      : [`Past the usual time (${clock(s.at)}). If a test still fails, wait until about ${clock(s.latest)}.`];
  return [`${head[0][0].toUpperCase()}${head[0].slice(1)}`, ...head.slice(1), ...s.live.map(entryLine), "Click to open the result."];
}

/** What the polite status region says: once per phase, never the countdown. */
export function phaseAnnouncement(s: SettleSummary): string {
  if (s.phase === "settling") return `Applied changes are settling: ready around ${clock(s.at)}.`;
  if (s.phase === "in_effect") return "Applied changes should be in effect now.";
  return "";
}

/** The map's tooltip for a line or node an apply changed. */
export const markText = (e: SettleEntry) =>
  `Applied at ${clock(e.appliedAt)}; the gateway may still enforce the old policy until about ${clock(e.at)}${e.latest > e.at ? ` (latest about ${clock(e.latest)})` : ""}.`;

const isEntry = (x: unknown): x is SettleEntry => {
  const e = x as SettleEntry;
  return !!e && typeof e === "object" && typeof e.runId === "string" && typeof e.appliedAt === "number" && typeof e.at === "number" && typeof e.latest === "number" && Array.isArray(e.kinds) && Array.isArray(e.targets);
};

/** Read the saved list (sessionStorage, like the Apply history): missing, broken or blocked storage gives []; expired
 *  and malformed entries are dropped. */
export function loadSettling(store: Pick<Storage, "getItem"> | null | undefined, now: number): SettleEntry[] {
  try {
    const v: unknown = JSON.parse(store?.getItem(SETTLING_KEY) ?? "[]");
    return Array.isArray(v) ? pruneSettling(v.filter(isEntry), now) : [];
  } catch {
    return [];
  }
}

export function saveSettling(store: Pick<Storage, "setItem" | "removeItem"> | null | undefined, list: SettleEntry[]) {
  try {
    if (list.length) store?.setItem(SETTLING_KEY, JSON.stringify(list));
    else store?.removeItem(SETTLING_KEY);
  } catch {
    /* storage disabled */
  }
}

/** sessionStorage, or null where reading it throws. */
export function sessionStore(): Storage | null {
  try {
    return typeof sessionStorage === "undefined" ? null : sessionStorage;
  } catch {
    return null;
  }
}
