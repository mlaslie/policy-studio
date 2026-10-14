// Applies still settling (lib/settling.ts): the list (add, merge several, expiry), the summary's phases as time passes
// (settling → in effect → gone), the chip's text and tooltip, the polite announcement, and saving to and loading from
// sessionStorage, broken storage included.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Intent } from "../api/types";
import type { ApplyRun } from "./apply";
import {
  IN_EFFECT_MS,
  SETTLING_KEY,
  addSettling,
  chipText,
  chipTip,
  loadSettling,
  markText,
  nextSettleChange,
  phaseAnnouncement,
  pruneSettling,
  saveSettling,
  settleEntry,
  settleSummary,
  type SettleEntry,
} from "./settling";
import { clock } from "./timing";

const MIN = 60_000;
const T0 = Date.UTC(2026, 9, 14, 15, 31, 0);

const grant: Intent = { id: "g", kind: "grant", source: { type: "engine", principal: "principal://agents/a1", label: "Helpdesk", engine: "engines/a1" }, destination: { kind: "mcp_server", id: "m1", name: "mcp/m1", label: "Tickets" }, access: { mode: "tools", tools: ["get_ticket"] } };
const bind: Intent = { id: "b", kind: "bind_gateway", engine: "engines/a2", gateway: { name: "gateways/egress", direction: "egress" } };
const enforce: Intent = { id: "e", kind: "set_enforcement", gateway: { name: "gateways/egress", direction: "egress" }, mode: "ENFORCE" };

function run(id: string, endedAt: number, items: [Intent, ApplyRun["items"][number]["state"]][]): ApplyRun {
  return { id, project: "my-demo-project", region: "us-east4", startedAt: endedAt - 5_000, endedAt, done: true, items: items.map(([intent, state]) => ({ intent, state, undo: [] })) };
}
const entry = (id: string, endedAt: number, items: Intent[]) => settleEntry(run(id, endedAt, items.map((i) => [i, "verified"])))!;

describe("settleEntry", () => {
  it("takes the verified items: ready at the largest typical time, latest at the largest max", () => {
    const e = settleEntry(run("r1", T0, [[grant, "verified"], [bind, "verified"], [enforce, "failed"]]))!;
    // grant: typical 2, max 7; bind: typical 1, max 2
    expect(e).toMatchObject({ runId: "r1", project: "my-demo-project", appliedAt: T0, at: T0 + 2 * MIN, latest: T0 + 7 * MIN, kinds: ["grant", "bind_gateway"] });
    expect(e.targets).toEqual([
      { kind: "grant", source: { principal: "principal://agents/a1", engine: "engines/a1" }, destination: { name: "mcp/m1" }, tools: ["get_ticket"] },
      { kind: "bind_gateway", gateway: { name: "gateways/egress", direction: "egress" }, engine: "engines/a2" },
    ]);
  });

  it("is null when nothing was stored", () => {
    expect(settleEntry(run("r1", T0, [[grant, "failed"], [bind, "skipped"]]))).toBeNull();
  });
});

describe("the list", () => {
  it("adds newest first, replaces the same run and drops expired entries", () => {
    const a = entry("a", T0, [grant]);
    const b = entry("b", T0 + MIN, [bind]);
    let l = addSettling([], a, T0);
    l = addSettling(l, b, T0 + MIN);
    expect(l.map((e) => e.runId)).toEqual(["b", "a"]);
    expect(addSettling(l, { ...a, at: a.at + 1 }, T0 + MIN).map((e) => e.runId)).toEqual(["b", "a"]);
    expect(addSettling(l, { ...a, at: a.at + 1 }, T0 + MIN)).toHaveLength(2);
    // b (bind, max 2) has expired at T0 + 3 min; a (grant, max 7) hasn't
    expect(pruneSettling(l, T0 + 3 * MIN).map((e) => e.runId)).toEqual(["a"]);
    expect(pruneSettling(l, T0 + 7 * MIN)).toEqual([]);
    // unchanged: the same array (no re-render)
    expect(pruneSettling(l, T0 + MIN)).toBe(l);
  });

  it("merges several applies: the latest ready time and the latest max across all of them", () => {
    const a = entry("a", T0, [bind]); // ready +1, latest +2
    const b = entry("b", T0 + 30_000, [grant]); // ready +2.5, latest +7.5
    const s = settleSummary([a, b], T0 + 10_000);
    expect(s).toMatchObject({ phase: "settling", at: b.at, latest: b.latest });
    expect(s.newest!.runId).toBe("b");
    expect(s.live.map((e) => e.runId)).toEqual(["b", "a"]);
    // once a's max passes, only b counts
    expect(settleSummary([a, b], T0 + 2 * MIN).live.map((e) => e.runId)).toEqual(["b"]);
  });
});

describe("phases over time", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });
  afterEach(() => vi.useRealTimers());

  it("settling → in effect (about a minute) → gone, then the entry expires at its max", () => {
    const l = [entry("a", Date.now(), [grant])];
    const at = () => settleSummary(l, Date.now()).phase;
    expect(at()).toBe("settling");
    vi.advanceTimersByTime(2 * MIN - 1);
    expect(at()).toBe("settling");
    vi.advanceTimersByTime(1);
    expect(at()).toBe("in_effect");
    vi.advanceTimersByTime(IN_EFFECT_MS - 1);
    expect(at()).toBe("in_effect");
    vi.advanceTimersByTime(1);
    expect(at()).toBe("gone");
    // still in the list (the map's markers stay) until the max
    expect(pruneSettling(l, Date.now())).toHaveLength(1);
    vi.advanceTimersByTime(7 * MIN);
    expect(pruneSettling(l, Date.now())).toEqual([]);
  });

  it("in effect never outlasts the max: a bind (typical 1, max 2) goes at its max", () => {
    const l = [entry("a", Date.now(), [enforce])]; // typical 2, max 3
    vi.advanceTimersByTime(2 * MIN + 30_000);
    expect(settleSummary(l, Date.now()).phase).toBe("in_effect");
    const b = [entry("b", T0, [{ ...bind }])];
    // a bind's window is 1 min typical, 2 max: in effect from +1 to +2
    expect(settleSummary(b, T0 + MIN + 59_000).phase).toBe("in_effect");
    expect(settleSummary(b, T0 + 2 * MIN).phase).toBe("gone");
  });

  it("a new apply while one is in effect starts settling again", () => {
    const a = entry("a", Date.now(), [bind]);
    vi.advanceTimersByTime(MIN + 10_000);
    expect(settleSummary([a], Date.now()).phase).toBe("in_effect");
    const b = entry("b", Date.now(), [grant]);
    expect(settleSummary(addSettling([a], b, Date.now()), Date.now())).toMatchObject({ phase: "settling", at: b.at });
  });

  it("nextSettleChange gives the next boundary, for one timer", () => {
    const l = [entry("a", Date.now(), [grant])];
    expect(nextSettleChange(l, Date.now())).toBe(T0 + 2 * MIN);
    expect(nextSettleChange(l, T0 + 2 * MIN)).toBe(T0 + 2 * MIN + IN_EFFECT_MS);
    expect(nextSettleChange(l, T0 + 3 * MIN)).toBe(T0 + 7 * MIN);
    expect(nextSettleChange(l, T0 + 7 * MIN)).toBeNull();
  });
});

describe("the chip", () => {
  const l = [entry("a", T0, [grant, bind])];

  it("says settling with the ready time, then should be in effect, then nothing", () => {
    expect(chipText(settleSummary(l, T0))).toBe(`Settling · ready ~${clock(T0 + 2 * MIN)}`);
    expect(chipText(settleSummary(l, T0 + 2 * MIN))).toBe("Should be in effect");
    expect(chipText(settleSummary(l, T0 + 3 * MIN + 1))).toBe("");
    expect(chipText(settleSummary([], T0))).toBe("");
  });

  it("has a countdown tooltip, with each apply briefly", () => {
    const tip = chipTip(settleSummary(l, T0 + 10_000), T0 + 10_000);
    expect(tip[0]).toBe(`About 2 min left; latest about ${clock(T0 + 7 * MIN)}.`);
    expect(tip).toContain(`${clock(T0)}: Grant, Bind (ready ~${clock(T0 + 2 * MIN)}, latest ~${clock(T0 + 7 * MIN)})`);
    expect(tip[tip.length - 1]).toBe("Click to open the result.");
    const two = [...l, entry("b", T0 - MIN, [enforce])];
    expect(chipTip(settleSummary(two, T0), T0).filter((x) => /: (Grant|Enforcement)/.test(x))).toHaveLength(2);
    expect(chipTip(settleSummary(l, T0 + 2 * MIN), T0 + 2 * MIN)[0]).toBe(`Past the usual time (${clock(T0 + 2 * MIN)}). If a test still fails, wait until about ${clock(T0 + 7 * MIN)}.`);
    expect(chipTip(settleSummary([], T0), T0)).toEqual([]);
  });

  it("announces only the phase: the same text for every tick within it", () => {
    const say = (t: number) => phaseAnnouncement(settleSummary(l, t));
    expect(say(T0)).toBe(say(T0 + 90_000));
    expect(say(T0)).toBe(`Applied changes are settling: ready around ${clock(T0 + 2 * MIN)}.`);
    expect(say(T0 + 2 * MIN)).toBe("Applied changes should be in effect now.");
    expect(say(T0 + 4 * MIN)).toBe("");
  });

  it("gives the map's tooltip", () => {
    expect(markText(l[0])).toBe(`Applied at ${clock(T0)}; the gateway may still enforce the old policy until about ${clock(T0 + 2 * MIN)} (latest about ${clock(T0 + 7 * MIN)}).`);
  });
});

describe("persistence", () => {
  const mem = () => {
    const m = new Map<string, string>();
    return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k), m };
  };

  it("saves and loads the list; expired and malformed entries are dropped", () => {
    const s = mem();
    const a = entry("a", T0, [grant]);
    const b = entry("b", T0, [bind]);
    saveSettling(s, [a, b]);
    expect(loadSettling(s, T0 + MIN)).toEqual([a, b]);
    expect(loadSettling(s, T0 + 3 * MIN)).toEqual([a]);
    s.setItem(SETTLING_KEY, JSON.stringify([a, { runId: 1 }, null, "x"]));
    expect(loadSettling(s, T0)).toEqual([a]);
    saveSettling(s, []);
    expect(s.m.has(SETTLING_KEY)).toBe(false);
  });

  it("survives broken storage: throwing, bad JSON, the wrong shape, none at all", () => {
    const boom = {
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
      removeItem: () => {
        throw new Error("SecurityError");
      },
    };
    expect(loadSettling(boom, T0)).toEqual([]);
    expect(() => saveSettling(boom, [entry("a", T0, [grant])])).not.toThrow();
    expect(() => saveSettling(boom, [])).not.toThrow();
    expect(loadSettling({ getItem: () => "{not json" }, T0)).toEqual([]);
    expect(loadSettling({ getItem: () => '{"runId":"a"}' }, T0)).toEqual([]);
    expect(loadSettling(null, T0)).toEqual([]);
    expect(() => saveSettling(undefined, [])).not.toThrow();
  });

  it("round-trips through the list helpers (an entry is plain JSON)", () => {
    const a: SettleEntry = entry("a", T0, [grant, bind]);
    expect(JSON.parse(JSON.stringify(a))).toEqual(a);
  });
});
