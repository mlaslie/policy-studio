// How long changes take to take effect: the table covers every intent kind, the "ready around" time (largest typical,
// largest max, mixed kinds), measured vs estimated labels, and the results banner before and after the time passes.
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ReadyBanner } from "../components/Timing";
import { KIND_LABEL, KIND_ORDER } from "./policy";
import { TYPICAL } from "./apply";
import { BASIS_LABEL, TIMING, clock, effectText, isMeasured, readyPhase, readyWindow, setupTimingNote, stageTip, storedText, timeLeft, timingNote, type Kind } from "./timing";

const MIN = 60_000;
const T0 = Date.UTC(2026, 9, 13, 20, 12, 46);

/** The kinds as declared: the IntentKind union in api/types.ts, and the backend's IntentKind Literal when present. */
function declaredKinds(): { ts: string[]; py: string[] | null } {
  const ts = readFileSync(resolve(__dirname, "../api/types.ts"), "utf8");
  const union = /export type IntentKind =([^;]+);/.exec(ts)![1];
  const py = resolve(__dirname, "../../../backend/policy_studio/model.py");
  const lit = existsSync(py) ? /IntentKind = Literal\[([^\]]+)\]/.exec(readFileSync(py, "utf8"))?.[1] : undefined;
  const names = (s: string) => [...s.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  return { ts: names(union), py: lit ? names(lit) : null };
}

describe("timing table", () => {
  it("has an entry for every intent kind", () => {
    const { ts, py } = declaredKinds();
    expect(ts.length).toBeGreaterThanOrEqual(12);
    for (const k of [...ts, ...(py ?? []), ...Object.keys(KIND_LABEL), ...Object.keys(KIND_ORDER)]) {
      expect(TIMING[k as Kind], `no timing for ${k}`).toBeDefined();
      expect(TYPICAL[k as Kind], `no apply time for ${k}`).toBeDefined();
    }
    if (py) expect(new Set(py)).toEqual(new Set(ts));
    expect(Object.keys(TIMING).sort()).toEqual([...ts].sort());
  });

  it("gives every entry a label, min ≤ typical ≤ max in minutes, a basis and what happens in between", () => {
    for (const [k, x] of Object.entries(TIMING)) {
      expect(x.min, k).toBeGreaterThanOrEqual(0);
      expect(x.min, k).toBeLessThanOrEqual(x.typical);
      expect(x.typical, k).toBeLessThanOrEqual(x.max);
      expect(x.max, k).toBeLessThanOrEqual(10);
      expect(BASIS_LABEL[x.basis], k).toBeTruthy();
      expect(x.after && x.note, k).toBeTruthy();
      expect(x.between, k).toMatch(/\.$/);
      expect(`${x.after} ${x.note} ${x.between}`, k).not.toMatch(/please|successfully/i);
    }
  });

  it("uses the known numbers", () => {
    expect([TIMING.set_enforcement.typical, TIMING.set_enforcement.max]).toEqual([2, 3]);
    for (const k of ["grant", "revoke", "modify", "iam_project_grant"] as Kind[]) expect(TIMING[k].max).toBe(7);
    expect(TYPICAL.bind_gateway.label).toBe("about 5 min");
    expect(TIMING.bind_gateway.note).toContain("redeploys the agent (about 5 min)");
    expect(TIMING.unbind_gateway.between).toContain("calls in flight during the switch can fail");
    expect(TIMING.dedicate_extension.note).toContain("about 20 s");
  });
});

describe("measured vs estimated labels", () => {
  it("marks only the enforcement change as measured", () => {
    expect((Object.keys(TIMING) as Kind[]).filter(isMeasured)).toEqual(["set_enforcement"]);
    expect(effectText("set_enforcement")).toBe("about 2–3 minutes after Apply (measured)");
  });
  it("says (not measured) for estimates and nothing extra for Google's documented IAM range", () => {
    expect(effectText("model_armor_on")).toBe("usually in a few minutes (not measured)");
    expect(effectText("model_armor_template")).toBe("in a few minutes (not measured)");
    expect(effectText("bind_gateway")).toMatch(/\(not measured\)$/);
    expect(effectText("grant")).toBe("in a few minutes (up to about 7)");
    expect(storedText("grant")).toBe("Stored. Takes effect in a few minutes (up to about 7).");
  });
});

describe("notes before applying", () => {
  it("lists each distinct note once and ends with wait before testing", () => {
    expect(timingNote(["grant", "grant", "revoke", "bind_gateway"])).toBe(
      "After Apply: IAM grants usually take effect within a few minutes (up to about 7); IAM revokes usually take effect within a few minutes (up to about 7); binding redeploys the agent (about 5 min). Wait before testing.",
    );
    expect(timingNote([])).toBe("");
  });
  it("explains the redeploy in bind and unbind tooltips", () => {
    expect(stageTip("bind_gateway")).toContain("redeploys (about 5 minutes)");
    expect(stageTip("unbind_gateway")).toContain("calls in flight during the switch can fail");
    expect(stageTip("set_enforcement")).toBe("An enforcement change takes effect about 2–3 minutes after Apply (measured).");
  });
});

describe("ready around", () => {
  it("is the finish time plus the largest typical time, and the largest max", () => {
    const w = readyWindow(["grant"], T0)!;
    expect(w.at - T0).toBe(2 * MIN);
    expect(w.latest - T0).toBe(7 * MIN);
    expect(w.slowest).toBe("grant");
  });
  it("takes each bound from its own kind when kinds are mixed", () => {
    // enforcement: typical 2, max 3; grant: typical 2, max 7; bind: typical 1, max 2
    const w = readyWindow(["bind_gateway", "set_enforcement", "grant"], T0)!;
    expect(w.at - T0).toBe(2 * MIN);
    expect(w.latest - T0).toBe(7 * MIN);
    expect(w.slowest).toBe("set_enforcement"); // the first with the largest typical
    const ma = readyWindow(["grant", "model_armor_on"], T0)!;
    expect([(ma.at - T0) / MIN, (ma.latest - T0) / MIN, ma.slowest]).toEqual([3, 7, "model_armor_on"]);
    const enf = readyWindow(["set_enforcement", "bind_gateway"], T0)!;
    expect([(enf.at - T0) / MIN, (enf.latest - T0) / MIN]).toEqual([2, 3]);
  });
  it("is null when nothing was stored", () => {
    expect(readyWindow([], T0)).toBeNull();
  });
  it("moves from waiting to likely to done", () => {
    const w = readyWindow(["grant"], T0)!;
    expect(readyPhase(w, T0)).toBe("waiting");
    expect(readyPhase(w, w.at - 1)).toBe("waiting");
    expect(readyPhase(w, w.at)).toBe("likely");
    expect(readyPhase(w, w.latest)).toBe("done");
    expect(timeLeft(150_000)).toBe("about 3 min left");
    expect(timeLeft(20_000)).toBe("under a minute left");
    expect(timeLeft(0)).toBe("");
  });
});

describe("results banner", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());
  const kinds: Kind[] = ["grant", "bind_gateway", "set_enforcement"];
  const banner = () => renderToStaticMarkup(<ReadyBanner kinds={kinds} finishedAt={T0} />);

  it("says when to test before the time passes, politely and without announcing the countdown", () => {
    vi.setSystemTime(T0 + 30_000);
    const html = banner();
    expect(html).toContain('role="status"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain(`Ready to test around ${clock(T0 + 2 * MIN)}`);
    expect(html).toContain(`latest about ${clock(T0 + 7 * MIN)}`);
    expect(html).toMatch(/aria-hidden="true">about 2 min left</);
    expect(html).toContain("Verified means stored");
    expect(html).not.toContain("Should be in effect now");
    // each kind's own time, since they differ
    expect(html).toContain("Enforcement mode: about 2–3 minutes after Apply (measured)");
  });

  it("turns into should be in effect now once the time has passed", () => {
    vi.setSystemTime(T0 + 3 * MIN);
    const html = banner();
    expect(html).toContain("Should be in effect now");
    expect(html).not.toContain("Ready to test around");
    expect(html).toContain(`wait until about ${clock(T0 + 7 * MIN)}`);
  });

  it("says it isn't the wait any more after the latest time", () => {
    vi.setSystemTime(T0 + 8 * MIN);
    const html = banner();
    expect(html).toContain("Should be in effect now");
    expect(html).toContain("Past the latest expected time");
  });

  it("shows nothing when no item was verified", () => {
    vi.setSystemTime(T0);
    expect(renderToStaticMarkup(<ReadyBanner kinds={[]} finishedAt={T0} />)).toBe("");
  });
});

describe("Model Armor setup note", () => {
  it("is built from the kinds being staged", () => {
    expect(setupTimingNote(["model_armor_template", "model_armor_extension", "iam_project_grant", "model_armor_on"])).toBe(
      "After Apply this takes several minutes to take effect: the template, extension and policy need a few minutes each, and service-agent roles up to about 7. Test once the Apply page says it's ready.",
    );
    expect(setupTimingNote(["model_armor_extension", "iam_project_grant", "iam_project_grant", "model_armor_on"])).toBe(
      "After Apply this takes several minutes to take effect: the extension and policy need a few minutes each, and service-agent roles up to about 7. Test once the Apply page says it's ready.",
    );
    expect(setupTimingNote(["model_armor_on"])).toBe("After Apply this takes several minutes to take effect: the policy needs a few minutes. Test once the Apply page says it's ready.");
    expect(setupTimingNote(["iam_project_grant"])).toBe("After Apply this takes several minutes to take effect: service-agent roles need up to about 7. Test once the Apply page says it's ready.");
  });

  it("follows the table and says nothing when nothing is staged", () => {
    expect(setupTimingNote([])).toBe("");
    expect(setupTimingNote(["grant"])).toBe("");
    expect(setupTimingNote(["iam_project_grant"])).toContain(`up to about ${TIMING.iam_project_grant.max}`);
  });
});
