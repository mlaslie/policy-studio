// Every navigation target is a step key: goto("…") and stepN("…") anywhere in the source, the keys the store's
// actions use, and no step referred to by number any more.
import { describe, expect, it } from "vitest";
import { STEPS, STEP_KEYS, isStepKey, migrateSavedStep, stepN } from "./store";

// Every source file as text (Vite's glob import; test files left out).
const raw = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}"], { query: "?raw", import: "default", eager: true });
const files = Object.entries(raw).map(([f, text]) => ({ f: f.replace(/^\.\//, ""), text }));

describe("step navigation", () => {
  it("has the map at step 1 and unique keys", () => {
    expect(STEPS.map((s) => s.key)).toEqual(["context", "map", "gateways", "model-armor", "inventory", "build", "review", "apply", "audit"]);
    expect(new Set(STEP_KEYS).size).toBe(STEPS.length);
    expect(stepN("map")).toBe(1);
    expect(stepN("apply")).toBe(7);
  });

  it("every goto / stepN target in the source is a step key", () => {
    const targets = files.flatMap(({ f, text }) => [...text.matchAll(/\b(?:goto|stepN)\(\s*"([^"]*)"\s*\)/g)].map((m) => ({ f, key: m[1] })));
    expect(targets.length).toBeGreaterThan(20);
    expect(targets.filter((t) => !isStepKey(t.key))).toEqual([]);
  });

  it("no step is navigated to or compared by number", () => {
    const numeric = files.flatMap(({ f, text }) => [...text.matchAll(/\bgoto\(\s*\d+\s*\)|\bstep\s*[!=]==\s*\d+/g)].map((m) => `${f}: ${m[0]}`));
    // ModelArmorSetup has its own numbered wizard (a local `step` state), not the app's steps.
    expect(numeric.filter((x) => !x.startsWith("steps/ModelArmorSetup.tsx"))).toEqual([]);
  });
});

describe("saved step", () => {
  const store = new Map<string, string>();
  const ls = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v), removeItem: (k: string) => void store.delete(k) };
  it("moves a saved step number (the order before the map) to its key", () => {
    Object.defineProperty(globalThis, "localStorage", { value: ls, configurable: true });
    store.set("studio.step", "6");
    expect(migrateSavedStep()).toBe("apply");
    expect(store.get("studio.step")).toBe('"apply"');
    expect(migrateSavedStep()).toBe("apply");
    store.set("studio.step", '"map"');
    expect(migrateSavedStep()).toBe("map");
    store.set("studio.step", "42");
    expect(migrateSavedStep()).toBeNull();
  });
});
