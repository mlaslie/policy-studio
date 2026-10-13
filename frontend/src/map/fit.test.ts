// Card text that fits its box (fit.ts): shrink, then ellipsis, never below the minimum size; chip short forms
// (labels.ts); and card heights that include the chip rows (layout.ts), all with a mocked measurer.
import { describe, expect, it } from "vitest";
import { FIT, fitText, type FitStyle, type Measure } from "./fit";
import type { Chip, PNode } from "./graph";
import { chipLabel } from "./labels";
import { CHIP_GAP, CHIP_H, chipShown, innerW, layoutView, nodeHeight, wrapRows } from "./layout";

/** Every character is half the font size wide. */
const half: Measure = (text, font) => text.length * Number(/([\d.]+)px/.exec(font)![1]) * 0.5;
const STYLE: FitStyle = { size: 15, min: 12, weight: 500 };

describe("fitText", () => {
  it("keeps the base size when the text fits", () => {
    expect(fitText("Helpdesk Agent", 200, STYLE, "end", half)).toEqual({ text: "Helpdesk Agent", size: 15, cut: false });
  });

  it("shrinks in 0.5px steps to the largest size that fits", () => {
    // 20 characters: 150px at 15px; 130px fits at 13px (130px), not at 13.5px (135px)
    expect(fitText("a".repeat(20), 130, STYLE, "end", half)).toEqual({ text: "a".repeat(20), size: 13, cut: false });
  });

  it("stops at the minimum size, then shortens with an ellipsis at the end", () => {
    const name = "acme-prod-helpdesk-orchestrator-eu"; // 34 characters: 204px at 12px
    const f = fitText(name, 120, STYLE, "end", half);
    expect(f.size).toBe(12);
    expect(f.cut).toBe(true);
    // 6px a character at 12px: 20 fit in 120px, the ellipsis one of them
    expect(f.text).toBe("acme-prod-helpdesk-…");
    expect(half(f.text, "500 12px x")).toBeLessThanOrEqual(120);
  });

  it("never goes below the minimum size", () => {
    for (const room of [10, 40, 80, 160]) expect(fitText("x".repeat(40), room, STYLE, "end", half).size).toBeGreaterThanOrEqual(STYLE.min);
  });

  it("shortens URLs and ids from the middle, and hosts as hosts (the shared domain first)", () => {
    const url = "tickets-mcp-a1b2c3-uk.a.run.app/mcp";
    const mid = fitText(url, 120, FIT.monoSub, "middle", half);
    expect(mid.text.startsWith("tickets")).toBe(true);
    expect(mid.text.endsWith("/mcp")).toBe(true);
    expect(mid.text).toContain("…");
    const host = fitText("iamcredentials.mtls.googleapis.com:443", 200, FIT.monoTitle, "host", half);
    expect(host.text).toMatch(/^iamcredentials\.mtls….*:443$/);
    expect(half(host.text, "600 11px x")).toBeLessThanOrEqual(200);
  });

  it("is deterministic", () => {
    const a = fitText("acme-prod-helpdesk-orchestrator-eu", 150, STYLE, "end", half);
    expect(fitText("acme-prod-helpdesk-orchestrator-eu", 150, STYLE, "end", half)).toEqual(a);
  });
});

describe("chipLabel", () => {
  it("shortens the inherited-grants count", () => {
    expect(chipLabel("+25 via group or registry-wide grants")).toBe("+25 inherited");
    expect(chipLabel("+1 via project-wide grant")).toBe("+1 inherited");
  });
  it("keeps other chips as they are", () => {
    for (const t of ["Agent Identity", "3 allowed", "Denied by default: 10", "Would be denied: 4"]) expect(chipLabel(t)).toBe(t);
  });
  it("shortens a chip that still doesn't fit the card, with an end ellipsis", () => {
    const long = { text: "A chip whose text is far too long for any card on the map", pending: false };
    const s = chipShown(long, "engine", half);
    expect(s.cut).toBe(true);
    expect(s.text.endsWith("…")).toBe(true);
    expect(half(s.text, "500 11.5px x") + 18).toBeLessThanOrEqual(innerW("engine"));
  });
});

describe("card heights include the chip rows", () => {
  const engine = (chips: string[]): PNode => ({
    id: `e:${chips.length}`,
    kind: "engine",
    label: "acme-prod-helpdesk-orchestrator-eu",
    sub: "7000328212139988",
    column: "callers",
    section: "nogw",
    chips: chips.map((text): Chip => ({ text, tone: "neutral" })),
    search: "",
  });

  it("wraps pills into rows within the width", () => {
    expect(wrapRows([], 100)).toBe(0);
    expect(wrapRows([40, 40], 100)).toBe(1); // 40 + 6 + 40
    expect(wrapRows([40, 40, 40], 100)).toBe(2);
    expect(wrapRows([500], 100)).toBe(1); // cut to the row
  });

  it("grows by a row of chips per wrapped row", () => {
    const none = nodeHeight(engine([]), false, half);
    const one = nodeHeight(engine(["Agent Identity"]), false, half);
    const four = nodeHeight(engine(["Agent Identity", "3 allowed", "+25 via group or registry-wide grants", "Denied by default: 10"]), false, half);
    expect(one - none).toBe(10 + CHIP_H);
    // 5.75px a character, 18px of padding, 218px rows: "Agent Identity" (98.5) and "3 allowed" (69.75) share row 1;
    // "+25 inherited" (92.75) starts row 2; "Denied by default: 10" (138.75) doesn't fit beside it: row 3
    const rows = wrapRows(["Agent Identity", "3 allowed", "+25 inherited", "Denied by default: 10"].map((t) => half(t, "500 11.5px x") + 18), innerW("engine"));
    expect(rows).toBe(3);
    expect(four - none).toBe(10 + rows * (CHIP_H + CHIP_GAP) - CHIP_GAP);
  });

  it("the layout spaces cards by those heights, so a card's chips never reach the next card", () => {
    const tall = engine(["Agent Identity", "3 allowed", "+25 via group or registry-wide grants", "Denied by default: 10"]);
    const short = { ...engine(["Agent Identity"]), id: "e:short", label: "b" };
    const l = layoutView({ nodes: [tall, short], edges: [] }, { measure: half });
    expect(l.size[tall.id].h).toBe(nodeHeight(tall, false, half));
    const [a, b] = [tall.id, short.id].sort((p, q) => l.pos[p].y - l.pos[q].y);
    expect(l.pos[b].y).toBeGreaterThanOrEqual(l.pos[a].y + l.size[a].h);
    // measured heights (React Flow) replace the estimates
    const m = layoutView({ nodes: [tall, short], edges: [] }, { measure: half, heights: { [tall.id]: 300 } });
    expect(m.size[tall.id].h).toBe(300);
  });
});
