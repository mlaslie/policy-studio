// Pinned nodes and the auto layout (docs/VISUALIZATION_PLAN.md §7): auto-placed nodes and section titles move down
// their column off pinned nodes, the rest of the column keeps its order and spacing, and pinned nodes never move.
import { describe, expect, it } from "vitest";
import { freeSpot, resolveOverlaps, type Box } from "./layout";
import { placeNodes } from "./usePositions";

const GAP = 22;
const box = (id: string, y: number, extra: Partial<Box> = {}): Box => ({ id, x: 0, y, w: 240, h: 64, column: "gateways", pinned: false, ...extra });
const hit = (a: Box, b: Box) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
/** Every unpinned box clear of every pinned one, at the resolved positions. */
function clear(boxes: Box[], pos: Record<string, { x: number; y: number }>) {
  const at = boxes.map((b) => ({ ...b, ...pos[b.id] }));
  for (const a of at.filter((b) => !b.pinned)) for (const p of at.filter((b) => b.pinned)) expect(hit(a, p), `${a.id} on ${p.id}`).toBe(false);
}

describe("resolveOverlaps", () => {
  it("moves an auto node out from under a pinned one, past it plus the gap", () => {
    // the ingress gateway, pinned exactly on top of the "No ingress gateway" lane
    const boxes = [box("nogw", 100), box("gw", 100, { pinned: true, column: undefined })];
    const pos = resolveOverlaps(boxes, GAP);
    expect(pos.gw).toEqual({ x: 0, y: 100 });
    expect(pos.nogw).toEqual({ x: 0, y: 100 + 64 + GAP });
    clear(boxes, pos);
  });

  it("shifts the rest of the column by the same amount, in the same order", () => {
    const boxes = [box("a", 0), box("b", 86), box("c", 172), box("d", 258), box("pin", 60, { pinned: true, x: 100 })];
    const pos = resolveOverlaps(boxes, GAP);
    expect(pos.a).toEqual({ x: 0, y: 60 + 64 + GAP });
    const d = pos.a.y - 0;
    expect([pos.b.y, pos.c.y, pos.d.y]).toEqual([86 + d, 172 + d, 258 + d]);
    clear(boxes, pos);
  });

  it("leaves nodes above the pinned one, and other columns, where they were", () => {
    const boxes = [box("a", 0), box("b", 86), box("other", 86, { x: 400, column: "dests" }), box("pin", 100, { pinned: true })];
    const pos = resolveOverlaps(boxes, GAP);
    expect(pos.a).toEqual({ x: 0, y: 0 });
    expect(pos.other).toEqual({ x: 400, y: 86 });
    expect(pos.b.y).toBe(100 + 64 + GAP);
  });

  it("never moves pinned nodes, even when they overlap each other", () => {
    const pins = [box("p1", 10, { pinned: true }), box("p2", 30, { pinned: true }), box("p3", 500, { pinned: true, x: 999 })];
    const pos = resolveOverlaps([...pins, box("a", 0), box("b", 40)], GAP);
    for (const p of pins) expect(pos[p.id]).toEqual({ x: p.x, y: p.y });
  });

  it("clears a chain of pinned nodes, and section titles move with their column", () => {
    // pushed past p1 lands on p2, then on p3; the title and the node under it follow
    const boxes = [
      box("hdr", -30, { h: 26, w: 300 }),
      box("a", 0),
      box("b", 86),
      box("p1", -20, { pinned: true }),
      box("p2", 60, { pinned: true, x: 120 }),
      box("p3", 150, { pinned: true, x: -100 }),
    ];
    const pos = resolveOverlaps(boxes, GAP);
    clear(boxes, pos);
    expect(pos.hdr.y).toBe(150 + 64 + GAP);
    expect(pos.a.y - pos.hdr.y).toBe(30);
    expect(pos.b.y - pos.a.y).toBe(86);
    expect(pos.b.y).toBeGreaterThan(pos.a.y);
  });

  it("is deterministic, whatever order the boxes come in", () => {
    const boxes = [box("x", 0), box("y", 0, { x: 300 }), box("z", 86), box("w", 172, { column: "dests", x: 600 }), box("p", 50, { pinned: true, w: 900 }), box("q", 260, { pinned: true, x: 500 })];
    const a = resolveOverlaps(boxes, GAP);
    expect(resolveOverlaps([...boxes].reverse(), GAP)).toEqual(a);
    expect(resolveOverlaps(boxes, GAP)).toEqual(a);
    clear(boxes, a);
  });
});

describe("dropping a node onto another", () => {
  it("onto an auto node: the drop stays, the auto node makes way", () => {
    const size = { a: { w: 240, h: 64 }, b: { w: 240, h: 64 } };
    const column = { a: "gateways", b: "gateways" };
    // b is dropped where a sits
    const pos = placeNodes({ a: { x: 0, y: 0 }, b: { x: 0, y: 200 } }, { b: { x: 0, y: 10 } }, { size, column });
    expect(pos.b).toEqual({ x: 0, y: 10 });
    expect(pos.a).toEqual({ x: 0, y: 10 + 64 + GAP });
  });

  it("onto a pinned node: the drop slides to the nearest free spot below", () => {
    const others = [box("p", 100, { pinned: true }), box("q", 100 + 64 + 10, { pinned: true }), box("auto", 400)];
    // lands on p; just below p is q, so it goes below q; the unpinned node doesn't count
    expect(freeSpot({ id: "d", x: 20, y: 120, w: 240, h: 64 }, others, GAP)).toEqual({ x: 20, y: 174 + 64 + GAP });
    // on a free spot it stays where it was dropped, and its own old pin doesn't count
    expect(freeSpot({ id: "p", x: 0, y: 105, w: 240, h: 64 }, [box("p", 100, { pinned: true })], GAP)).toEqual({ x: 0, y: 105 });
    expect(freeSpot({ id: "d", x: 600, y: 120, w: 240, h: 64 }, others, GAP)).toEqual({ x: 600, y: 120 });
  });
});
