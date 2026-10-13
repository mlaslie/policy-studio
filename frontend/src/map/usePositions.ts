// Saved node positions (docs/VISUALIZATION_PLAN.md §7): only nodes you drag (or move with the arrow keys) are pinned,
// per project, region and direction, in localStorage. Auto layout places everything else. Pinned nodes keep their
// place across Sync and filter changes; ids no longer in the graph are dropped on load; Reset layout clears the key.
// Zoom and pan aren't saved. Every storage access is wrapped: private windows and disabled storage just don't pin.
import { useCallback, useEffect, useRef, useState } from "react";
import type { Direction } from "./graph";
import { GAP_Y, resolveOverlaps } from "./layout";

export type XY = { x: number; y: number };
export type Pins = Record<string, XY>;
/** The minimum of Storage that's used (a fake in tests). */
export type PinStore = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** Bumping the version (v1 → v2) drops every saved layout. */
export const posKey = (project: string, region: string, direction: Direction) => `studio.map.v1:${project}:${region}:${direction}`;
const SAVE_MS = 400;

const storage = (): PinStore | null => {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
};

/** The saved pins, without ids that aren't known any more (written back when some were dropped). */
export function loadPins(store: PinStore | null, key: string, known: (id: string) => boolean): Pins {
  if (!store) return {};
  try {
    const raw = JSON.parse(store.getItem(key) ?? "{}") as Record<string, unknown>;
    const out: Pins = {};
    let dropped = false;
    for (const [id, v] of Object.entries(raw ?? {})) {
      const p = v as Partial<XY> | null;
      if (known(id) && p && Number.isFinite(p.x) && Number.isFinite(p.y)) out[id] = { x: p.x!, y: p.y! };
      else dropped = true;
    }
    if (dropped) savePins(store, key, out);
    return out;
  } catch {
    return {};
  }
}

export function savePins(store: PinStore | null, key: string, pins: Pins) {
  if (!store) return;
  try {
    if (Object.keys(pins).length) store.setItem(key, JSON.stringify(pins));
    else store.removeItem(key);
  } catch {
    /* storage full or disabled: the pins live until reload */
  }
}

/** Layout positions with the pins on top (a pin wins; nodes without one take the auto layout). With `size`, auto
 *  placed nodes (and section titles) are then moved off the pinned ones, within their `column` (resolveOverlaps). */
export function placeNodes(auto: Record<string, XY>, pins: Pins, opts: { size?: Record<string, { w: number; h: number }>; column?: Record<string, string>; gap?: number } = {}): Record<string, XY> {
  const out: Record<string, XY> = {};
  for (const [id, p] of Object.entries(auto)) out[id] = pins[id] ?? p;
  const { size } = opts;
  if (!size) return out;
  const boxes = Object.entries(out).map(([id, p]) => ({ id, ...p, w: size[id]?.w ?? 0, h: size[id]?.h ?? 0, column: opts.column?.[id], pinned: !!pins[id] }));
  return resolveOverlaps(boxes, opts.gap ?? GAP_Y);
}

/** Pins for one map key. `known` decides which saved ids are still in the graph; `ready` = the graph is loaded. */
export function usePositions(key: string, known: (id: string) => boolean, ready: boolean) {
  const [pins, setPins] = useState<Pins>({});
  const pinsRef = useRef(pins);
  pinsRef.current = pins;
  const knownRef = useRef(known);
  knownRef.current = known;
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    if (!ready) return;
    setPins(loadPins(storage(), key, knownRef.current));
  }, [key, ready]);
  // A pending save is flushed when the key changes or the map closes.
  useEffect(
    () => () => {
      if (timer.current === undefined) return;
      clearTimeout(timer.current);
      timer.current = undefined;
      savePins(storage(), key, pinsRef.current);
    },
    [key],
  );

  const write = useCallback(
    (next: Pins, debounce: boolean) => {
      pinsRef.current = next;
      setPins(next);
      clearTimeout(timer.current);
      timer.current = undefined;
      if (!debounce) return savePins(storage(), key, next);
      timer.current = setTimeout(() => {
        timer.current = undefined;
        savePins(storage(), key, pinsRef.current);
      }, SAVE_MS);
    },
    [key],
  );
  /** Pin a node where it was dropped (debounced save). */
  const pin = useCallback((id: string, p: XY) => write({ ...pinsRef.current, [id]: { x: Math.round(p.x), y: Math.round(p.y) } }, true), [write]);
  /** Send one node back to auto layout. */
  const unpin = useCallback(
    (id: string) => {
      const { [id]: _drop, ...rest } = pinsRef.current;
      write(rest, false);
    },
    [write],
  );
  /** Reset layout: every node back to auto layout, the saved key cleared. */
  const reset = useCallback(() => write({}, false), [write]);
  return { pins, pin, unpin, reset };
}
