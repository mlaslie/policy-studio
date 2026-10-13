// Fitting card text into its box (titles, subtitles, chips, skills): shrink the font down to a minimum, then shorten
// (end ellipsis for names, middle for hosts, labels.ts). Widths come from a text measurer: canvas measureText with the
// card's real font in the browser (cached per font and text, so a map of hundreds of cards stays fast), a character
// estimate where there's no canvas (tests). Pure apart from the measurer's cache; tests pass their own measurer.
import { middleEllipsis, shortLabel } from "./labels";

/** Width in px of `text` drawn in a CSS `font` (`500 15px "Google Sans", …`). */
export type Measure = (text: string, font: string) => number;

/** The card fonts (styles.css --font and --mono). */
export const SANS = `"Google Sans", "Google Sans Text", Inter, Roboto, system-ui, -apple-system, "Segoe UI", sans-serif`;
export const MONO = `"Google Sans Mono", "Roboto Mono", ui-monospace, SFMono-Regular, Menlo, monospace`;

/** A text style on a card: its size (px), the smallest it may shrink to, weight and family. */
export interface FitStyle {
  size: number;
  min: number;
  weight: number;
  mono?: boolean;
}

/** Titles shrink to 80% (12px); the 12px lines (subtitles, mono titles and ids) to 11px; chips and skills don't
 *  shrink (they're already small), they only shorten. Keep in step with styles.css (.node-title, .node-sub, .chip). */
export const FIT = {
  title: { size: 15, min: 12, weight: 500 },
  monoTitle: { size: 12, min: 11, weight: 600, mono: true },
  sub: { size: 12, min: 11, weight: 400 },
  monoSub: { size: 12, min: 11, weight: 400, mono: true },
  chip: { size: 11.5, min: 11.5, weight: 500 },
  skill: { size: 12, min: 12, weight: 400 },
} satisfies Record<string, FitStyle>;

export const fontOf = (s: FitStyle, size = s.size) => `${s.weight} ${size}px ${s.mono ? MONO : SANS}`;

/** How text is shortened once it's at its minimum size: from the end (names), from the middle (URLs and ids, so both
 *  ends show), or as a host (labels.ts shortLabel: the shared domain goes first, the service name and port stay). */
export type Cut = "end" | "middle" | "host";

export interface Fitted {
  /** What's drawn: the text, or shortened with an ellipsis. */
  text: string;
  /** Font size in px. */
  size: number;
  /** Shortened (the full text goes in the title and aria-label). */
  cut: boolean;
}

const endCut = (s: string, n: number) => (n >= s.length ? s : `${s.slice(0, Math.max(0, n - 1)).trimEnd()}…`);
const shorten = (s: string, n: number, cut: Cut) => (cut === "end" || n < 5 ? endCut(s, n) : cut === "host" ? shortLabel(s, n) : middleEllipsis(s, n));

/** Fit `text` into `room` px: the base size when it fits; else the largest size (in 0.5px steps, not below the
 *  minimum) at which it fits; else the minimum size, shortened to the most characters that fit. Deterministic. */
export function fitText(text: string, room: number, style: FitStyle, cut: Cut, measure: Measure = measureText): Fitted {
  const w = measure(text, fontOf(style));
  if (w <= room || !text) return { text, size: style.size, cut: false };
  // width grows with the font size: start from the proportional size and step down until it fits
  for (let s = Math.min(style.size - 0.5, Math.floor(((style.size * room) / w) * 2) / 2); s >= style.min; s -= 0.5)
    if (measure(text, fontOf(style, s)) <= room) return { text, size: s, cut: false };
  const font = fontOf(style, style.min);
  // the most characters whose shortened form fits (binary search; one character and the ellipsis at the least)
  let lo = 1;
  let hi = text.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measure(shorten(text, mid, cut), font) <= room) lo = mid;
    else hi = mid - 1;
  }
  return { text: shorten(text, lo, cut), size: style.min, cut: true };
}

// ---------- the measurer ----------

/** A character-width estimate (no canvas: tests, server). Monospace glyphs are 0.6em; proportional ones about 0.55em. */
export const estimateText: Measure = (text, font) => {
  const px = Number(/([\d.]+)px/.exec(font)?.[1] ?? 12);
  return text.length * px * (font.includes("Mono") ? 0.6 : 0.55);
};

let ctx: CanvasRenderingContext2D | null | undefined;
const cache = new Map<string, number>();
let epoch = 0;
const listeners = new Set<() => void>();

/** Canvas measureText with the given font, cached. Web fonts that finish loading later clear the cache (and bump
 *  fontEpoch, so cards and the layout fit again with the real glyphs). */
export const measureText: Measure = (text, font) => {
  const k = `${font}\n${text}`;
  const hit = cache.get(k);
  if (hit !== undefined) return hit;
  if (ctx === undefined) {
    ctx = null;
    try {
      if (typeof document !== "undefined" && typeof navigator !== "undefined" && !/jsdom/i.test(navigator.userAgent)) ctx = document.createElement("canvas").getContext("2d");
      const fonts = typeof document !== "undefined" ? document.fonts : undefined;
      fonts?.addEventListener?.("loadingdone", () => {
        cache.clear();
        epoch++;
        for (const l of listeners) l();
      });
    } catch {
      ctx = null;
    }
  }
  let w: number;
  if (ctx) {
    ctx.font = font;
    w = ctx.measureText(text).width;
  } else w = estimateText(text, font);
  cache.set(k, w);
  return w;
};

/** Bumped when web fonts finish loading (the measurer's cache was cleared). */
export const fontEpoch = () => epoch;
export function onFontEpoch(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}
