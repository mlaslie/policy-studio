// Accessible hover/focus description for buttons. Wrap the button (works for disabled buttons too):
//   <Tip tip="Re-read everything from Google Cloud."><button …>Sync</button></Tip>
// Shows after ~300 ms on hover and immediately on keyboard focus, stays on-screen, Esc dismisses.
// The text is also rendered visually hidden and linked with aria-describedby, so screen readers read it.
import { cloneElement, isValidElement, useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ReactElement, type ReactNode } from "react";
import { createPortal } from "react-dom";

const DELAY = 300;
const GAP = 8;
const MARGIN = 8;

type ChildProps = { disabled?: boolean; "aria-describedby"?: string; title?: string };

export function Tip({ tip, children, block = false, className = "", placement = "top" }: { tip: ReactNode; children: ReactElement; block?: boolean; className?: string; placement?: "top" | "bottom" }) {
  const id = useId();
  const descId = `tip${id.replace(/:/g, "")}`;
  const wrap = useRef<HTMLSpanElement>(null);
  const bubble = useRef<HTMLDivElement>(null);
  const timer = useRef<number | undefined>(undefined);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number; side: "top" | "bottom" } | null>(null);

  const child = isValidElement<ChildProps>(children) ? children : null;
  const disabled = !!child?.props.disabled;

  const show = useCallback((delay: number) => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setOpen(true), delay);
  }, []);
  const hide = useCallback(() => {
    window.clearTimeout(timer.current);
    setOpen(false);
    setPos(null);
  }, []);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  // Esc dismisses; scrolling or resizing hides (the anchor moved).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") hide();
    };
    const onMove = () => hide();
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("resize", onMove);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("resize", onMove);
    };
  }, [open, hide]);

  // Position after the bubble renders so we know its size; flip and clamp to stay inside the viewport.
  useLayoutEffect(() => {
    if (!open || !wrap.current || !bubble.current) return;
    const a = wrap.current.getBoundingClientRect();
    const b = bubble.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    let side: "top" | "bottom" = placement;
    if (side === "top" && a.top - GAP - b.height < MARGIN) side = "bottom";
    else if (side === "bottom" && a.bottom + GAP + b.height > vh - MARGIN && a.top - GAP - b.height >= MARGIN) side = "top";
    const top = side === "top" ? a.top - GAP - b.height : a.bottom + GAP;
    const left = Math.min(Math.max(MARGIN, a.left + a.width / 2 - b.width / 2), vw - MARGIN - b.width);
    setPos((p) => (p && p.left === left && p.top === top && p.side === side ? p : { left, top, side }));
  }, [open, placement, tip]);

  if (!child) return <>{children}</>;
  const describedBy = [child.props["aria-describedby"], descId].filter(Boolean).join(" ");
  const inner = disabled ? child : cloneElement(child, { "aria-describedby": describedBy, title: undefined });

  return (
    <span
      ref={wrap}
      className={`tip-wrap ${block ? "tip-block" : ""} ${disabled ? "tip-disabled" : ""} ${className}`}
      onPointerEnter={(e) => e.pointerType !== "touch" && show(DELAY)}
      onPointerLeave={hide}
      onFocus={(e) => (e.target as HTMLElement).matches?.(":focus-visible") && show(0)}
      onBlur={hide}
      onPointerDown={hide}
      // A disabled button can't take focus, so the wrapper does, and carries the description.
      tabIndex={disabled ? 0 : undefined}
      aria-describedby={disabled ? descId : undefined}
    >
      {inner}
      <span id={descId} className="sr-only">
        {tip}
      </span>
      {open &&
        createPortal(
          <div ref={bubble} className={`tooltip tooltip-${pos?.side ?? placement}`} aria-hidden="true" style={pos ? { left: pos.left, top: pos.top } : { left: -9999, top: -9999, visibility: "hidden" }}>
            {tip}
          </div>,
          document.body,
        )}
    </span>
  );
}

/** Plain-English "why is this disabled" suffix. */
export const unavailable = (reason: string | null | undefined) => (reason ? ` Unavailable: ${reason}` : "");
