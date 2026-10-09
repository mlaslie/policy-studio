// "Liquid glass" modal sheet (portal, focus trap, Esc, animated open/close) and a copy-to-clipboard button.
import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { copyText } from "../lib/util";
import { CheckIcon, CloseIcon, CopyIcon } from "./Icons";
import { Tip } from "./Tooltip";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const CLOSE_MS = 180;

export function GlassModal(props: {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}) {
  const { onClose } = props;
  const panel = useRef<HTMLDivElement>(null);
  const [closing, setClosing] = useState(false);
  const titleId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  const closingRef = useRef(false);
  const requestClose = useCallback(() => {
    if (closingRef.current) return;
    closingRef.current = true;
    setClosing(true);
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    setTimeout(() => closeRef.current(), reduce ? 0 : CLOSE_MS);
  }, []);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    panel.current?.focus({ preventScroll: true });
    const onKey = (e: KeyboardEvent) => {
      const el = panel.current;
      if (!el) return;
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        requestClose();
        return;
      }
      if (e.key !== "Tab") return;
      const items = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null);
      if (!items.length) {
        e.preventDefault();
        el.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (!el.contains(active)) {
        e.preventDefault();
        first.focus();
      } else if (e.shiftKey && (active === first || active === el)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      if (prev && document.contains(prev)) prev.focus({ preventScroll: true });
    };
  }, [requestClose]);

  return createPortal(
    <div className={`glass-backdrop ${closing ? "closing" : ""}`} onMouseDown={(e) => e.target === e.currentTarget && requestClose()}>
      <div
        ref={panel}
        className={`glass glass-sheet ${props.className ?? ""} ${closing ? "closing" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="sheet-head">
          {props.icon && <span className="sheet-icon">{props.icon}</span>}
          <div className="sheet-titles">
            <h2 id={titleId}>{props.title}</h2>
            {props.subtitle && <div className="sheet-sub">{props.subtitle}</div>}
          </div>
          <div className="sheet-actions">
            {props.actions}
            <button className="glass-btn" onClick={requestClose} aria-label="Close expanded view" title="Close (Esc)">
              <CloseIcon size={16} />
              <span>Close</span>
            </button>
          </div>
        </div>
        <div className="sheet-body">{props.children}</div>
      </div>
    </div>,
    document.body,
  );
}

/** Button that copies `getText()` and shows "Copied" (or "Copy failed") feedback for a moment. */
export function CopyButton({ getText, label = "Copy", ariaLabel, className = "glass-btn", compact, tip }: { getText: () => string; label?: string; ariaLabel: string; className?: string; compact?: boolean; tip?: ReactNode }) {
  const [st, setSt] = useState<"idle" | "ok" | "fail">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const onClick = async () => {
    let ok = false;
    try {
      ok = await copyText(getText());
    } catch {
      ok = false;
    }
    setSt(ok ? "ok" : "fail");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setSt("idle"), 1800);
  };
  return (
    <Tip tip={tip ?? `${ariaLabel} to the clipboard.`}>
      <button className={`${className} ${st === "ok" ? "copied" : ""} ${st === "fail" ? "copy-failed" : ""}`} onClick={onClick} aria-label={ariaLabel}>
        {st === "ok" ? <CheckIcon size={15} /> : <CopyIcon size={15} />}
        {!compact || st !== "idle" ? <span aria-live="polite">{st === "ok" ? "Copied" : st === "fail" ? "Copy failed" : label}</span> : null}
      </button>
    </Tip>
  );
}
