// Policy cart: a top-bar button (count badge, pulse on add, destructive dot) that opens a liquid-glass
// popover with the staged intents in plain English, edit / duplicate / remove, "Review all", "Apply"
// and "Clear cart".
import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type RefObject } from "react";
import { useStudio } from "../store";
import { KIND_LABEL, KIND_ORDER, intentEnglish } from "../lib/policy";
import { isDestructive } from "../lib/apply";
import { useApplyGate } from "../components/Mode";
import { Tip, unavailable } from "../components/Tooltip";
import { CartIcon, CloseIcon, DuplicateIcon, PencilIcon, PlayIcon, TrashIcon, ArrowIcon } from "../components/Icons";
import type { Intent } from "../api/types";

const TONE: Record<Intent["kind"], string> = {
  grant: "green",
  revoke: "red",
  modify: "amber",
  bind_gateway: "blue",
  unbind_gateway: "amber",
  model_armor_on: "purple",
  model_armor_off: "amber",
  model_armor_template: "purple",
  model_armor_extension: "purple",
  iam_project_grant: "purple",
  set_enforcement: "amber",
  dedicate_extension: "blue",
};

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function CartButton() {
  const { cart } = useStudio();
  const [open, setOpen] = useState(false);
  const [pulse, setPulse] = useState(0);
  const btn = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const prevLen = useRef(cart.length);
  const panelId = useId();
  const destructive = cart.some(isDestructive);

  // Pulse the button whenever something is added.
  useEffect(() => {
    if (cart.length > prevLen.current) setPulse((p) => p + 1);
    prevLen.current = cart.length;
  }, [cart.length]);

  const close = useCallback((returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) requestAnimationFrame(() => btn.current?.focus({ preventScroll: true }));
  }, []);

  useEffect(() => {
    if (!open) return;
    requestAnimationFrame(() => {
      const first = panel.current?.querySelector<HTMLElement>(FOCUSABLE);
      (first ?? panel.current)?.focus({ preventScroll: true });
    });
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (panel.current?.contains(t) || btn.current?.contains(t)) return;
      // Clicks inside a tooltip bubble or a modal opened from here don't count as "outside".
      if ((t as HTMLElement).closest?.(".tooltip, .glass-backdrop")) return;
      close(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || document.querySelector(".glass-backdrop")) return;
      e.preventDefault();
      close(true);
    };
    document.addEventListener("mousedown", onDown, true);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown, true);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);

  const label = `Policy cart, ${cart.length} staged item${cart.length === 1 ? "" : "s"}${destructive ? ", includes destructive changes" : ""}`;
  return (
    <div className="cart-anchor">
      <Tip tip="Open the policy cart: the changes you've staged. Nothing changes in Google Cloud until you apply." placement="bottom">
        <button
          ref={btn}
          type="button"
          className={`cart-btn ${open ? "open" : ""} ${cart.length ? "has-items" : ""}`}
          aria-haspopup="dialog"
          aria-expanded={open}
          aria-controls={open ? panelId : undefined}
          aria-label={label}
          onClick={() => (open ? close(true) : setOpen(true))}
        >
          <CartIcon size={16} />
          <span>Cart</span>
          <span key={pulse} className={`cart-btn-count ${pulse ? "pulse" : ""}`}>
            {cart.length}
          </span>
          {destructive && <span className="cart-btn-dot" aria-hidden="true" />}
        </button>
      </Tip>
      {open && <CartPopover id={panelId} panelRef={panel} onClose={close} />}
    </div>
  );
}

function CartPopover({ id, panelRef, onClose }: { id: string; panelRef: RefObject<HTMLDivElement | null>; onClose: (returnFocus: boolean) => void }) {
  const { cart, ctx, removeIntent, duplicateIntent, openBuilder, openReview, openApply, clearCart, reviewFocus, step } = useStudio();
  const gate = useApplyGate();
  const [confirmClear, setConfirmClear] = useState(false);
  const sorted = [...cart].sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind]);
  const blocked = cart.length ? gate.blockedFor(cart) : "The cart is empty.";
  const nDestructive = cart.filter(isDestructive).length;
  const titleId = `${id}-title`;
  const project = ctx.project || "your project";

  // Keep keyboard focus inside the popover while it's open (Tab wraps).
  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key !== "Tab" || !panelRef.current) return;
    const items = Array.from(panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === panelRef.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div ref={panelRef} id={id} className="glass cart-pop" role="dialog" aria-labelledby={titleId} tabIndex={-1} onKeyDown={onKeyDown}>
      <div className="cart-pop-head">
        <CartIcon size={16} />
        <h2 id={titleId} className="cart-pop-title">
          Policy cart
        </h2>
        <span className="cart-count" aria-hidden="true">
          {cart.length}
        </span>
        {nDestructive > 0 && (
          <span className="badge badge-red">
            {nDestructive} destructive
          </span>
        )}
        <button type="button" className="icon-btn cart-pop-close" aria-label="Close policy cart" onClick={() => onClose(true)}>
          <CloseIcon size={16} />
        </button>
      </div>
      {cart.length === 0 ? (
        <div className="cart-empty">
          <p>Nothing staged yet.</p>
          <p className="muted small">Build a policy, or use “Stage fix” in the audit. Staging changes nothing in your project: you copy the commands, or Apply them after confirming.</p>
        </div>
      ) : (
        <>
          <ol className="cart-list">
            {sorted.map((i) => (
              <li key={i.id} className={`cart-item ${step === "review" && reviewFocus === i.id ? "focused" : ""}`}>
                <Tip tip="Open this item in Review & output to see its commands and diff." block className="grow">
                  <button
                    type="button"
                    className="cart-main"
                    onClick={() => {
                      openReview(i.id);
                      onClose(false);
                    }}
                  >
                    <span className={`badge badge-${TONE[i.kind]}`}>{KIND_LABEL[i.kind]}</span>
                    <span className="cart-text">{intentEnglish(i)}</span>
                  </button>
                </Tip>
                <div className="cart-actions">
                  {(i.kind === "grant" || i.kind === "revoke") && (
                    <Tip tip="Open this item in the builder to change it. Saving replaces it in the cart.">
                      <button
                        type="button"
                        className="icon-btn"
                        aria-label="Edit in builder"
                        onClick={() => {
                          openBuilder(i, { editId: i.id, mode: i.kind === "revoke" ? "revoke" : "grant" });
                          onClose(false);
                        }}
                      >
                        <PencilIcon size={14} />
                      </button>
                    </Tip>
                  )}
                  <Tip tip="Add a copy of this item to the cart, right below it.">
                    <button type="button" className="icon-btn" aria-label="Duplicate" onClick={() => duplicateIntent(i.id)}>
                      <DuplicateIcon size={14} />
                    </button>
                  </Tip>
                  <Tip tip="Take this item out of the cart. Nothing in Google Cloud changes.">
                    <button type="button" className="icon-btn danger" aria-label="Remove from cart" onClick={() => removeIntent(i.id)}>
                      <TrashIcon size={14} />
                    </button>
                  </Tip>
                </div>
              </li>
            ))}
          </ol>
          <div className="cart-pop-actions">
            <Tip tip="See every staged item as Terraform, gcloud, REST and Python, with a diff against the project." block className="grow">
              <button
                type="button"
                className="btn btn-tonal btn-block"
                onClick={() => {
                  openReview(null);
                  onClose(false);
                }}
              >
                Review all <ArrowIcon size={16} />
              </button>
            </Tip>
            <Tip tip={`Make these changes in ${project} now. You'll confirm first.${unavailable(blocked)}`} block className="grow">
              <button
                type="button"
                className={`btn btn-block ${nDestructive ? "btn-danger" : "btn-primary"}`}
                disabled={!!blocked}
                aria-label={`Apply ${cart.length} item${cart.length === 1 ? "" : "s"}${blocked ? ` (unavailable: ${blocked})` : ""}`}
                onClick={() => {
                  openApply(null);
                  onClose(false);
                }}
              >
                <PlayIcon size={15} /> Apply
              </button>
            </Tip>
          </div>
          <div className="cart-pop-foot">
            {confirmClear ? (
              <div className="cart-confirm" role="group" aria-label="Confirm clearing the cart">
                <span className="small">Remove all {cart.length} staged item{cart.length === 1 ? "" : "s"}?</span>
                <button type="button" className="btn btn-text btn-small" onClick={() => setConfirmClear(false)} autoFocus>
                  Cancel
                </button>
                <Tip tip="Empty the cart. Nothing in Google Cloud changes.">
                  <button
                    type="button"
                    className="btn btn-danger btn-small"
                    onClick={() => {
                      clearCart();
                      setConfirmClear(false);
                      panelRef.current?.focus({ preventScroll: true });
                    }}
                  >
                    Clear cart
                  </button>
                </Tip>
              </div>
            ) : (
              <Tip tip="Remove every staged item from the cart (you'll confirm). Nothing in Google Cloud changes.">
                <button type="button" className="link-btn small danger-link" onClick={() => setConfirmClear(true)}>
                  <TrashIcon size={13} /> Clear cart
                </button>
              </Tip>
            )}
          </div>
        </>
      )}
    </div>
  );
}
