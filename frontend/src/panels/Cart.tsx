// Policy cart: staged intents in plain English, with edit / duplicate / remove and "Review all".
import { useStudio } from "../store";
import { KIND_LABEL, KIND_ORDER, intentEnglish } from "../lib/policy";
import { CartIcon, DuplicateIcon, PencilIcon, TrashIcon, ArrowIcon } from "../components/Icons";
import type { Intent } from "../api/types";

const TONE: Record<Intent["kind"], string> = {
  grant: "green",
  revoke: "red",
  bind_gateway: "blue",
  unbind_gateway: "amber",
  model_armor_on: "purple",
  model_armor_off: "amber",
};

export function CartPanel() {
  const { cart, removeIntent, duplicateIntent, openBuilder, openReview, clearCart, reviewFocus, step } = useStudio();
  const sorted = [...cart].sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind]);
  return (
    <section className="cart" aria-label="Policy cart">
      <div className="rail-head static">
        <CartIcon size={16} />
        <span className="rail-title">Policy cart</span>
        <span className="cart-count" aria-label={`${cart.length} staged`}>
          {cart.length}
        </span>
        {cart.length > 0 && (
          <button className="link-btn" onClick={() => confirm("Remove every staged item?") && clearCart()}>
            Clear
          </button>
        )}
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
              <li key={i.id} className={`cart-item ${step === 5 && reviewFocus === i.id ? "focused" : ""}`}>
                <button className="cart-main" onClick={() => openReview(i.id)} title="Review this item">
                  <span className={`badge badge-${TONE[i.kind]}`}>{KIND_LABEL[i.kind]}</span>
                  <span className="cart-text">{intentEnglish(i)}</span>
                </button>
                <div className="cart-actions">
                  {(i.kind === "grant" || i.kind === "revoke") && (
                    <button className="icon-btn" aria-label="Edit in builder" title="Edit in builder" onClick={() => openBuilder(i, { editId: i.id, mode: i.kind === "revoke" ? "revoke" : "grant" })}>
                      <PencilIcon size={14} />
                    </button>
                  )}
                  <button className="icon-btn" aria-label="Duplicate" title="Duplicate" onClick={() => duplicateIntent(i.id)}>
                    <DuplicateIcon size={14} />
                  </button>
                  <button className="icon-btn danger" aria-label="Remove from cart" title="Remove" onClick={() => removeIntent(i.id)}>
                    <TrashIcon size={14} />
                  </button>
                </div>
              </li>
            ))}
          </ol>
          <button className="btn btn-primary btn-block" onClick={() => openReview(null)}>
            Review all <ArrowIcon size={16} />
          </button>
        </>
      )}
    </section>
  );
}
