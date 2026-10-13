// The Build step's Add to cart preview as state transitions (pure; the builder holds the state). Add to cart opens the
// preview with the one change and its "also stage" fixes; then:
//   Approve  stage them (or replace the cart item being edited) and go to Review focused on the change, or, from "Add &
//            build another", stay in the builder for the next one (keeping who is calling).
//   Modify   close; back to the builder with every choice kept (Esc, the close button and a click outside do this too,
//            so no work is lost by accident).
//   Cancel   discard the pending change: close, keep the selection (who is calling and the destination), and put "how
//            much" back where it started for that pair (today's access in change mode, the default for a new grant);
//            the "also stage" fixes picked for it are dropped too.
import type { Intent } from "../api/types";
import type { BuildChoice } from "../lib/existing";

export interface PreviewOpen {
  intent: Intent;
  /** "Also stage fix" intents picked in the builder, staged with it on Approve. */
  extras: Intent[];
  /** Opened from "Add & build another". */
  another: boolean;
  /** Editing a cart item: Approve replaces it. */
  editId?: string;
}
export type PreviewState = PreviewOpen | null;

export type PreviewEffect =
  | { kind: "stage"; intents: Intent[]; replace?: { id: string; intent: Intent }; focus: string; another: boolean }
  | { kind: "keep" }
  | { kind: "reset"; choice: BuildChoice; clearExtras: true };

export const openPreview = (intent: Intent, extras: Intent[], another: boolean, editId?: string): PreviewOpen => ({ intent, extras, another, editId });

/** Approve: the intents to stage (fixes first, as the builder always did), or the edited item's replacement. */
export function approve(p: PreviewOpen, newId: () => string): { state: PreviewState; effect: PreviewEffect } {
  const id = p.editId ?? newId();
  const intent = { ...p.intent, id };
  return {
    state: null,
    effect: p.editId ? { kind: "stage", intents: p.extras, replace: { id: p.editId, intent }, focus: id, another: p.another } : { kind: "stage", intents: [...p.extras, intent], focus: id, another: p.another },
  };
}

/** Modify (also Esc): close, nothing changes. */
export const modify = (): { state: PreviewState; effect: PreviewEffect } => ({ state: null, effect: { kind: "keep" } });

/** Cancel: close and reset "how much" to `initial` (the pair's starting point), dropping the picked fixes. */
export const cancel = (initial: BuildChoice): { state: PreviewState; effect: PreviewEffect } => ({ state: null, effect: { kind: "reset", choice: { ...initial, tools: [...initial.tools] }, clearExtras: true } });
