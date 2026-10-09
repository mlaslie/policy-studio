// Run-mode badge (Generate-only / Apply enabled / Apply blocked) and a hook for "can I apply, and if not, why".
import { useStudio } from "../store";
import { applyBlockedReason, kindBlockedReason } from "../lib/apply";
import type { Intent } from "../api/types";
import { CheckIcon, CodeIcon, LockIcon, WarnIcon } from "./Icons";

export const GENERATE_TIP = "Running on Cloud Run with a service account: build and copy commands; apply them yourself";

export function useApplyGate() {
  const { auth } = useStudio();
  const a = auth.data;
  const reason = applyBlockedReason(a, auth.loading, auth.error);
  /** Reason these intents can't be applied (mode, credentials, or a kind the user can't write), or null. */
  const blockedFor = (items: Intent[]): string | null => {
    if (reason) return reason;
    for (const i of items) {
      const r = kindBlockedReason(a, i.kind);
      if (r) return r;
    }
    return null;
  };
  return { auth: a, canApply: !!a?.can_apply, reason, blockedFor, generate: a?.mode === "generate", loading: auth.loading && !a };
}

export function ModeBadge({ onClick }: { onClick?: () => void }) {
  const { auth, generate, reason, loading } = useApplyGate();
  let cls = "mode-badge mode-checking";
  let icon = <LockIcon size={13} />;
  let text = "Checking…";
  let tip = "Checking run mode and credentials…";
  if (auth) {
    if (generate) {
      cls = "mode-badge mode-generate";
      icon = <CodeIcon size={13} />;
      text = "Generate-only";
      tip = GENERATE_TIP;
    } else if (auth.can_apply) {
      cls = "mode-badge mode-apply";
      icon = <CheckIcon size={13} />;
      text = "Apply enabled";
      tip = `Running locally with your Application Default Credentials${auth.adc.account ? ` (${auth.adc.account})` : ""}. Apply targets ${auth.target_project} after you confirm.`;
    } else {
      cls = "mode-badge mode-blocked";
      icon = <WarnIcon size={13} />;
      text = "Apply blocked";
      tip = `Apply blocked: ${reason}`;
    }
  } else if (!loading && reason) {
    cls = "mode-badge mode-blocked";
    icon = <WarnIcon size={13} />;
    text = "Mode unknown";
    tip = reason;
  }
  const body = (
    <>
      {icon}
      <span>{text}</span>
    </>
  );
  return onClick ? (
    <button type="button" className={cls} title={`${tip}\n\nClick to see your credentials.`} aria-label={`${text}. ${tip}. Show credentials.`} onClick={onClick}>
      {body}
    </button>
  ) : (
    <span className={cls} title={tip}>
      {body}
    </span>
  );
}
