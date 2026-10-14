// The top bar's "Settling · ready ~15:34" chip (lib/settling.ts): shown while a recent apply may not be enforced yet,
// then "Should be in effect" for about a minute. Clicking it opens that apply's result. It re-renders at the next phase
// change and every 15 s while settling (for the countdown in its tooltip); the polite status region next to it says
// only the phase, never the countdown.
import { useEffect, useState } from "react";
import { useStudio } from "../store";
import { CheckIcon, ClockIcon } from "./Icons";
import { Tip } from "./Tooltip";
import { chipText, chipTip, nextSettleChange, phaseAnnouncement, settleSummary } from "../lib/settling";
import { clock } from "../lib/timing";

export function SettlingChip() {
  const { settling, showRun } = useStudio();
  const [now, setNow] = useState(() => Date.now());
  const s = settleSummary(settling, now);
  // A new apply (or a reload) reads the clock again.
  useEffect(() => setNow(Date.now()), [settling]);
  // One timer: the next phase change, or 15 s while settling (the countdown in the tooltip).
  useEffect(() => {
    const t0 = Date.now();
    const next = nextSettleChange(settling, t0);
    const wait = Math.min(next === null ? Infinity : next - t0 + 20, settleSummary(settling, t0).phase === "settling" ? 15_000 : Infinity);
    if (wait === Infinity) return;
    const t = setTimeout(() => setNow(Date.now()), wait);
    return () => clearTimeout(t);
  }, [settling, now]);

  const text = chipText(s);
  return (
    <>
      <span className="sr-only" role="status" aria-live="polite">
        {phaseAnnouncement(s)}
      </span>
      {text && s.newest && (
        <Tip
          placement="bottom"
          tip={
            <span className="settle-tip">
              {chipTip(s, now).map((l) => (
                <span key={l}>{l}</span>
              ))}
            </span>
          }
        >
          <button
            type="button"
            className={`settle-chip phase-${s.phase}`}
            onClick={() => showRun(s.newest!.runId)}
            aria-label={s.phase === "settling" ? `Settling, ready around ${clock(s.at)}. Open the apply result` : "Should be in effect. Open the apply result"}
          >
            {s.phase === "settling" ? <ClockIcon size={14} /> : <CheckIcon size={14} />}
            <span>{text}</span>
          </button>
        </Tip>
      )}
    </>
  );
}
