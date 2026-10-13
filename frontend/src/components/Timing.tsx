// How long changes take to take effect (lib/timing.ts): the compact note before applying, the "Stored. Takes effect …"
// line of a verified item, and the "Ready to test around HH:MM" banner after an apply.
import { useEffect, useState } from "react";
import type { Intent } from "../api/types";
import { CheckIcon, ClockIcon } from "./Icons";
import { Callout } from "./ui";
import { KIND_LABEL } from "../lib/policy";
import { TIMING, clock, effectText, effectWhy, readyPhase, readyWindow, storedText, timeLeft, timingNote, timingSentence, type Kind } from "../lib/timing";

/** "After Apply: IAM grants usually take effect within a few minutes (up to about 7); …. Wait before testing." */
export function TimingNote({ kinds, className = "" }: { kinds: Kind[]; className?: string }) {
  const text = timingNote(kinds);
  if (!text) return null;
  return (
    <p className={`timing-note small ${className}`}>
      <ClockIcon size={13} /> <span>{text}</span>
    </p>
  );
}

/** "Stored. Takes effect …" under a verified item, with what happens in between. */
export function EffectLine({ kind }: { kind: Kind }) {
  return (
    <span className="effect-line small">
      <ClockIcon size={11} /> <b>{storedText(kind)}</b> <span className="muted">{TIMING[kind].between}</span>
    </span>
  );
}

function useTick(active: boolean, ms: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [active, ms]);
  return now;
}

/** After an apply: "Ready to test around HH:MM" (finish + the largest typical time among the verified items, and the
 *  latest expected time), then "Should be in effect now". The phase change is announced politely; the minutes-left
 *  countdown isn't (it would repeat), the times are in the title. Nothing here blocks anything else. */
export function ReadyBanner({ kinds, finishedAt }: { kinds: Intent["kind"][]; finishedAt: number }) {
  const w = readyWindow(kinds, finishedAt);
  const now = useTick(!!w && Date.now() < w.latest, 5_000);
  if (!w) return null;
  const phase = readyPhase(w, now);
  const distinct = [...new Set(kinds)];
  const title =
    phase === "waiting" ? (
      <>
        Ready to test around {clock(w.at)} <span className="muted">(latest about {clock(w.latest)})</span>
      </>
    ) : (
      "Should be in effect now"
    );
  return (
    <div className="ready-banner" role="status" aria-live="polite">
      <Callout tone={phase === "waiting" ? "info" : "ok"} icon={phase === "waiting" ? <ClockIcon size={18} /> : <CheckIcon size={18} />} title={title}>
        {phase === "waiting" && (
          <p>
            Verified means stored, not yet enforced by the gateway. {timingSentence(w.slowest)}{" "}
            <span className="ready-left" aria-hidden="true">
              {timeLeft(w.at - now)}
            </span>
          </p>
        )}
        {phase === "likely" && <p>Changes like these are usually in effect by now. If a test still fails, wait until about {clock(w.latest)} before looking for another cause.</p>}
        {phase === "done" && <p>Past the latest expected time ({clock(w.latest)}). If a test still fails, it isn't the wait: Sync and check the change.</p>}
        {distinct.length > 1 && (
          <ul className="ready-kinds tiny muted">
            {distinct.map((k) => (
              <li key={k} title={effectWhy(k)}>
                {KIND_LABEL[k]}: {effectText(k)}
              </li>
            ))}
          </ul>
        )}
      </Callout>
    </div>
  );
}
