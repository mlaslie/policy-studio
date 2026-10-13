// Apply step: Apply. Shows the plan (cart or the selected items) with a diff per item, asks for confirmation
// (type the project ID; acknowledge destructive changes), streams POST /apply progress, then offers Undo.
// In generate mode, or when credential checks fail, it explains why and points at the commands instead.
import { Tip, unavailable } from "../components/Tooltip";
import { useEffect, useMemo, useState } from "react";
import { useStudio } from "../store";
import { api } from "../api/client";
import type { DiffItem, Intent, PreflightItem } from "../api/types";
import { RedeployHelp } from "../components/Redeploy";
import { Badge, Callout, Disclosure, Spinner, StepHeader } from "../components/ui";
import { ArrowIcon, CheckIcon, ClockIcon, CloseIcon, CopyIcon, LockIcon, PlayIcon, RefreshIcon, WarnIcon } from "../components/Icons";
import { useApplyGate } from "../components/Mode";
import { CopyButton } from "../components/Glass";
import { KIND_LABEL, KIND_ORDER, intentEnglish } from "../lib/policy";
import { CHANGE_KIND, DESTRUCTIVE_PHRASE, MODIFY_STATUS, TYPICAL, fmtElapsed, isDestructive, isLongRunning, kindBlockedReason, sameChange, type ApplyRun, type RunItem } from "../lib/apply";
import { LocalSetup, projectMismatch } from "./CredentialsCard";
import { EffectLine, ReadyBanner, TimingNote } from "../components/Timing";
import { clock, effectText, effectWhy, readyWindow } from "../lib/timing";

const STATUS: Record<DiffItem["status"], { label: string; tone: "green" | "neutral" | "amber" | "red" }> = {
  add: { label: "Will add", tone: "green" },
  present: { label: "Already in place", tone: "neutral" },
  replace: { label: "Will replace", tone: "amber" },
  remove: { label: "Will remove", tone: "red" },
  absent: { label: "Nothing to remove", tone: "neutral" },
};
const KIND_TONE: Record<Intent["kind"], "green" | "red" | "blue" | "amber" | "purple"> = {
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

function useNow(active: boolean) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);
  return now;
}

// ---------------- plan ----------------

/** What to do about an item the preflight blocked. */
function BlockedFix({ p }: { p: PreflightItem }) {
  const { openMaSetup, goto } = useStudio();
  if (p.fix === "ma_setup")
    return (
      <Tip tip="Open the guided Model Armor setup: stage a template, an extension and the service agent roles, then come back to Apply. Nothing changes until you apply.">
        <button className="btn btn-small btn-primary" onClick={openMaSetup}>
          Set up Model Armor in this region <ArrowIcon size={13} />
        </button>
      </Tip>
    );
  if (p.fix === "redeploy") return <RedeployHelp />;
  if (p.fix === "permission")
    return (
      <Tip tip="Open Context to see which role you're missing and the command to grant it.">
        <button className="link-btn small" onClick={() => goto("context")}>
          See the missing permission on Context
        </button>
      </Tip>
    );
  return null;
}

function PlanRow({ intent, n, d, p }: { intent: Intent; n: number; d: DiffItem | undefined; p?: PreflightItem }) {
  const { auth } = useStudio();
  const denied = kindBlockedReason(auth.data, intent.kind);
  // A modify whose grant isn't there any more fails (the grant changed), it isn't skipped.
  const noop = d && (d.status === "present" || (d.status === "absent" && intent.kind !== "modify"));
  const blocked = p && p.status !== "ok";
  return (
    <li className={`plan-row ${noop || blocked ? "noop" : ""} ${blocked ? "blocked" : ""} ${isDestructive(intent) ? "destructive" : ""}`}>
      <span className="review-num">{n}</span>
      <div className="grow plan-main">
        <div className="plan-tags">
          <span className={`badge badge-${KIND_TONE[intent.kind]}`}>{KIND_LABEL[intent.kind]}</span>
          <span className="tiny muted">{CHANGE_KIND[intent.kind]}</span>
          {isDestructive(intent) && (
            <span className="badge badge-red" title="This change takes something away">
              <WarnIcon size={11} /> Destructive: {DESTRUCTIVE_PHRASE[intent.kind]}
            </span>
          )}
          {denied && (
            <span className="badge badge-amber" title={denied}>
              <LockIcon size={11} /> No permission
            </span>
          )}
          {p?.status === "blocked" && (
            <span className="badge badge-red">
              <LockIcon size={11} /> Blocked
            </span>
          )}
          {p?.status === "duplicate" && <span className="badge badge-neutral">Duplicate</span>}
        </div>
        <div className="plan-text">{intentEnglish(intent)}</div>
        {p?.status === "ok" && p.warning && (
          <div className="small warn-text">
            <WarnIcon size={12} /> {p.warning}
          </div>
        )}
        {blocked && (
          <div className="plan-blocked">
            <span className="small field-error">
              {p.status === "blocked" ? "Will certainly fail, so it's left out of this apply: " : p.status === "duplicate" ? "Left out: " : ""}
              {p.reason}
            </span>
            <BlockedFix p={p} />
          </div>
        )}
        {!d ? (
          <Spinner label="Comparing with the project…" />
        ) : d.error ? (
          <span className="small field-error">{d.error}</span>
        ) : (
          <span className="small muted">
            {d.detail}
            {noop && " Apply will skip it."}
          </span>
        )}
        {!noop && !blocked && (
          <span className="tiny muted effect-plan" title={effectWhy(intent.kind)}>
            <ClockIcon size={11} /> Takes effect {effectText(intent.kind)}.
          </span>
        )}
      </div>
      <div className="plan-side">
        {d && !d.error && <Badge tone={STATUS[d.status].tone}>{(intent.kind === "modify" && MODIFY_STATUS[d.status]) || STATUS[d.status].label}</Badge>}
        <span className="tiny muted" title="Typical time for Apply to make this kind of change">
          <ClockIcon size={11} /> {TYPICAL[intent.kind].label}
        </span>
      </div>
    </li>
  );
}

function ConfirmCard({ items, diff, blocked }: { items: Intent[]; diff: DiffItem[] | null; blocked: number }) {
  const { ctx, startApply, run, auth, openApply } = useStudio();
  const denied = items.filter((i) => kindBlockedReason(auth.data, i.kind));
  const other = projectMismatch(auth.data);
  const [typed, setTyped] = useState("");
  const [ack, setAck] = useState(false);
  const key = items.map((i) => i.id).join("|");
  useEffect(() => {
    setTyped("");
    setAck(false);
  }, [key, ctx.project]);
  const destructive = items.filter(isDestructive);
  const phrases = [...new Set(destructive.map((i) => DESTRUCTIVE_PHRASE[i.kind]!))];
  const invalid = diff?.filter((d) => d.error).length ?? 0;
  const lro = items.filter(isLongRunning).length;
  const match = typed.trim() === ctx.project;
  const busy = !!run && !run.done;
  const ready = match && (!destructive.length || ack) && !busy && items.length > 0 && !invalid && !denied.length;
  const why = !items.length
    ? "Nothing to apply."
    : denied.length
      ? `${denied.length} item${denied.length > 1 ? "s need" : " needs"} a permission you don't have.`
      : invalid
      ? `${invalid} item${invalid > 1 ? "s are" : " is"} invalid; fix or remove ${invalid > 1 ? "them" : "it"} first.`
      : !match
        ? "Type the project ID to confirm."
        : destructive.length && !ack
          ? "Tick the box to acknowledge the destructive changes."
          : busy
            ? "An apply is already running."
            : "";
  return (
    <form
      className="card confirm-card"
      onSubmit={(e) => {
        e.preventDefault();
        if (ready) void startApply(items, { project: ctx.project, acknowledge_destructive: destructive.length > 0 && ack });
      }}
    >
      <h3 className="card-title">Confirm</h3>
      <p className="small">
        Apply <b>{items.length} change{items.length > 1 ? "s" : ""}</b> to project <b className="mono">{ctx.project}</b> ({ctx.region}), in the order above. Each one is read back and verified.
        {blocked > 0 && (
          <>
            {" "}
            <b>{blocked} blocked</b> item{blocked > 1 ? "s are" : " is"} left out (see above); {blocked > 1 ? "they stay" : "it stays"} in the cart.
          </>
        )}
        {lro > 0 && <> {lro} of them {lro > 1 ? "are" : "is a"} long-running operation{lro > 1 ? "s" : ""} (binding an agent takes about 5 minutes, Model Armor about 4); you can keep using Policy Studio meanwhile.</>}
      </p>
      <TimingNote kinds={items.map((i) => i.kind)} />
      {denied.length > 0 && (
        <Callout tone="warn" title="You can't apply some of these changes">
          {kindBlockedReason(auth.data, denied[0].kind)} Get the role and click Check again on Context, or copy the commands for {denied.length > 1 ? "them" : "it"} from Review and run them with an account that can.{" "}
          {items.length > denied.length && (
            <Tip tip={`Limit this apply to the ${items.length - denied.length} change${items.length - denied.length > 1 ? "s" : ""} you have permission for, in ${ctx.project}. You'll confirm first; the rest stay in the cart.`}>
              <button type="button" className="link-btn" onClick={() => openApply(items.filter((i) => !denied.includes(i)).map((i) => i.id))}>
                Apply only the {items.length - denied.length} you can
              </button>
            </Tip>
          )}
        </Callout>
      )}
      {other && (
        <Callout tone="warn" title={<>You're signed in to <span className="mono">{other}</span> but working on <span className="mono">{ctx.project}</span></>}>
          Apply will target <b className="mono">{ctx.project}</b> explicitly. Make sure that's the project you mean.
        </Callout>
      )}
      <div className={`field ${typed && !match ? "has-error" : ""}`}>
        <label htmlFor="confirm-project">
          Type <span className="mono">{ctx.project}</span> to confirm
        </label>
        <input id="confirm-project" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={ctx.project} autoComplete="off" spellCheck={false} aria-describedby="confirm-help" />
        <div className="field-help" id="confirm-help">
          {typed && !match ? <span className="field-error">That doesn't match the project you're working on.</span> : "This guards against changing the wrong project."}
        </div>
      </div>
      {destructive.length > 0 && (
        <label className="ack">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>
            I understand this <b>{phrases.join(", ")}</b> ({destructive.length} item{destructive.length > 1 ? "s" : ""}).
          </span>
        </label>
      )}
      <div className="row">
        <Tip tip={`Make ${items.length > 1 ? "these changes" : "this change"} in ${ctx.project} now. Each one is read back and verified, and can be undone.${unavailable(why || null)}`}>
          <button type="submit" className={`btn ${destructive.length ? "btn-danger" : "btn-primary"}`} disabled={!ready}>
            <PlayIcon size={15} /> Apply {items.length} change{items.length > 1 ? "s" : ""}
          </button>
        </Tip>
        {why && <span className="muted small">{why}</span>}
      </div>
    </form>
  );
}

// ---------------- progress / results ----------------

function StateIcon({ s }: { s: RunItem["state"] }) {
  if (s === "verified") return <span className="dot dot-green" aria-label="Verified"><CheckIcon size={12} /></span>;
  if (s === "failed") return <span className="dot dot-red" aria-label="Failed"><CloseIcon size={12} /></span>;
  if (s === "skipped") return <span className="dot dot-grey" aria-label="Skipped">–</span>;
  if (s === "queued") return <span className="dot dot-grey" aria-label="Waiting"><ClockIcon size={11} /></span>;
  return <span className="spinner run-spinner" aria-label={s === "done" ? "Verifying" : "Running"} />;
}

const STATE_LABEL: Record<RunItem["state"], string> = {
  queued: "Waiting",
  running: "Applying",
  done: "Applied, verifying",
  verified: "Verified",
  failed: "Failed",
  skipped: "Skipped",
};

function RunRow({ it, now }: { it: RunItem; now: number }) {
  const live = it.state === "running" || it.state === "done";
  const elapsed = it.startedAt ? (it.endedAt ?? now) - it.startedAt : 0;
  const typ = TYPICAL[it.intent.kind];
  const pct = Math.min(95, (elapsed / 1000 / typ.seconds) * 100);
  return (
    <li className={`run-row state-${it.state}`}>
      <StateIcon s={it.state} />
      <div className="grow check-main">
        <span>{intentEnglish(it.intent)}</span>
        <span className={`small ${it.state === "failed" ? "field-error" : "muted"}`}>
          <b>{STATE_LABEL[it.state]}</b>
          {it.detail ? ` · ${it.detail}` : ""}
        </span>
        {it.state === "verified" && <EffectLine kind={it.intent.kind} />}
        {it.operation && <span className="mono tiny muted" title="Long-running operation">{it.operation}</span>}
        {it.rawError && (
          <Disclosure summary="Show the Google Cloud error">
            <pre className="mono tiny raw-error">{it.rawError}</pre>
          </Disclosure>
        )}
        {live && isLongRunning(it.intent) && (
          <div className="lro" aria-label={`Elapsed ${fmtElapsed(elapsed)}, usually ${typ.label}`}>
            <div className="lro-bar">
              <span style={{ width: `${pct}%` }} />
            </div>
            <span className="tiny muted">
              {fmtElapsed(elapsed)} elapsed · usually {typ.label}
            </span>
          </div>
        )}
      </div>
      {it.startedAt && !live && <span className="tiny muted">{fmtElapsed(elapsed)}</span>}
    </li>
  );
}

function counts(r: ApplyRun) {
  const c = { verified: 0, failed: 0, skipped: 0, pending: 0 };
  for (const i of r.items) {
    if (i.state === "verified") c.verified++;
    else if (i.state === "failed") c.failed++;
    else if (i.state === "skipped") c.skipped++;
    else c.pending++;
  }
  return c;
}

const verifiedKinds = (r: ApplyRun) => r.items.filter((i) => i.state === "verified").map((i) => i.intent.kind);

function UndoList({ run }: { run: ApplyRun }) {
  const { stageUndo, cart } = useStudio();
  const withUndo = run.items.filter((i) => i.undo.length);
  if (!withUndo.length) return null;
  // Undo in reverse order, so later changes are reverted first.
  const all = [...withUndo].reverse().flatMap((i) => i.undo);
  // An undo that is already in the cart (e.g. "enforce" staged again from Gateways) is the same change, not another one.
  const staged = (u: Intent) => cart.some((c) => sameChange(c, u));
  const fresh = all.filter((u) => !staged(u));
  return (
    <div className="card undo-card">
      <div className="card-title-row">
        <h3 className="card-title">
          <RefreshIcon size={15} /> Undo
        </h3>
        <span className="grow" />
        <Tip tip={`Stage the reverse of every applied change in the cart and open Apply. Nothing changes in Google Cloud until you confirm.${all.length > fresh.length ? ` ${all.length - fresh.length} of them ${all.length - fresh.length > 1 ? "are" : "is"} already in the cart and isn't staged twice.` : ""}`}>
          <button className="btn btn-tonal btn-small" onClick={() => stageUndo(all)}>
            {fresh.length ? `Undo all (${all.length})` : "Review the staged undo"}
          </button>
        </Tip>
      </div>
      <p className="small muted">Each applied change has an inverse. Undo stages it in the cart and opens Apply, so you confirm it like any other change.</p>
      <ul className="undo-list">
        {withUndo.map((i) => (
          <li key={i.intent.id}>
            <div className="grow">
              <div className="small muted">Applied: {intentEnglish(i.intent)}</div>
              {i.undo.map((u) => (
                <div key={u.id}>
                  <span className={`badge badge-${KIND_TONE[u.kind]}`}>{KIND_LABEL[u.kind]}</span> {intentEnglish(u)}
                  {staged(u) && (
                    <span className="badge badge-neutral undo-staged" title="The cart already has this change (staged after the apply); it's the same thing as this undo.">
                      <CheckIcon size={11} /> Already staged
                    </span>
                  )}
                  <span className="tiny muted effect-plan" title={effectWhy(u.kind)}>
                    <ClockIcon size={11} /> Takes effect {effectText(u.kind)}.
                  </span>
                </div>
              ))}
            </div>
            {i.undo.every(staged) ? (
              <Tip tip="This undo is already in the cart. Open Apply focused on it.">
                <button className="btn btn-text btn-small" onClick={() => stageUndo(i.undo)}>
                  Review staged
                </button>
              </Tip>
            ) : (
              <Tip tip="Stage the reverse of this change in the cart and open Apply. Nothing changes in Google Cloud until you confirm.">
                <button className="btn btn-outline btn-small" onClick={() => stageUndo(i.undo)}>
                  Undo this
                </button>
              </Tip>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function RunPanel({ run }: { run: ApplyRun }) {
  const { dismissRun, cancelApply, goto, syncing } = useStudio();
  const now = useNow(!run.done);
  const c = counts(run);
  const tone = !run.done ? "info" : run.error || c.failed ? (c.verified ? "warn" : "danger") : "ok";
  const summary = typeof run.summary === "string" ? run.summary : null;
  return (
    <>
      <div className="card run-card" aria-live="polite">
        <div className="card-title-row">
          <h3 className="card-title">{run.done ? "Apply finished" : "Applying…"}</h3>
          <span className="small muted">
            {run.project} · {run.region} · {fmtElapsed((run.endedAt ?? now) - run.startedAt)}
          </span>
          <span className="grow" />
          {!run.done && (
            <Tip tip="Stop following progress here. Operations already started keep running in Google Cloud; Sync later to see the result.">
              <button className="btn btn-text btn-small" onClick={cancelApply}>
                Stop watching
              </button>
            </Tip>
          )}
        </div>
        <ol className="run-list">
          {run.items.map((it) => (
            <RunRow key={it.intent.id} it={it} now={now} />
          ))}
        </ol>
      </div>
      {run.done && (
        <Callout
          tone={tone as "ok" | "warn" | "danger"}
          title={
            run.error && !c.verified
              ? "Apply didn't run"
              : `${c.verified} verified${c.failed ? `, ${c.failed} failed` : ""}${c.skipped ? `, ${c.skipped} skipped (no change needed)` : ""}`
          }
        >
          {run.error && <p className="mono small">{run.error}</p>}
          {summary && <p>{summary}</p>}
          {c.verified > 0 && (
            <p>
              {syncing ? "Syncing so Inventory, Audit and Gateways show the change…" : "Synced: Inventory, Audit and Gateways now show the change."} Verified and skipped items left the cart
              {c.failed ? "; failed items stay there so you can retry." : "."}
            </p>
          )}
          {!c.verified && c.failed > 0 && <p>Nothing was changed by the failed items. They stay in the cart so you can retry.</p>}
        </Callout>
      )}
      {run.done && <ReadyBanner kinds={verifiedKinds(run)} finishedAt={run.endedAt ?? now} />}
      {run.done && <UndoList run={run} />}
      {run.done && (
        <div className="row">
          <button className="btn btn-primary" onClick={dismissRun}>
            Back to the plan
          </button>
          <button className="btn btn-tonal" onClick={() => goto("audit")}>
            Open the audit <ArrowIcon size={16} />
          </button>
        </div>
      )}
    </>
  );
}

/** When a past apply's changes were expected to take effect. */
function HistoryReady({ r }: { r: ApplyRun }) {
  const w = r.endedAt ? readyWindow(verifiedKinds(r), r.endedAt) : null;
  if (!w) return null;
  return (
    <p className="tiny muted">
      <ClockIcon size={11} /> Expected in effect around {clock(w.at)}, by about {clock(w.latest)} at the latest.
    </p>
  );
}

function History() {
  const { history, stageUndo } = useStudio();
  if (!history.length) return null;
  return (
    <section className="card history-card" aria-label="Apply history">
      <h3 className="card-title">Apply history (this browser session)</h3>
      <ul className="history-list">
        {history.map((r) => {
          const c = counts(r);
          const undo = [...r.items].reverse().flatMap((i) => i.undo);
          return (
            <li key={r.id}>
              <Disclosure
                summary={
                  <span className="history-sum">
                    <span>{new Date(r.startedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
                    <span className="mono small">{r.project}</span>
                    {c.verified > 0 && <Badge tone="green">{c.verified} verified</Badge>}
                    {c.failed > 0 && <Badge tone="red">{c.failed} failed</Badge>}
                    {c.skipped > 0 && <Badge tone="neutral">{c.skipped} skipped</Badge>}
                    {r.error && !c.verified && <Badge tone="red">didn't run</Badge>}
                  </span>
                }
              >
                <ul className="history-items">
                  {r.items.map((it) => (
                    <li key={it.intent.id}>
                      <StateIcon s={it.state} />
                      <span className="small">
                        {intentEnglish(it.intent)} <span className="muted">· {STATE_LABEL[it.state]}</span>
                      </span>
                    </li>
                  ))}
                </ul>
                {r.error && <p className="small mono field-error">{r.error}</p>}
                <HistoryReady r={r} />
                {undo.length > 0 && (
                  <Tip tip="Stage the reverse of every change in this apply and open Apply. Nothing changes in Google Cloud until you confirm.">
                    <button className="btn btn-outline btn-small" onClick={() => stageUndo(undo)}>
                      Undo this apply ({undo.length})
                    </button>
                  </Tip>
                )}
              </Disclosure>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// ---------------- blocked / generate ----------------

function Unavailable() {
  const { goto, openReview, ctx, cart } = useStudio();
  const { auth, generate, reason } = useApplyGate();
  if (generate)
    return (
      <div className="card apply-card">
        <div className="row">
          <div className="apply-lock">
            <LockIcon size={24} />
          </div>
          <div className="grow">
            <h3>Apply is off here: generate-only mode</h3>
            <p className="small muted">This Policy Studio runs on Cloud Run with a service account, so it builds the commands and you run them with your own credentials. Nothing below changes your project.</p>
          </div>
        </div>
        <div className="row">
          <Tip tip={cart.length ? "Open Review & output, where Copy all and Download bundle give you every command to run yourself." : "The cart is empty."}>
            <button className="btn btn-primary" onClick={() => openReview(null)} disabled={!cart.length}>
              <CopyIcon size={15} /> Copy all commands
            </button>
          </Tip>
          <span className="muted small">Opens Review & output, with Copy all and Download bundle (Terraform, gcloud, REST, Python).</span>
        </div>
        <Disclosure summary={<span>Or run Policy Studio locally to apply from here</span>}>
          <LocalSetup project={ctx.project} compact />
        </Disclosure>
      </div>
    );
  const errors = auth?.checks.filter((c) => c.status === "error") ?? [];
  return (
    <Callout tone="warn" title="Apply is blocked">
      <p>{reason}</p>
      {errors.map((c) => (
        <div key={c.id} className="blocked-check">
          <b>{c.title}.</b> <span className="small">{c.detail}</span>
          {c.fix && (
            <div className="fix">
              <code>{c.fix}</code>
              <CopyButton compact className="mini-btn" ariaLabel={`Copy fix: ${c.fix}`} tip="Copy this fix command to the clipboard. Run it in your terminal, then Check again." getText={() => c.fix!} />
            </div>
          )}
        </div>
      ))}
      <p className="small">
        <button className="link-btn" onClick={() => goto("context")}>
          Open Credentials on the Context step
        </button>{" "}
        to see every check and copy the fixes. You can still <button className="link-btn" onClick={() => openReview(null)}>copy the commands</button> and run them yourself.
      </p>
    </Callout>
  );
}

// ---------------- step ----------------

export function ApplyStep() {
  const { cart, ctx, applyFocus, openApply, run, goto } = useStudio();
  const { canApply, loading } = useApplyGate();
  const sorted = useMemo(() => [...cart].sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind]), [cart]);
  const focused = applyFocus && !run ? sorted.filter((i) => applyFocus.includes(i.id)) : [];
  // While a finished apply is shown, cart items staged after it (not part of it) get their own plan + confirm above
  // it, so they can be applied without going "Back to the plan" first. Nothing is planned while an apply runs.
  const inRun = useMemo(() => new Set(run?.items.map((i) => i.intent.id) ?? []), [run]);
  const items = run ? (run.done ? sorted.filter((i) => !inRun.has(i.id)) : []) : focused.length ? focused : sorted;
  const [diff, setDiff] = useState<DiffItem[] | null>(null);
  const [diffErr, setDiffErr] = useState<string | null>(null);
  const [pre, setPre] = useState<PreflightItem[] | null>(null);
  const key = JSON.stringify([items, ctx]);

  useEffect(() => {
    setDiff(null);
    setDiffErr(null);
    setPre(null);
    if (!items.length) return;
    let live = true;
    api
      .diff(ctx, items)
      .then((d) => live && setDiff(d.items))
      .catch((e) => live && setDiffErr(e instanceof Error ? e.message : String(e)));
    // Preflight: items that would certainly fail (or repeat another) are left out of the run.
    api
      .preflight(ctx, items)
      .then((p) => {
        if (!live) return;
        // "Same change as <id>" -> "Same change as item N" (ids mean nothing to people).
        const pos = new Map(items.map((i, n) => [i.id, n + 1]));
        setPre(p.items.map((x) => (x.status === "duplicate" && x.duplicate_of && pos.has(x.duplicate_of) ? { ...x, reason: `Same change as item ${pos.get(x.duplicate_of)}; it's applied once.` } : x)));
      })
      .catch(() => live && setPre([]));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, run?.done]);

  const skip = new Set((pre ?? []).filter((x) => x.status !== "ok").map((x) => x.intent_id));
  const runnable = items.filter((i) => !skip.has(i.id));
  const blockedN = skip.size;

  const lead = canApply ? (
    <>Make the staged changes in <b className="mono">{ctx.project}</b> with your credentials. You confirm first; each change is read back and verified, and can be undone.</>
  ) : (
    <>Applying changes needs Policy Studio running locally with working credentials. You can always copy the commands and run them yourself.</>
  );

  const plan = (
    <>
      <section className="card plan-card" aria-label="Changes to apply">
        <div className="card-title-row">
          <h3 className="card-title">{run ? "Staged since this apply" : canApply ? "What will change" : "What would change"}</h3>
          <span className="small muted">
            {run ? `${items.length} new cart item${items.length > 1 ? "s" : ""}` : focused.length ? `${items.length} of ${sorted.length} cart items` : `${items.length} item${items.length > 1 ? "s" : ""} in the cart`}
          </span>
          <span className="grow" />
          {focused.length > 0 && sorted.length > focused.length && (
            <button className="link-btn small" onClick={() => openApply(null)}>
              Show the whole cart ({sorted.length})
            </button>
          )}
        </div>
        {diffErr && (
          <Callout tone="danger" title="Couldn't compare with the project">
            <span className="mono small">{diffErr}</span>
          </Callout>
        )}
        {blockedN > 0 && (
          <Callout tone="warn" title={`${blockedN} blocked`}>
            {blockedN > 1 ? "These items" : "This item"} would certainly fail (or repeat another one), so Apply leaves {blockedN > 1 ? "them" : "it"} out. Each one says why and how to fix it.
          </Callout>
        )}
        <ol className="plan-list">
          {items.map((i, n) => (
            <PlanRow key={i.id} intent={i} n={n + 1} d={diff?.find((d) => d.intent_id === i.id)} p={pre?.find((x) => x.intent_id === i.id)} />
          ))}
        </ol>
      </section>
      {canApply && (pre ? <ConfirmCard items={runnable} diff={diff} blocked={blockedN} /> : <Spinner label="Checking what can be applied…" />)}
    </>
  );

  return (
    <>
      <StepHeader title="Apply" lead={lead} />
      {run ? (
        <>
          {run.done && items.length > 0 && (
            <div className="staged-since" id="staged-since">
              <Callout tone="info" title={`${items.length} staged change${items.length > 1 ? "s" : ""} ready to apply`}>
                {items.length > 1 ? "These were" : "This was"} added to the cart after the apply below. Review and apply {items.length > 1 ? "them" : "it"} here; the finished apply and its Undo are further down.
              </Callout>
              {canApply ? plan : <Unavailable />}
            </div>
          )}
          <RunPanel run={run} />
        </>
      ) : (
        <>
          {!canApply && !loading && <Unavailable />}
          {loading && <Spinner label="Checking credentials…" />}
          {!items.length ? (
            <div className="card empty-card">
              <h3>Nothing to apply</h3>
              <p>Build a policy, or stage a fix from the audit, then come back here.</p>
              <div className="row center-row">
                <button className="btn btn-primary" onClick={() => goto("build")}>
                  Build a policy
                </button>
                <button className="btn btn-tonal" onClick={() => goto("audit")}>
                  Open the audit
                </button>
              </div>
            </div>
          ) : (
            plan
          )}
        </>
      )}
      <History />
    </>
  );
}
