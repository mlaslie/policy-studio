// Review step: render the cart (or one item) as Terraform / gcloud / REST / Python with copy and download,
// plus a diff against the current state from POST /diff.
import { Tip, unavailable } from "../components/Tooltip";
import { useEffect, useMemo, useState } from "react";
import { useStudio } from "../store";
import { api } from "../api/client";
import type { Binding, DiffItem, Intent, Outputs, RenderResult } from "../api/types";
import { Badge, Callout, Spinner, StepHeader, Tabs } from "../components/ui";
import { CodeView, type Lang } from "../components/CodeView";
import { CopyButton } from "../components/Glass";
import { DownloadIcon, PencilIcon, PlusIcon, TrashIcon, WarnIcon, LockIcon } from "../components/Icons";
import { KIND_LABEL, KIND_ORDER, ROLE, conditionFor, intentEnglish, missingContext } from "../lib/policy";
import { downloadBlob, makeZip } from "../lib/zip";
import { useApplyGate } from "../components/Mode";
import { WarningCallouts } from "./ModelArmorSetup";
import { RedeployHelp } from "../components/Redeploy";
import { PlayIcon } from "../components/Icons";
import { DESTRUCTIVE_PHRASE, MODIFY_STATUS, isDestructive } from "../lib/apply";
import { ShowOnMap } from "../components/ShowOnMap";
import { focusForIntent } from "../map/focus";
import { TimingNote } from "../components/Timing";
import { timingNote } from "../lib/timing";

function ApplyButton({ ids, label, small }: { ids: string[] | null; label: string; small?: boolean }) {
  const { openApply, cart, ctx } = useStudio();
  const { blockedFor } = useApplyGate();
  const reason = blockedFor(ids ? cart.filter((i) => ids.includes(i.id)) : cart);
  const canApply = !reason;
  const what = ids?.length === 1 ? "this change" : "these changes";
  return (
    <Tip tip={`Make ${what} in ${ctx.project || "your project"} now. You'll confirm first.${unavailable(reason)}`}>
      <button className={`btn btn-outline ${small ? "btn-small" : ""}`} disabled={!canApply} aria-label={`${label}${canApply ? "" : ` (unavailable: ${reason})`}`} onClick={() => openApply(ids)}>
        {canApply ? <PlayIcon size={14} /> : <LockIcon size={14} />} {label}
      </button>
    </Tip>
  );
}

type Fmt = keyof Outputs;
const FMT: { id: Fmt; label: string; lang: Lang; file: string }[] = [
  { id: "terraform", label: "Terraform", lang: "hcl", file: "main.tf" },
  { id: "gcloud", label: "gcloud", lang: "shell", file: "apply.sh" },
  { id: "rest", label: "REST", lang: "shell", file: "rest.sh" },
  { id: "python", label: "Python", lang: "python", file: "apply.py" },
];

const STATUS: Record<DiffItem["status"], { label: string; tone: "green" | "neutral" | "amber" | "red" }> = {
  add: { label: "Will add", tone: "green" },
  present: { label: "Already present", tone: "neutral" },
  replace: { label: "Will replace", tone: "amber" },
  remove: { label: "Will remove", tone: "red" },
  absent: { label: "Nothing to remove", tone: "neutral" },
};

function resulting(intent: Intent, d: DiffItem): Binding[] | null {
  if (!d.current) return null;
  const member = intent.source?.principal;
  const others = d.current.filter((b) => b.member !== member);
  if (intent.kind === "revoke") return others;
  if (d.status === "present") return d.current;
  const cond = conditionFor(intent.access);
  const next: Binding = { role: ROLE, member: member ?? "", member_label: intent.source?.label ?? "", condition: cond, english: intentEnglish(intent) };
  return d.status === "replace" ? [...others, next] : [...d.current, next];
}

function BindingMini({ b, tone }: { b: Binding; tone?: "add" | "del" }) {
  return (
    <li className={`bmini ${tone ?? ""}`} title={`${b.member}\n${b.condition?.expression ?? "(no condition)"}`}>
      <span className="bmini-sign">{tone === "add" ? "+" : tone === "del" ? "−" : "·"}</span>
      <span>{b.english}</span>
    </li>
  );
}

function DiffColumn({ intent, d }: { intent: Intent; d: DiffItem | undefined }) {
  if (!d) return <div className="diff"><Spinner label="Comparing…" /></div>;
  const s = STATUS[d.status];
  const after = d.after !== undefined ? d.after : resulting(intent, d);
  const key = (b: Binding) => `${b.member}|${b.condition?.expression ?? ""}`;
  const beforeKeys = new Set((d.current ?? []).map(key));
  const afterKeys = new Set((after ?? []).map(key));
  return (
    <div className="diff" aria-label="Diff against current state">
      <div className="diff-head">
        <span className="muted small">Diff</span>
        <Badge tone={s.tone}>{(intent.kind === "modify" && MODIFY_STATUS[d.status]) || s.label}</Badge>
      </div>
      <p className="small">{d.detail}</p>
      {d.current && (
        <>
          <div className="diff-sub">Now ({d.current.length})</div>
          <ul className="bmini-list">
            {d.current.length ? d.current.map((b, i) => <BindingMini key={i} b={b} tone={afterKeys.has(key(b)) ? undefined : "del"} />) : <li className="muted small">No one</li>}
          </ul>
          {after && (
            <>
              <div className="diff-sub">After ({after.length})</div>
              <ul className="bmini-list">
                {after.length ? after.map((b, i) => <BindingMini key={i} b={b} tone={beforeKeys.has(key(b)) ? undefined : "add"} />) : <li className="muted small">No one</li>}
              </ul>
            </>
          )}
        </>
      )}
    </div>
  );
}

function ItemCard({ intent, idx, res, diff, fmt, setFmt }: { intent: Intent; idx: number; res: RenderResult | null; diff: DiffItem | undefined; fmt: Fmt; setFmt: (f: Fmt) => void }) {
  const { removeIntent, openBuilder, inventory } = useStudio();
  const item = res?.items.find((x) => x.intent_id === intent.id);
  const f = FMT.find((x) => x.id === fmt)!;
  return (
    <article className="card review-item" id={`item-${intent.id}`}>
      <header className="review-head">
        <span className="review-num">{idx + 1}</span>
        <div className="grow">
          <div className="small muted">
            {KIND_LABEL[intent.kind]}
            {isDestructive(intent) && (
              <>
                {" "}
                <Badge tone="red" title="This change takes something away; Apply asks you to acknowledge it.">
                  <WarnIcon size={11} /> Destructive: {DESTRUCTIVE_PHRASE[intent.kind]}
                </Badge>
              </>
            )}
          </div>
          <h3>{item?.english ?? intentEnglish(intent)}</h3>
        </div>
        <ShowOnMap focus={focusForIntent(intent, inventory.data)} what="this pending change" compact />
        {(intent.kind === "grant" || intent.kind === "revoke") && (
          <Tip tip="Open this item in the builder to change it. Saving replaces it in the cart.">
            <button className="icon-btn" aria-label="Edit in builder" onClick={() => openBuilder(intent, { editId: intent.id, mode: intent.kind === "revoke" ? "revoke" : "grant" })}>
              <PencilIcon size={15} />
            </button>
          </Tip>
        )}
        <Tip tip="Take this item out of the cart. Nothing in Google Cloud changes.">
          <button className="icon-btn danger" aria-label="Remove from cart" onClick={() => removeIntent(intent.id)}>
            <TrashIcon size={15} />
          </button>
        </Tip>
        <ApplyButton ids={[intent.id]} label="Apply" small />
      </header>
      {item?.error && (
        <Callout tone="danger" title="This item can't work as staged">
          {item.error}
          {/Agent Identity|can't be bound/.test(item.error) && <RedeployHelp reason={item.error} />}
        </Callout>
      )}
      <WarningCallouts warnings={item?.warnings} />
      <div className="review-body">
        <div className="review-code">
          <Tabs<Fmt> label="Output format" value={fmt} onChange={setFmt} items={FMT.map((x) => ({ id: x.id, label: x.label }))} />
          {item ? <CodeView code={item.outputs[fmt]} lang={f.lang} label={`${f.label} · item ${idx + 1}`} /> : <Spinner label="Rendering…" />}
        </div>
        <DiffColumn intent={intent} d={diff} />
      </div>
    </article>
  );
}

export function ReviewStep() {
  const { cart, ctx, reviewFocus, openReview, goto } = useStudio();
  const [fmt, setFmt] = useState<Fmt>("terraform");
  const [res, setRes] = useState<RenderResult | null>(null);
  const [diff, setDiff] = useState<DiffItem[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const sorted = useMemo(() => [...cart].sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind]), [cart]);
  const focus = reviewFocus && sorted.find((i) => i.id === reviewFocus) ? reviewFocus : null;
  const shown = focus ? sorted.filter((i) => i.id === focus) : sorted;
  const key = JSON.stringify([sorted, ctx]);

  useEffect(() => {
    if (!sorted.length) return;
    let live = true;
    setErr(null);
    Promise.all([api.render(ctx, sorted), api.diff(ctx, sorted)])
      .then(([r, d]) => {
        if (!live) return;
        setRes(r);
        setDiff(d.items);
      })
      .catch((e) => live && setErr(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const missing = missingContext(ctx, sorted);
  const allText = (f: Fmt) => {
    if (!res) return "";
    if (f === "terraform") return `# ---- main.tf\n${res.bundle.terraform["main.tf"]}\n# ---- variables.tf\n${res.bundle.terraform["variables.tf"]}`;
    return res.bundle[f];
  };
  const download = () => {
    if (!res) return;
    const readme = `Policy Studio bundle for project ${ctx.project}, region ${ctx.region}
Generated ${new Date().toISOString()}

${sorted.map((i, n) => `${n + 1}. ${intentEnglish(i)}`).join("\n")}

Pick one way to apply it (they do the same thing):
  Terraform:  terraform init && terraform apply
  gcloud:     bash apply.sh
  REST:       bash rest.sh        (needs curl and jq)
  Python:     python3 apply.py    (pip install google-cloud-iap google-cloud-network-security google-auth)

Run with credentials that can change IAM in ${ctx.project}.

${timingNote(sorted.map((i) => i.kind)).replace(/^After Apply: /, "After running it: ")}
`;
    const blob = makeZip([
      { name: "policy-studio/main.tf", content: res.bundle.terraform["main.tf"] },
      { name: "policy-studio/variables.tf", content: res.bundle.terraform["variables.tf"] },
      { name: "policy-studio/apply.sh", content: res.bundle.gcloud, executable: true },
      { name: "policy-studio/rest.sh", content: res.bundle.rest, executable: true },
      { name: "policy-studio/apply.py", content: res.bundle.python },
      { name: "policy-studio/README.txt", content: readme },
    ]);
    downloadBlob(blob, `policy-studio-${ctx.project || "bundle"}.zip`);
  };
  const counts = diff?.reduce<Record<string, number>>((m, d) => ((m[d.status] = (m[d.status] ?? 0) + 1), m), {});

  if (!cart.length)
    return (
      <>
        <StepHeader title="Review & output" lead="Your staged changes become ready-to-run Terraform, gcloud, REST and Python here." />
        <div className="card empty-card">
          <h3>The cart is empty</h3>
          <p>Build a policy, or stage a fix from the audit, then come back here for the commands.</p>
          <div className="row center-row">
            <button className="btn btn-primary" onClick={() => goto("build")}>
              <PlusIcon size={16} /> Build a policy
            </button>
            <button className="btn btn-tonal" onClick={() => goto("audit")}>
              Open the audit
            </button>
          </div>
        </div>
      </>
    );

  return (
    <>
      <StepHeader
        title="Review & output"
        lead={<>Each staged item as code you can run yourself. They all do the same thing; pick the format your team uses. The diff shows what would change compared with {ctx.project} now.</>}
      />
      <div className="review-bar card">
        <div className="review-summary">
          <b>{focus ? "1 item" : `${sorted.length} item${sorted.length > 1 ? "s" : ""}`}</b>
          {counts && !focus && (
            <span className="small">
              {Object.entries(counts).map(([k, n]) => (
                <Badge key={k} tone={STATUS[k as DiffItem["status"]].tone}>
                  {n} {STATUS[k as DiffItem["status"]].label.toLowerCase()}
                </Badge>
              ))}
            </span>
          )}
          {focus && (
            <button className="link-btn" onClick={() => openReview(null)}>
              Show all {sorted.length}
            </button>
          )}
        </div>
        <div className="row">
          <CopyButton
            className="btn btn-tonal"
            label={`Copy all (${FMT.find((x) => x.id === fmt)!.label})`}
            ariaLabel={`Copy all items as ${fmt}`}
            tip={`Copy every staged item as ${FMT.find((x) => x.id === fmt)!.label} to the clipboard, ready to run yourself.`}
            getText={() => allText(fmt)}
          />
          <Tip tip={res ? `Download a .zip with Terraform, gcloud, REST and Python versions of every staged item, plus a README. Nothing changes in ${ctx.project}.` : "Still rendering the cart…"}>
            <button className="btn btn-primary" onClick={download} disabled={!res}>
              <DownloadIcon size={16} /> Download bundle
            </button>
          </Tip>
          <ApplyButton ids={focus ? [focus] : null} label={focus ? "Apply this" : `Apply all ${sorted.length}`} />
        </div>
      </div>
      <TimingNote kinds={shown.map((i) => i.kind)} className="review-timing" />
      {missing.length > 0 && (
        <Callout tone="warn" title="Some context is missing">
          <ul className="plain-list">
            {missing.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
          <button className="link-btn" onClick={() => goto("context")}>
            Fill it in on the Context step
          </button>
          , outputs update automatically.
        </Callout>
      )}
      {err && (
        <Callout tone="danger" title="Couldn't render the cart">
          <span className="mono small">{err}</span>
        </Callout>
      )}
      <div className="review-list">
        {shown.map((i) => (
          <ItemCard key={i.id} intent={i} idx={sorted.indexOf(i)} res={res} diff={diff?.find((d) => d.intent_id === i.id)} fmt={fmt} setFmt={setFmt} />
        ))}
      </div>
      <p className="muted small">
        <WarnIcon size={13} /> Generated for <span className="mono">{ctx.project}</span> / <span className="mono">{ctx.region}</span>. Review before running. When a command finishes, the gateway may not enforce the change yet: see the timing note above.
      </p>
    </>
  );
}
