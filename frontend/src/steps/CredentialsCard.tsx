// Context step: the Credentials card (GET /auth): run mode, where credentials come from, checks with fixes,
// a project-mismatch warning, and in generate mode how to run Policy Studio locally to apply.
import { Tip } from "../components/Tooltip";
import { useMemo } from "react";
import { useStudio } from "../store";
import type { AuthCheck, AuthInfo } from "../api/types";
import { Callout, Spinner } from "../components/ui";
import { CopyButton } from "../components/Glass";
import { CheckIcon, CloseIcon, RefreshIcon, WarnIcon } from "../components/Icons";
import { FixCheck, FixToolbar, useFixSelection, type FixRow } from "../components/FixSelect";
import { GENERATE_TIP, ModeBadge } from "../components/Mode";

const ADC_TYPE: Record<AuthInfo["adc"]["type"], string> = {
  user: "Your user account",
  service_account: "Service account key",
  impersonated: "Impersonated service account",
  external_account: "Workload identity federation",
  compute_engine: "Attached service account (metadata server)",
  unknown: "Unknown",
};

function CheckDot({ s }: { s: AuthCheck["status"] }) {
  if (s === "ok") return <span className="dot dot-green" aria-label="OK"><CheckIcon size={12} /></span>;
  if (s === "error") return <span className="dot dot-red" aria-label="Error"><CloseIcon size={12} /></span>;
  return <span className="dot dot-amber" aria-label="Warning"><WarnIcon size={12} /></span>;
}

function Cmd({ cmd, label }: { cmd: string; label: string }) {
  return (
    <div className="fix">
      <code>{cmd}</code>
      <CopyButton compact className="mini-btn" ariaLabel={label} tip="Copy this command to the clipboard. Run it in your terminal." getText={() => cmd} />
    </div>
  );
}

export function localSetup(project: string) {
  return [
    { title: "Sign in to gcloud", cmd: "gcloud auth login" },
    { title: "Create Application Default Credentials (what Policy Studio uses to apply)", cmd: "gcloud auth application-default login" },
    { title: "Bill API quota to the project you're changing", cmd: `gcloud auth application-default set-quota-project ${project || "PROJECT_ID"}` },
    { title: "Start Policy Studio locally (from the repo root), then open http://localhost:8090", cmd: "./studio-app" },
  ];
}

export function LocalSetup({ project, compact }: { project: string; compact?: boolean }) {
  const steps = localSetup(project);
  return (
    <div className="local-setup">
      {!compact && <div className="callout-title">To apply from Policy Studio, run it on your machine</div>}
      <p className="small">
        {compact ? "" : "This copy runs on Cloud Run with a service account and never changes your project. "}
        Locally, Policy Studio applies changes with your own Google login, only after its checks pass and you confirm.
      </p>
      <ol className="setup-steps">
        {steps.map((s) => (
          <li key={s.cmd}>
            <span className="small">{s.title}</span>
            <Cmd cmd={s.cmd} label={`Copy: ${s.cmd}`} />
          </li>
        ))}
      </ol>
      <CopyButton className="btn btn-tonal btn-small" label="Copy all 4 commands" ariaLabel="Copy all local setup commands" tip="Copy all four setup commands to the clipboard as one script, with a comment above each." getText={() => steps.map((s) => `# ${s.title}\n${s.cmd}`).join("\n\n") + "\n"} />
    </div>
  );
}

/** "You're signed in to proj-a but working on proj-b" (null when they match or are unknown). */
export function projectMismatch(a: AuthInfo | null): string | null {
  if (!a?.target_project) return null;
  const other = [a.adc.adc_project, a.gcloud.project].find((p) => p && p !== a.target_project);
  return other ?? null;
}

export function CredentialsCard() {
  const { auth, refreshAuth, ctx } = useStudio();
  const a = auth.data;
  const rows = useMemo<FixRow[]>(() => (a?.checks ?? []).map((c) => ({ key: c.id, title: c.title, fix: c.fix, missing: c.status !== "ok" })), [a]);
  const sel = useFixSelection(rows);

  if (!a)
    return (
      <div className="card cred-card">
        <div className="card-title-row">
          <h3 className="card-title">Credentials</h3>
        </div>
        {auth.error ? (
          <Callout tone="danger" title="Couldn't check credentials">
            <span className="mono small">{auth.error}</span>
          </Callout>
        ) : (
          <Spinner label="Checking credentials…" />
        )}
      </div>
    );

  const other = projectMismatch(a);
  const target = a.target_project || ctx.project;
  const errors = a.checks.filter((c) => c.status === "error");
  return (
    <section className="card cred-card" aria-label="Credentials">
      <div className="card-title-row">
        <h3 className="card-title">Credentials</h3>
        <ModeBadge />
        <span className="grow" />
        <Tip tip="Re-run the credential and permission checks (after you sign in or change projects).">
          <button type="button" className="btn btn-text btn-small" onClick={() => void refreshAuth(true)} disabled={auth.loading}>
            <RefreshIcon size={14} className={auth.loading ? "spin" : ""} /> Check again
          </button>
        </Tip>
      </div>

      {a.mode === "generate" ? (
        <p className="small muted">{GENERATE_TIP}.</p>
      ) : a.can_apply ? (
        <p className="small muted">Running locally. Apply uses the Application Default Credentials below, always targets <b className="mono">{target}</b>, and asks you to confirm first.</p>
      ) : (
        <Callout tone="danger" title="Apply is blocked">
          {(a.can_apply_reason || "A credential check failed.").replace(/\.?$/, ".")} {errors.some((e) => e.fix) ? "Run the fix below, then click Check again." : "Then click Check again."}
        </Callout>
      )}

      {other && (
        <Callout tone="warn" title={<>You're signed in to <span className="mono">{other}</span> but working on <span className="mono">{target}</span></>}>
          {a.mode === "apply" ? <>Apply will target <b className="mono">{target}</b> explicitly. </> : null}
          If <span className="mono">{target}</span> is the wrong project, change it above. To point gcloud and API quota at it too:
          <Cmd cmd={`gcloud config set project ${target} && gcloud auth application-default set-quota-project ${target}`} label="Copy the commands that switch gcloud to the target project" />
        </Callout>
      )}

      <div className="kv-grid">
        <div className="kv">
          <span>Runs on</span>
          <b>{a.runtime === "cloud_run" ? "Cloud Run" : "Local machine"}</b>
        </div>
        <div className="kv">
          <span>Target project</span>
          <b className="mono">{target}</b>
        </div>
        <div className="kv">
          <span>ADC account</span>
          <b className="mono">{a.adc.account || (a.adc.ok ? "unknown" : "none")}</b>
        </div>
        <div className="kv">
          <span>ADC type</span>
          <b>{a.adc.ok || a.adc.type !== "unknown" ? ADC_TYPE[a.adc.type] : "—"}</b>
        </div>
        <div className="kv wide">
          <span>ADC source</span>
          <b className="mono">{a.adc.source || "—"}</b>
        </div>
        <div className="kv">
          <span>Quota project</span>
          <b className={`mono ${a.adc.quota_project && a.adc.quota_project !== target ? "warn-text" : ""}`}>{a.adc.quota_project || "not set"}</b>
        </div>
        <div className="kv">
          <span>ADC project</span>
          <b className={`mono ${a.adc.adc_project && a.adc.adc_project !== target ? "warn-text" : ""}`}>{a.adc.adc_project || "—"}</b>
        </div>
        <div className="kv">
          <span>gcloud account</span>
          <b className="mono">{a.gcloud.available ? a.gcloud.account || "not signed in" : "gcloud not installed here"}</b>
        </div>
        <div className="kv">
          <span>gcloud project</span>
          <b className={`mono ${a.gcloud.project && a.gcloud.project !== target ? "warn-text" : ""}`}>{a.gcloud.available ? a.gcloud.project || "not set" : "—"}</b>
        </div>
      </div>
      {a.adc.error && <p className="small field-error">{a.adc.error}</p>}

      {a.checks.length > 0 && (
        <>
          <h4 className="sub-title">Checks</h4>
          <FixToolbar sel={sel} label="Credential checks" filename={`fix-credentials-${target}.sh`} />
          <ul className="checklist">
            {a.checks.map((c, n) => (
              <li key={c.id}>
                <FixCheck sel={sel} row={rows[n]} />
                <CheckDot s={c.status} />
                <div className="check-main">
                  <span>{c.title}</span>
                  <span className="small muted">{c.detail}</span>
                  {c.fix && <Cmd cmd={c.fix} label={`Copy fix: ${c.fix}`} />}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      {a.mode === "generate" && (
        <div className="callout callout-info">
          <LocalSetup project={target} />
        </div>
      )}
    </section>
  );
}
