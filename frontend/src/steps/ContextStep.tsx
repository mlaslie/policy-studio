// Context step: project / region / optional gateway project and Gemini Enterprise app, then the access check.
import { Tip } from "../components/Tooltip";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useStudio } from "../store";
import type { ContextInfo, Ctx, PermissionCheck } from "../api/types";
import { FixCheck, FixToolbar, useFixSelection, type FixRow } from "../components/FixSelect";
import { CredentialsCard } from "./CredentialsCard";
import { Callout, Load, StepHeader, Term } from "../components/ui";
import { CopyButton } from "../components/Glass";
import { ArrowIcon, CheckIcon, CloseIcon, HelpIcon, WarnIcon } from "../components/Icons";

const REGIONS = ["us-central1", "us-east1", "us-east4", "us-east5", "us-south1", "us-west1", "us-west4", "northamerica-northeast1", "southamerica-east1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west9", "asia-northeast1", "asia-south1", "asia-southeast1", "australia-southeast1"];

const PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

function Field({ id, label, help, error, children }: { id: string; label: string; help: string; error?: string | null; children: React.ReactNode }) {
  return (
    <div className={`field ${error ? "has-error" : ""}`}>
      <label htmlFor={id}>{label}</label>
      {children}
      <div className="field-help" id={`${id}-help`}>
        {error ? <span className="field-error">{error}</span> : help}
      </div>
    </div>
  );
}

function StatusDot({ ok }: { ok: boolean | null }) {
  if (ok === true) return <span className="dot dot-green" aria-label="OK"><CheckIcon size={12} /></span>;
  if (ok === false) return <span className="dot dot-red" aria-label="Missing"><CloseIcon size={12} /></span>;
  return <span className="dot dot-amber" aria-label="Not checked"><HelpIcon size={12} /></span>;
}

export function ContextStep() {
  const { ctx, setCtx, sync, ctxInfo, goto, syncing } = useStudio();
  const [f, setF] = useState<Ctx>(ctx);
  const [touched, setTouched] = useState(false);
  useEffect(() => setF(ctx), [ctx]);

  const projErr = !f.project ? "Required." : !PROJECT_RE.test(f.project) ? "Project IDs are 6–30 lowercase letters, digits or hyphens (not the project number)." : null;
  const regErr = !f.region ? "Required." : !/^[a-z]+-[a-z]+\d+$/.test(f.region) ? "Looks like us-east4 or europe-west1." : null;
  const gpErr = f.gateway_project && !PROJECT_RE.test(f.gateway_project) ? "Not a valid project ID." : null;
  const dirty = JSON.stringify(f) !== JSON.stringify(ctx);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (projErr || regErr || gpErr) return;
    const c = { ...f, project: f.project.trim(), region: f.region.trim() };
    setCtx(c);
    void sync(true, c);
  };

  return (
    <>
      <StepHeader
        title="Context"
        lead={<>Tell Policy Studio which Google Cloud project and region to look at. Every list, check and generated command uses these values, and they're remembered in this browser.</>}
      />
      <form className="card form-card" onSubmit={submit} noValidate>
        <div className="form-grid">
          <Field id="project" label="Project ID" help="Where your agents run, e.g. my-demo-project. The project number is looked up for you." error={touched ? projErr : null}>
            <input id="project" value={f.project} onChange={(e) => setF({ ...f, project: e.target.value })} placeholder="my-demo-project" autoComplete="off" spellCheck={false} aria-describedby="project-help" />
          </Field>
          <Field id="region" label="Region" help="Gateways, registries and agents are regional. Pick from the list or type one." error={touched ? regErr : null}>
            <input id="region" list="regions" value={f.region} onChange={(e) => setF({ ...f, region: e.target.value })} placeholder="us-east4" autoComplete="off" spellCheck={false} aria-describedby="region-help" />
            <datalist id="regions">
              {REGIONS.map((r) => (
                <option key={r} value={r} />
              ))}
            </datalist>
          </Field>
          <Field id="gwp" label="Gateway project (optional)" help="Only if your egress gateway and Agent Registry live in a different project. Leave empty to use the project above." error={gpErr}>
            <input id="gwp" value={f.gateway_project ?? ""} onChange={(e) => setF({ ...f, gateway_project: e.target.value })} placeholder={f.project || "same as project"} autoComplete="off" spellCheck={false} />
          </Field>
          <div className="field-pair">
            <Field id="geapp" label="Gemini Enterprise app (optional)" help="Used in generated commands that connect an agent to your Gemini Enterprise app.">
              <input id="geapp" value={f.ge_app ?? ""} onChange={(e) => setF({ ...f, ge_app: e.target.value })} placeholder="e.g. helpdesk-app_1712345678" autoComplete="off" spellCheck={false} />
            </Field>
            <Field id="geloc" label="App location" help="Where the app lives.">
              <select id="geloc" value={f.ge_location ?? "global"} onChange={(e) => setF({ ...f, ge_location: e.target.value })}>
                <option value="global">global</option>
                <option value="us">us</option>
                <option value="eu">eu</option>
              </select>
            </Field>
          </div>
        </div>
        <div className="form-actions">
          <Tip
            tip={
              syncing
                ? "Checking now…"
                : ctxInfo.data && !dirty
                  ? "Re-run the API and permission checks for this project and region, and re-read everything from Google Cloud."
                  : "Save this project and region as your context (in this browser), then check APIs and permissions and read everything from Google Cloud."
            }
          >
            <button type="submit" className="btn btn-primary" disabled={syncing}>
              {syncing ? "Checking…" : ctxInfo.data && !dirty ? "Check again" : "Save and check access"}
            </button>
          </Tip>
          {dirty && ctx.project && (
            <Tip tip="Put the form back to the saved project and region. Nothing is re-checked.">
              <button type="button" className="btn btn-text" onClick={() => setF(ctx)}>
                Discard changes
              </button>
            </Tip>
          )}
          <span className="muted small">Checking only lists and reads resources.</span>
        </div>
      </form>

      <CredentialsCard />

      {ctx.project && (ctxInfo.data || ctxInfo.loading || ctxInfo.error) && (
        <Load l={ctxInfo} what="your access">
          {(ci) => {
            const apis = Object.entries(ci.apis);
            const missingApis = apis.filter(([, v]) => !v).map(([k]) => k);
            const missingPerms = ci.permissions.filter((p) => p.granted === false && !p.write);
            return (
              <div className="ctx-result">
                <div className="card kv-card">
                  <div className="kv">
                    <span>Project</span>
                    <b className="mono">{ci.project}</b>
                  </div>
                  <div className="kv">
                    <span>Project number</span>
                    <b className="mono">{ci.project_number}</b>
                  </div>
                  <div className="kv">
                    <span>Region</span>
                    <b className="mono">{ci.region}</b>
                  </div>
                  <div className="kv">
                    <span>Gateway project</span>
                    <b className="mono">{ci.gateway_project}</b>
                  </div>
                  <div className="kv wide">
                    <span>You are signed in as</span>
                    <b className="mono">{ci.principal}</b>
                  </div>
                </div>
                {ci.error && <Callout tone="danger" title="Some checks failed">{ci.error}</Callout>}
                {missingApis.length + missingPerms.length === 0 ? (
                  <Callout tone="ok" title="You're all set">Every API is enabled and you can read everything Policy Studio needs.</Callout>
                ) : (
                  <Callout tone="warn" title={`${missingApis.length + missingPerms.length} thing${missingApis.length + missingPerms.length > 1 ? "s" : ""} to look at`}>
                    Policy Studio still works; the affected sections will be empty or marked. Each item below has the command that fixes it.
                  </Callout>
                )}
                <div className="two-col">
                  <ApisCard ci={ci} />
                  <PermissionsCard ci={ci} />
                </div>
                <div className="next-row">
                  <button className="btn btn-primary" onClick={() => goto("map")}>
                    Next: see the policy map <ArrowIcon size={16} />
                  </button>
                  {missingApis.length + missingPerms.length > 0 && (
                    <span className="muted small">
                      <WarnIcon size={14} /> You can continue with missing items.
                    </span>
                  )}
                </div>
              </div>
            );
          }}
        </Load>
      )}
    </>
  );
}

function ApisCard({ ci }: { ci: ContextInfo }) {
  const apis = Object.entries(ci.apis);
  const rows = useMemo<FixRow[]>(
    () => apis.map(([k, v]) => ({ key: k, title: `Enable ${k}`, fix: v ? null : `gcloud services enable ${k} --project=${ci.project}`, missing: !v })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [JSON.stringify(ci.apis), ci.project],
  );
  const sel = useFixSelection(rows);
  return (
    <div className="card">
      <h3 className="card-title">APIs</h3>
      <FixToolbar sel={sel} label="APIs" filename={`enable-apis-${ci.project}.sh`} />
      <ul className="checklist">
        {rows.map((r) => (
          <li key={r.key}>
            <FixCheck sel={sel} row={r} />
            <StatusDot ok={!r.missing} />
            <div className="check-main">
              <span className="mono small">{r.key}</span>
              {r.fix && (
                <div className="fix">
                  <code>{r.fix}</code>
                  <CopyButton compact className="mini-btn" ariaLabel={`Copy command to enable ${r.key}`} tip="Copy the gcloud command that enables this API. Run it yourself; nothing changes from here." getText={() => r.fix!} />
                </div>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

type PermGroup = { key: string; perms: PermissionCheck[]; fix: string | null; granted: boolean | null };

/** One row per permission, except missing permissions fixed by the same command share one row. */
function groupPerms(perms: PermissionCheck[]): PermGroup[] {
  const out: PermGroup[] = [];
  const byFix = new Map<string, PermGroup>();
  for (const p of perms) {
    if (p.granted === false && p.fix) {
      const g = byFix.get(p.fix);
      if (g) {
        g.perms.push(p);
        continue;
      }
      const ng: PermGroup = { key: p.permission, perms: [p], fix: p.fix, granted: false };
      byFix.set(p.fix, ng);
      out.push(ng);
    } else out.push({ key: p.permission, perms: [p], fix: null, granted: p.granted });
  }
  return out;
}

function PermissionsCard({ ci }: { ci: ContextInfo }) {
  const groups = useMemo(() => groupPerms(ci.permissions), [ci.permissions]);
  const rows = useMemo<FixRow[]>(
    () =>
      groups.map((g) => {
        const role = g.perms[0].role;
        const what = g.perms.map((p) => p.needed_for).join("; ");
        return { key: g.key, title: role ? `Grant ${role} (${what})` : what, fix: g.fix, missing: g.granted === false };
      }),
    [groups],
  );
  const sel = useFixSelection(rows);
  return (
    <div className="card">
      <h3 className="card-title">Your permissions</h3>
      <FixToolbar sel={sel} label="Permissions" filename={`grant-roles-${ci.project}.sh`} />
      <ul className="checklist">
        {groups.map((g, n) => {
          const p = g.perms[0];
          return (
            <li key={g.key}>
              <FixCheck sel={sel} row={rows[n]} />
              <StatusDot ok={g.granted} />
              <div className="check-main">
                {g.perms.length === 1 ? (
                  <>
                    <span>
                      {p.needed_for}
                      {p.write && <span className="badge badge-neutral perm-tag" title="Only needed to apply changes from Policy Studio">Apply</span>}
                    </span>
                    <span className="mono tiny muted">
                      {p.permission}
                      {p.granted === null ? " · not checked" : ""}
                    </span>
                  </>
                ) : (
                  <>
                    <span>
                      {p.role ? <>One grant of <span className="mono small">{p.role}</span> fixes {g.perms.length} permissions</> : <>One command fixes {g.perms.length} permissions</>}
                      {g.perms.every((x) => x.write) && <span className="badge badge-neutral perm-tag" title="Only needed to apply changes from Policy Studio">Apply</span>}
                    </span>
                    <ul className="perm-covers">
                      {g.perms.map((x, i) => (
                        <li key={`${x.permission}-${x.needed_for}-${i}`}>
                          {x.needed_for} <span className="mono tiny muted">{x.permission}</span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
                {g.fix && (
                  <div className="fix">
                    <code>{g.fix}</code>
                    <CopyButton compact className="mini-btn" ariaLabel="Copy fix command" tip="Copy the command that grants the missing role. Run it yourself; nothing changes from here." getText={() => g.fix!} />
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      <p className="muted small">
        Permissions tagged “Apply” are only needed to make changes from Policy Studio. You don't need them to <Term k="iap-egressor">generate grants</Term>.
      </p>
    </div>
  );
}
