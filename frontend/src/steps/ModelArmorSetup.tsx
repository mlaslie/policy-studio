// "Set up Model Armor in this region": a guided mini-wizard for the prerequisites of Model Armor on a gateway.
//   1. Template   pick one in the region, or create one with friendly filter controls
//   2. Extension  a Model Armor authz extension that names the template
//   3. Permissions the gateways' service agents get the three Model Armor roles (only the missing ones are staged)
//   4. Turn on    model_armor_on for the chosen gateways, pointing at the extension
// Everything is staged in the cart (in that order); nothing changes in Google Cloud until Apply.
// Also exports the callout that replaces the old "no Model Armor extension" warning everywhere.
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useStudio } from "../store";
import type { Intent, MaLevel, ModelArmorResp, TemplateFilters } from "../api/types";
import { Badge, Callout, Term } from "../components/ui";
import { Tip } from "../components/Tooltip";
import { useApplyGate } from "../components/Mode";
import { ArrowIcon, CheckIcon, CloseIcon, InfoIcon, PlayIcon, PlusIcon, SparkIcon } from "../components/Icons";
import { newId, shortName } from "../lib/policy";

export const MA_ROLES = ["roles/modelarmor.calloutUser", "roles/modelarmor.user", "roles/serviceusage.serviceUsageConsumer"];
const ROLE_HELP: Record<string, string> = {
  "roles/modelarmor.calloutUser": "call Model Armor as a gateway extension",
  "roles/modelarmor.user": "use the template to screen content",
  "roles/serviceusage.serviceUsageConsumer": "use the Model Armor API in this project",
};
const LEVELS: { id: MaLevel; label: string; help: string }[] = [
  { id: "off", label: "Off", help: "Don't run this filter." },
  { id: "LOW_AND_ABOVE", label: "Low+", help: "Strictest: blocks even weak signals (most false positives)." },
  { id: "MEDIUM_AND_ABOVE", label: "Medium+", help: "Balanced: a good default." },
  { id: "HIGH", label: "High", help: "Most lenient: blocks only clear cases." },
];
const RAI: { id: string; label: string }[] = [
  { id: "HATE_SPEECH", label: "Hate speech" },
  { id: "HARASSMENT", label: "Harassment" },
  { id: "SEXUALLY_EXPLICIT", label: "Sexually explicit" },
  { id: "DANGEROUS", label: "Dangerous content" },
];
const DEFAULT_FILTERS: TemplateFilters = {
  pi_jailbreak: "MEDIUM_AND_ABOVE",
  sdp: "basic",
  rai: { HATE_SPEECH: "MEDIUM_AND_ABOVE", HARASSMENT: "MEDIUM_AND_ABOVE", SEXUALLY_EXPLICIT: "MEDIUM_AND_ABOVE", DANGEROUS: "MEDIUM_AND_ABOVE" },
  malicious_uri: true,
};
const DEFAULT_BLOCK = "This request was blocked by your organization's AI safety policy.";

/** The render / apply warning the backend gives a model_armor_on with no extension to use. */
export const isMaSetupWarning = (w: string) => w.includes("MODEL_ARMOR_EXTENSION") || w.startsWith("Model Armor isn't set up");

/** Friendlier replacement for the "no Model Armor extension" warning, with a button that opens the wizard. */
export function MaSetupCallout({ text }: { text?: string }) {
  const { openMaSetup, ctx } = useStudio();
  return (
    <Callout tone="warn" title={`Model Armor isn't set up in ${ctx.region || "this region"} yet`}>
      <p>{text ? text.replace(/^Model Armor isn't set up in [^:]+: /, "") : "There's no Model Armor authz extension for this gateway to use yet."}</p>
      <Tip tip="Open the guided setup on the Model Armor step: pick or create a template, create the extension, grant the gateway's service agent its roles. You stage each step; nothing changes until you apply.">
        <button className="btn btn-small btn-primary ma-setup-link" onClick={openMaSetup}>
          Set up Model Armor in this region <ArrowIcon size={14} />
        </button>
      </Tip>
    </Callout>
  );
}

/** Warnings as callouts; the Model Armor setup warning becomes MaSetupCallout. */
export function WarningCallouts({ warnings }: { warnings: string[] | undefined }) {
  return (
    <>
      {(warnings ?? []).map((w) =>
        isMaSetupWarning(w) ? (
          <MaSetupCallout key={w} text={w} />
        ) : (
          <Callout key={w} tone="warn">
            {w}
          </Callout>
        ),
      )}
    </>
  );
}

// ---------------------------------------------------------------- small pieces

type ChipState = "done" | "staged" | "todo";
function Chip({ n, label, state, active, onClick }: { n: number; label: string; state: ChipState; active: boolean; onClick: () => void }) {
  const what = state === "done" ? "in place" : state === "staged" ? "staged" : "to do";
  return (
    <button type="button" className={`setup-chip ${state} ${active ? "active" : ""}`} onClick={onClick} aria-current={active ? "step" : undefined} aria-label={`Step ${n}: ${label}, ${what}`}>
      <span className="setup-chip-num">{state === "todo" ? n : <CheckIcon size={12} />}</span>
      {label}
      {state === "staged" && <span className="setup-chip-tag">staged</span>}
    </button>
  );
}

function Learn({ children }: { children: ReactNode }) {
  return (
    <div className="learn-note">
      <InfoIcon size={16} />
      <div>{children}</div>
    </div>
  );
}

function Seg<T extends string>({ value, onChange, items, label }: { value: T; onChange: (v: T) => void; items: { id: T; label: string; help?: string }[]; label: string }) {
  return (
    <div className="seg" role="radiogroup" aria-label={label}>
      {items.map((it) => (
        <button key={it.id} type="button" role="radio" aria-checked={value === it.id} className={`seg-btn ${value === it.id ? "on" : ""}`} title={it.help} onClick={() => onChange(it.id)}>
          {it.label}
        </button>
      ))}
    </div>
  );
}

function StageBtn({ tip, onClick, disabled, done, children }: { tip: string; onClick: () => void; disabled?: boolean; done?: boolean; children: ReactNode }) {
  if (done) return <Badge tone="blue">Staged</Badge>;
  return (
    <Tip tip={tip}>
      <button className="btn btn-small btn-tonal" onClick={onClick} disabled={disabled}>
        <PlusIcon size={14} /> {children}
      </button>
    </Tip>
  );
}

// ---------------------------------------------------------------- the wizard

export function ModelArmorSetup({ data }: { data: ModelArmorResp }) {
  const { ctx, cart, addIntents, goto, openApply, maSetupOpen, setMaSetupOpen } = useStudio();
  const { canApply } = useApplyGate();
  const setup = data.setup;
  const region = ctx.region;
  const [step, setStep] = useState(1);

  // Where the template and extension live: the project of the gateways (the egress gateway's first).
  const project = useMemo(() => {
    const g = data.gateways.find((x) => x.type === "egress") ?? data.gateways[0];
    return g?.gateway.split("/")[1] || ctx.gateway_project || ctx.project;
  }, [data.gateways, ctx.gateway_project, ctx.project]);
  const loc = `projects/${project}/locations/${region}`;

  // 1. template
  const [mode, setMode] = useState<"existing" | "new">(setup?.templates.length ? "existing" : "new");
  const [existing, setExisting] = useState<string>(setup?.suggested.template ?? setup?.templates[0]?.name ?? "");
  const [tid, setTid] = useState(setup?.suggested.template_id ?? "agent-shield");
  const [filters, setFilters] = useState<TemplateFilters>(DEFAULT_FILTERS);
  const [inspect, setInspect] = useState("");
  const [block, setBlock] = useState(DEFAULT_BLOCK);
  // 2. extension
  const [extName, setExtName] = useState(setup?.suggested.extension_name ?? "agent-ma-authz");
  // 3. permissions: service agents to grant (default: every one with a missing role)
  const [skipAgents, setSkipAgents] = useState<string[]>([]);
  // 4. gateways to turn on (default: every gateway without Model Armor)
  const [skipGws, setSkipGws] = useState<string[]>([]);

  useEffect(() => {
    if (!setup) return;
    setMode(setup.templates.length ? "existing" : "new");
    setExisting(setup.suggested.template ?? setup.templates[0]?.name ?? "");
    setTid(setup.suggested.template_id);
    setExtName(setup.suggested.extension_name);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setup?.region, setup?.templates.length, setup?.extensions.length]);

  if (!setup) return null;
  const open = maSetupOpen || !setup.ready;
  if (!open) return null;

  // ---- what exists / what's staged
  const live = (i: Intent) => !i.params?.delete;
  const tmplName = mode === "existing" ? existing : `${loc}/templates/${tid.trim()}`;
  const stagedTmpl = cart.find((i) => i.kind === "model_armor_template" && live(i) && `projects/${i.params?.project || project}/locations/${region}/templates/${i.params?.template_id}` === tmplName);
  const tmplState: ChipState = mode === "existing" ? (existing ? "done" : "todo") : stagedTmpl ? "staged" : "todo";

  const existingExt = setup.extensions.find((x) => x.templates.includes(tmplName));
  const extFull = existingExt?.name ?? `${loc}/authzExtensions/${extName.trim()}`;
  const stagedExt = cart.find((i) => i.kind === "model_armor_extension" && live(i) && i.params?.name === extName.trim() && (i.params?.project || project) === project);
  const extState: ChipState = existingExt ? "done" : stagedExt ? "staged" : "todo";

  const agents = setup.service_agents.map((a) => {
    const missing = MA_ROLES.filter((r) => a.roles[r] !== true);
    const staged = cart.find((i) => i.kind === "iam_project_grant" && live(i) && i.params?.member === a.member);
    const stagedRoles = new Set(staged?.params?.roles ?? []);
    return { a, missing, staged, covered: missing.every((r) => stagedRoles.has(r)) };
  });
  const needAgents = agents.filter((x) => x.missing.length && !skipAgents.includes(x.a.email));
  const permState: ChipState = agents.every((x) => !x.missing.length) ? "done" : needAgents.every((x) => x.covered) && needAgents.length ? "staged" : "todo";

  const gws = data.gateways.map((g) => ({ g, staged: cart.find((i) => i.kind === "model_armor_on" && i.gateway?.name === g.gateway) }));
  const offGws = gws.filter((x) => !x.g.enabled && !skipGws.includes(x.g.gateway));
  const onState: ChipState = gws.every((x) => x.g.enabled) ? "done" : offGws.length && offGws.every((x) => x.staged) ? "staged" : "todo";

  // ---- intents
  const idOk = /^[A-Za-z0-9_-]{1,63}$/.test(tid.trim());
  const extOk = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/.test(extName.trim());
  const tmplIntent = (): Intent => ({
    id: newId("ma"),
    kind: "model_armor_template",
    params: { project, template_id: tid.trim(), filters, block_message: block.trim() || undefined, ...(filters.sdp === "advanced" && inspect.trim() ? { inspect_template: inspect.trim() } : {}) },
  });
  const extIntent = (): Intent => ({ id: newId("ma"), kind: "model_armor_extension", params: { project, name: extName.trim(), template: tmplName } });
  const grantIntents = (): Intent[] =>
    needAgents.filter((x) => !x.covered).map((x) => ({ id: newId("ma"), kind: "iam_project_grant", params: { project: x.a.project || project, member: x.a.member, roles: x.missing, gateway: x.a.gateway } }));
  const onIntents = (): Intent[] => offGws.filter((x) => !x.staged).map((x) => ({ id: newId("ma"), kind: "model_armor_on", gateway: { name: x.g.gateway, direction: x.g.type, extension: extFull } }));

  const pending: Intent[] = [
    ...(mode === "new" && !stagedTmpl && idOk ? [tmplIntent()] : []),
    ...(!existingExt && !stagedExt && extOk && tmplName && (mode === "existing" ? !!existing : idOk) ? [extIntent()] : []),
    ...grantIntents(),
    ...onIntents(),
  ];
  const stagedIds = [stagedTmpl, stagedExt, ...agents.map((x) => x.staged), ...gws.map((x) => x.staged)].filter((x): x is Intent => !!x).map((x) => x.id);
  const anyStaged = stagedIds.length > 0;
  const review = () => (canApply ? openApply(stagedIds) : goto(5));

  const chips: { label: string; state: ChipState }[] = [
    { label: "Template", state: tmplState },
    { label: "Extension", state: extState },
    { label: "Permissions", state: permState },
    { label: "On", state: onState },
  ];

  return (
    <section className="card ma-setup" id="ma-setup" aria-labelledby="ma-setup-title">
      <header className="ma-setup-head">
        <span className="gw-icon ma-off">
          <SparkIcon size={20} />
        </span>
        <div className="grow">
          <h2 id="ma-setup-title">{setup.ready ? `Set up Model Armor in ${region}` : `Model Armor isn't set up in ${region} yet`}</h2>
          <p className="muted small">
            {setup.ready
              ? "Everything Model Armor needs exists here. You can still stage a new template or extension, or turn it on for more gateways."
              : "Before a gateway can screen content, the region needs a template, an extension that uses it, and permissions for the gateway's service agent. Four short steps; each one is staged in the cart and nothing changes in Google Cloud until you apply."}
          </p>
        </div>
        {setup.ready && (
          <Tip tip="Hide the setup steps.">
            <button className="icon-btn" aria-label="Close Model Armor setup" onClick={() => setMaSetupOpen(false)}>
              <CloseIcon size={16} />
            </button>
          </Tip>
        )}
      </header>

      <nav className="setup-chips" aria-label="Setup steps">
        {chips.map((c, n) => (
          <Chip key={c.label} n={n + 1} label={c.label} state={c.state} active={step === n + 1} onClick={() => setStep(n + 1)} />
        ))}
      </nav>

      <div className="setup-body">
        {step === 1 && (
          <div className="setup-step">
            <h3>1. Template: what to screen for</h3>
            <Learn>
              A <Term k="model-armor-template">template</Term> is a saved set of filters (prompt injection, sensitive data, harmful content, malicious links) and how strict each one is. It lives in one region and does nothing on its own: the extension in step 2
              points at it.
            </Learn>
            {setup.templates.length > 0 && (
              <Seg<"existing" | "new">
                label="Template choice"
                value={mode}
                onChange={setMode}
                items={[
                  { id: "existing", label: `Use one in ${region} (${setup.templates.length})` },
                  { id: "new", label: "Create a new one" },
                ]}
              />
            )}
            {mode === "existing" ? (
              <div className="choices">
                {setup.templates.map((t) => (
                  <label key={t.name} className={`choice ${existing === t.name ? "checked" : ""}`}>
                    <input type="radio" name="ma-tmpl" checked={existing === t.name} onChange={() => setExisting(t.name)} />
                    <span className="choice-body">
                      <span className="choice-title mono">{t.id}</span>
                      <span className="choice-desc">{(t as { summary?: string[] }).summary?.slice(0, 3).join(" · ") ?? ""}</span>
                    </span>
                  </label>
                ))}
              </div>
            ) : (
              <div className="setup-form">
                <div className="field">
                  <label htmlFor="ma-tid">Template name</label>
                  <input id="ma-tid" value={tid} onChange={(e) => setTid(e.target.value)} spellCheck={false} aria-invalid={!idOk} />
                  <div className={`field-help ${idOk ? "" : "field-error"}`}>{idOk ? `Created as ${loc}/templates/${tid.trim()}` : "Letters, digits, - and _ only (at most 63)."}</div>
                </div>
                <div className="filter-row">
                  <div>
                    <div className="filter-label">Prompt injection &amp; jailbreak</div>
                    <div className="muted small">Attempts to override the agent's instructions.</div>
                  </div>
                  <Seg<MaLevel> label="Prompt injection and jailbreak" value={filters.pi_jailbreak} onChange={(v) => setFilters({ ...filters, pi_jailbreak: v })} items={LEVELS} />
                </div>
                <div className="filter-row">
                  <div>
                    <div className="filter-label">Sensitive data</div>
                    <div className="muted small">Basic finds credit cards, government IDs and keys; Advanced uses your own Sensitive Data Protection inspect template.</div>
                  </div>
                  <Seg<TemplateFilters["sdp"]>
                    label="Sensitive data"
                    value={filters.sdp}
                    onChange={(v) => setFilters({ ...filters, sdp: v })}
                    items={[
                      { id: "off", label: "Off" },
                      { id: "basic", label: "Basic" },
                      { id: "advanced", label: "Advanced" },
                    ]}
                  />
                </div>
                {filters.sdp === "advanced" && (
                  <div className="field">
                    <label htmlFor="ma-inspect">Inspect template</label>
                    <input id="ma-inspect" value={inspect} onChange={(e) => setInspect(e.target.value)} placeholder={`projects/${project}/locations/${region}/inspectTemplates/…`} spellCheck={false} />
                    <div className="field-help">Without one the commands use the placeholder INSPECT_TEMPLATE and Apply refuses the template.</div>
                  </div>
                )}
                <div className="filter-group">
                  <div className="filter-label">Responsible AI</div>
                  <div className="muted small">Harmful or abusive content, per category.</div>
                  {RAI.map((r) => (
                    <div key={r.id} className="filter-row sub">
                      <span>{r.label}</span>
                      <Seg<MaLevel> label={r.label} value={filters.rai[r.id] ?? "off"} onChange={(v) => setFilters({ ...filters, rai: { ...filters.rai, [r.id]: v } })} items={LEVELS} />
                    </div>
                  ))}
                </div>
                <label className="filter-row check">
                  <span>
                    <span className="filter-label">Malicious URLs</span>
                    <span className="muted small block">Blocks known phishing and malware links.</span>
                  </span>
                  <input type="checkbox" checked={filters.malicious_uri} onChange={(e) => setFilters({ ...filters, malicious_uri: e.target.checked })} />
                </label>
                <div className="field">
                  <label htmlFor="ma-block">Message people see when something is blocked</label>
                  <input id="ma-block" value={block} onChange={(e) => setBlock(e.target.value)} />
                  <div className="field-help">Returned with HTTP 403 for blocked prompts and responses.</div>
                </div>
              </div>
            )}
            <div className="setup-actions">
              {mode === "new" && (
                <StageBtn done={!!stagedTmpl} disabled={!idOk} onClick={() => addIntents([tmplIntent()])} tip={`Stage creating Model Armor template ${tid.trim() || "…"} in ${region}. Nothing changes in Google Cloud until you apply.`}>
                  Stage template
                </StageBtn>
              )}
              <button className="btn btn-small btn-text" onClick={() => setStep(2)}>
                Next: extension <ArrowIcon size={14} />
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="setup-step">
            <h3>2. Extension: connect the gateway to Model Armor</h3>
            <Learn>
              An <Term k="authz-extension">authz extension</Term> tells a gateway which service to consult. A Model Armor extension uses service <span className="mono">modelarmor.{region}.rep.googleapis.com</span> and names the template for both requests and responses. It's set to
              fail closed: if Model Armor can't be reached, traffic is blocked rather than let through unscreened.
            </Learn>
            {existingExt ? (
              <Callout tone="ok" title={`Using ${shortName(existingExt.name)}`}>
                This extension already screens with <span className="mono">{shortName(tmplName)}</span>, so there's nothing to create.
              </Callout>
            ) : (
              <div className="setup-form">
                <div className="field">
                  <label htmlFor="ma-ext">Extension name</label>
                  <input id="ma-ext" value={extName} onChange={(e) => setExtName(e.target.value)} spellCheck={false} aria-invalid={!extOk} />
                  <div className={`field-help ${extOk ? "" : "field-error"}`}>{extOk ? `Created as ${loc}/authzExtensions/${extName.trim()}` : "Lowercase letters, digits and hyphens, starting with a letter."}</div>
                </div>
                <div className="kv-inline small">
                  <span>
                    Screens with: <span className="mono">{tmplName ? shortName(tmplName) : "(pick a template in step 1)"}</span>
                    {mode === "new" && !stagedTmpl && <Badge tone="amber">template not staged yet</Badge>}
                  </span>
                  <span>
                    Timeout: <span className="mono">5s</span> · fail open: <span className="mono">false</span>
                  </span>
                </div>
              </div>
            )}
            <div className="setup-actions">
              {!existingExt && (
                <StageBtn done={!!stagedExt} disabled={!extOk || !tmplName || (mode === "new" && !idOk)} onClick={() => addIntents([extIntent()])} tip={`Stage creating authz extension ${extName.trim() || "…"} that screens with ${shortName(tmplName) || "the template"}. Nothing changes in Google Cloud until you apply.`}>
                  Stage extension
                </StageBtn>
              )}
              <button className="btn btn-small btn-text" onClick={() => setStep(3)}>
                Next: permissions <ArrowIcon size={14} />
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="setup-step">
            <h3>3. Permissions: let the gateway call Model Armor</h3>
            <Learn>
              A gateway calls Model Armor as its <Term k="ma-service-agent">service agent</Term>, named in the gateway resource. Each one needs three roles on <span className="mono">{project}</span>: <span className="mono">modelarmor.calloutUser</span>,{" "}
              <span className="mono">modelarmor.user</span> and <span className="mono">serviceusage.serviceUsageConsumer</span>. Without them every screened request fails. Only missing roles are staged.
            </Learn>
            {agents.length === 0 && <p className="muted">No gateway service agents found (no gateways in this region, or the gateway resource doesn't name one).</p>}
            <ul className="sa-list">
              {agents.map(({ a, missing, staged, covered }) => (
                <li key={a.email} className="sa-row">
                  <div className="sa-head">
                    {missing.length > 0 ? (
                      <input
                        type="checkbox"
                        aria-label={`Grant the missing roles to ${a.email}`}
                        checked={!skipAgents.includes(a.email)}
                        disabled={!!staged}
                        onChange={(e) => setSkipAgents(e.target.checked ? skipAgents.filter((x) => x !== a.email) : [...skipAgents, a.email])}
                      />
                    ) : (
                      <span className="dot dot-green">
                        <CheckIcon size={12} />
                      </span>
                    )}
                    <div className="grow">
                      <div className="mono small sa-email">{a.email}</div>
                      <div className="muted tiny">
                        {(a.gateways ?? [a.gateway]).map(shortName).join(", ")} · {a.note}
                      </div>
                    </div>
                    {staged ? <Badge tone="blue">{covered ? "Grant staged" : "Partly staged"}</Badge> : missing.length === 0 ? <Badge tone="green">All set</Badge> : null}
                  </div>
                  <ul className="role-list">
                    {MA_ROLES.map((r) => {
                      const v = a.roles[r];
                      return (
                        <li key={r} className={`role ${v ? "ok" : v === false ? "missing" : "unknown"}`}>
                          <span className="role-mark">{v ? <CheckIcon size={12} /> : v === false ? <CloseIcon size={12} /> : "?"}</span>
                          <span className="mono">{r}</span>
                          <span className="muted tiny">{ROLE_HELP[r]}</span>
                        </li>
                      );
                    })}
                  </ul>
                  {a.error && <div className="muted tiny">Couldn't read the IAM policy ({a.error}); staging grants all three (Apply skips any that exist).</div>}
                </li>
              ))}
            </ul>
            <div className="setup-actions">
              <StageBtn done={permState === "staged"} disabled={!grantIntents().length} onClick={() => addIntents(grantIntents())} tip={`Stage granting only the missing Model Armor roles to ${needAgents.filter((x) => !x.covered).length} service agent(s) on their project. Nothing changes in Google Cloud until you apply.`}>
                Stage permissions
              </StageBtn>
              <button className="btn btn-small btn-text" onClick={() => setStep(4)}>
                Next: turn on <ArrowIcon size={14} />
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="setup-step">
            <h3>4. Turn on Model Armor for gateways</h3>
            <Learn>
              Turning it on attaches a <Term k="content-authz">CONTENT_AUTHZ</Term> policy to the gateway that uses the extension <span className="mono">{shortName(extFull)}</span>. On an egress gateway it screens MCP tool calls and results (not A2A); on an ingress gateway, prompts into
              your agents and their answers.
            </Learn>
            <ul className="sa-list">
              {gws.map(({ g, staged }) => (
                <li key={g.gateway} className="sa-row">
                  <label className="sa-head">
                    {g.enabled ? (
                      <span className="dot dot-green">
                        <CheckIcon size={12} />
                      </span>
                    ) : (
                      <input type="checkbox" checked={!skipGws.includes(g.gateway)} disabled={!!staged} onChange={(e) => setSkipGws(e.target.checked ? skipGws.filter((x) => x !== g.gateway) : [...skipGws, g.gateway])} />
                    )}
                    <span className="grow">
                      <b>{shortName(g.gateway)}</b> <Badge tone={g.type === "egress" ? "blue" : "purple"}>{g.type === "egress" ? "Egress" : "Ingress"}</Badge>
                    </span>
                    {g.enabled ? <Badge tone="green">Already on</Badge> : staged ? <Badge tone="blue">Turn on staged</Badge> : null}
                  </label>
                </li>
              ))}
            </ul>
            <div className="setup-actions">
              <StageBtn done={onState === "staged"} disabled={!onIntents().length} onClick={() => addIntents(onIntents())} tip={`Stage turning on Model Armor (extension ${shortName(extFull)}) for ${onIntents().length} gateway(s). Nothing changes in Google Cloud until you apply.`}>
                Stage turn on
              </StageBtn>
            </div>
          </div>
        )}
      </div>

      <footer className="setup-foot">
        <Tip tip={pending.length ? `Add the ${pending.length} remaining step(s) to the cart in order: template, extension, permissions, turn on. Nothing changes in Google Cloud until you apply.` : "Every step is already in place or staged."}>
          <button className="btn btn-primary" disabled={!pending.length} onClick={() => addIntents(pending)}>
            <PlusIcon size={16} /> Stage all steps{pending.length ? ` (${pending.length})` : ""}
          </button>
        </Tip>
        <Tip tip={canApply ? "Open Apply with the staged setup items: you'll see the plan and confirm before anything changes." : "Open Review & output: the staged setup as Terraform, gcloud, REST and Python, in the right order."}>
          <button className="btn btn-outline" disabled={!anyStaged} onClick={review}>
            {canApply ? <PlayIcon size={14} /> : null} {canApply ? "Review and apply" : "Review"} <ArrowIcon size={14} />
          </button>
        </Tip>
      </footer>
    </section>
  );
}
