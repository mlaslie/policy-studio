// Gateways step: gateways in the region, their policies and bound agents; stage bind / unbind.
import { Tip, unavailable } from "../components/Tooltip";
import { useCallback, useEffect, useMemo, useState } from "react";
import { stepN, useLookup, useStudio } from "../store";
import { api } from "../api/client";
import type { EnforcementMode, Engine, Gateway, GatewayEnforcement, GatewayLogEntry, GatewayLogsResp, Intent } from "../api/types";
import { Badge, Callout, Disclosure, Load, Spinner, StepHeader, Term } from "../components/ui";
import { CodeView } from "../components/CodeView";
import { ArrowIcon, ClockIcon, EyeIcon, GatewayIcon, LockIcon, OpenInNewIcon, PlayIcon, PlusIcon, RefreshIcon, RobotIcon, ShieldIcon, SparkIcon, WarnIcon } from "../components/Icons";
import { intentKey, newId, shortName } from "../lib/policy";
import { RedeployHelp } from "../components/Redeploy";
import { useApplyGate } from "../components/Mode";
import { fmtDate, plural } from "../lib/util";
import { ShowOnMap } from "../components/ShowOnMap";
import { focusForGateway } from "../map/focus";
import { TIMING, effectText, stageTip } from "../lib/timing";
import { EGRESS_MODE, PSC_BIND_REASON, pscChips, privateEgressSummary } from "../lib/networking";

export function ProviderChip({ p }: { p: Gateway["authz_policies"][number] }) {
  const label = p.provider === "iap" ? "IAP" : p.provider === "model_armor" ? "Model Armor" : "Other";
  return (
    <div className={`policy-chip prov-${p.provider}`} title={p.name}>
      <span className="prov-icon">{p.provider === "iap" ? <LockIcon size={14} /> : p.provider === "model_armor" ? <SparkIcon size={14} /> : <ShieldIcon size={14} />}</span>
      <div>
        <div className="policy-chip-title">
          {label} <span className="muted">· {p.profile === "REQUEST_AUTHZ" ? "who may call what" : "content screening"}</span>
        </div>
        <div className="mono tiny muted">{shortName(p.name)}</div>
      </div>
      {p.enforcement && (
        <Badge tone={p.enforcement === "ENFORCE" ? "green" : "amber"} title={p.enforcement === "DRY_RUN" ? "Logs decisions but doesn't block" : "Blocks requests that fail the check"}>
          {p.enforcement === "ENFORCE" ? "Enforcing" : "Dry run"}
        </Badge>
      )}
    </div>
  );
}

function BindPicker({ gw, onDone }: { gw: Gateway; onDone: () => void }) {
  const { inv } = useLookup();
  const { addIntents } = useStudio();
  const engines = inv?.engines ?? [];
  const [sel, setSel] = useState("");
  const already = new Set(gw.bound_engines.filter((b) => b.direction === gw.type).map((b) => b.engine));
  const choices = engines.filter((e) => !already.has(e.name));
  const chosen = engines.find((e) => e.name === sel);
  const other = chosen?.gateways[gw.type];
  return (
    <div className="bind-picker">
      <label htmlFor={`bind-${gw.id}`}>Which Agent Runtime agent should send its {gw.type} traffic through {gw.id}?</label>
      <div className="row">
        <select id={`bind-${gw.id}`} value={sel} onChange={(e) => setSel(e.target.value)}>
          <option value="">Choose an agent…</option>
          {choices.map((e) => (
            <option key={e.name} value={e.name} disabled={!e.bindable} title={e.bindable ? undefined : e.bindable_reason ?? "Can't be bound"}>
              {e.display_name}
              {!e.bindable ? ` (can't be bound: ${e.psc_interface ? "PSC interface" : e.identity_type !== "AGENT_IDENTITY" ? "no Agent Identity" : "created before 2026-04-29"})` : e.gateways[gw.type] ? ` (now on ${shortName(e.gateways[gw.type]!)})` : ""}
            </option>
          ))}
        </select>
        <Tip tip={chosen ? `Stage binding ${chosen.display_name} to ${gw.id} in the cart. Nothing changes in Google Cloud until you apply. ${stageTip("bind_gateway")}` : "Choose an agent first."}>
          <button
            className="btn btn-primary"
            disabled={!chosen}
            onClick={() => {
              if (!chosen) return;
              addIntents([{ id: newId(), kind: "bind_gateway", gateway: { name: gw.name, direction: gw.type }, engine: chosen.name, engine_label: chosen.display_name }]);
              onDone();
            }}
          >
            Stage bind
          </button>
        </Tip>
        <button className="btn btn-text" onClick={onDone}>
          Cancel
        </button>
      </div>
      {choices.some((e) => !e.bindable) && (
        <div className="unbindable small">
          {choices
            .filter((e) => !e.bindable)
            .map((e) => (
              <Tip key={e.name} tip={e.bindable_reason ?? "This agent can't be bound to Agent Gateway."}>
                <span className="unbindable-item" tabIndex={0}>
                  <LockIcon size={12} /> {e.display_name} can't be bound
                </span>
              </Tip>
            ))}
          {choices.some((e) => !e.bindable && e.psc_interface) && <RedeployHelp reason={PSC_BIND_REASON} />}
          {choices.some((e) => !e.bindable && !e.psc_interface) && <RedeployHelp />}
        </div>
      )}
      {other && <p className="small warn-text"><WarnIcon size={13} /> It is currently bound to {shortName(other)}; this moves it.</p>}
      {!choices.length && <p className="muted small">Every agent is already bound.</p>}
      <p className="muted small">The agent redeploys when this is applied; it takes a few minutes. Nothing changes until you run the generated command.</p>
    </div>
  );
}

// ---------------- enforcement mode (Enforce / Dry run) ----------------

const EXT_NAME_RE = /^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;
const MODE_TEXT: Record<EnforcementMode, string> = { ENFORCE: "Enforce", DRY_RUN: "Dry run" };
const PROPAGATION = `Takes effect ${effectText("set_enforcement")}, sometimes before the operation reports done.`;

const extFull = (source: string, name: string) => source.replace(/\/authzExtensions\/[^/]+$/, `/authzExtensions/${name}`);
const listText = (xs: string[]) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

/** A free default name for a gateway's own IAP extension. */
function suggestName(gw: Gateway, taken: Set<string>): string {
  const base = `${gw.id}-iap-authz`.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 55);
  let n = base;
  let k = 2;
  while (taken.has(n)) n = `${base}-${k++}`;
  return n;
}

function useTakenExtensionNames(): Set<string> {
  const { gateways, modelArmor } = useStudio();
  return useMemo(() => {
    const s = new Set<string>();
    for (const g of gateways.data?.gateways ?? []) {
      if (g.enforcement?.extension) s.add(shortName(g.enforcement.extension));
      for (const p of g.authz_policies) if (p.extension) s.add(shortName(p.extension));
    }
    for (const x of modelArmor.data?.extensions ?? []) s.add(shortName(x.name));
    return s;
  }, [gateways.data, modelArmor.data]);
}

function EnforcementChange({ gw, enf, target, onDone }: { gw: Gateway; enf: GatewayEnforcement; target: EnforcementMode; onDone: () => void }) {
  const { addIntents, cart, openApply } = useStudio();
  const { blockedFor, generate } = useApplyGate();
  const taken = useTakenExtensionNames();
  const shared = enf.shared_with.map(shortName);
  const [choice, setChoice] = useState<"own" | "all">(shared.length ? "own" : "all");
  const [name, setName] = useState(() => suggestName(gw, taken));
  const nameErr = choice !== "own" ? null : !EXT_NAME_RE.test(name) ? "Lowercase letters, digits and hyphens, starting with a letter (at most 63)." : taken.has(name) ? "An extension with this name already exists." : null;
  const dry = target === "DRY_RUN";
  const gwRef = { name: gw.name, direction: gw.type };
  const build = (): Intent[] =>
    choice === "own" && shared.length
      ? [
          { id: newId(), kind: "dedicate_extension", gateway: gwRef, source_extension: enf.extension, new_name: name },
          { id: newId(), kind: "set_enforcement", gateway: gwRef, extension: extFull(enf.extension, name), mode: target, scope: "dedicated" },
        ]
      : [{ id: newId(), kind: "set_enforcement", gateway: gwRef, extension: enf.extension, mode: target, scope: shared.length ? "shared" : "dedicated" }];
  /** Stage (deduplicated) and return the cart ids of the staged items. */
  const stage = (): string[] => {
    const items = build();
    const ids = items.map((i) => cart.find((c) => intentKey(c) === intentKey(i))?.id ?? i.id);
    addIntents(items);
    return ids;
  };
  const preview = build();
  const applyReason = blockedFor(preview);
  const all = [gw.id, ...shared];
  return (
    <div className={`enf-change ${dry ? "enf-change-dry" : ""}`} role="group" aria-label={`Change ${gw.id} to ${MODE_TEXT[target]}`}>
      <div className="enf-change-title">
        {dry ? <WarnIcon size={15} /> : <ShieldIcon size={15} />} Switch {gw.id} to <b>{MODE_TEXT[target].toLowerCase()}</b>
      </div>
      <p className="small">
        {dry
          ? "Every call goes through, including ones without a grant. Google logs those as allowed; Policy Studio shows which ones enforcing would block, computed from the current grants. Use it for testing, not as a steady state."
          : "Calls without a matching roles/iap.egressor grant are blocked with 403. Check the “would have been denied” list first so enforcing doesn't break calls that should be allowed."}
      </p>
      {shared.length > 0 && (
        <>
          <Callout tone="warn" title={<>This extension also controls: {listText(shared)}</>}>
            The mode lives on the IAP authz extension <span className="mono">{shortName(enf.extension)}</span>, and {listText(shared)} use{shared.length === 1 ? "s" : ""} it too.
          </Callout>
          <div className="enf-choices" role="radiogroup" aria-label="Which gateways change">
            <Tip tip={`Create ${name || "a copy"} (same settings as ${shortName(enf.extension)}), point ${gw.id}'s IAP policy at it, then switch only the copy. ${listText(shared)} keep${shared.length === 1 ? "s" : ""} ${MODE_TEXT[enf.mode ?? "ENFORCE"].toLowerCase()}.`} block>
              <label className={`enf-choice ${choice === "own" ? "on" : ""}`}>
                <input type="radio" name={`enf-${gw.id}`} checked={choice === "own"} onChange={() => setChoice("own")} />
                <span>
                  <b>Give {gw.id} its own extension</b> <Badge tone="green">recommended</Badge>
                  <span className="block small muted">Only {gw.id} changes. Two steps: copy the extension, then point {gw.id}'s IAP policy at the copy.</span>
                </span>
              </label>
            </Tip>
            {choice === "own" && (
              <div className={`field enf-name ${nameErr ? "has-error" : ""}`}>
                <label htmlFor={`enf-name-${gw.id}`}>Name of the new extension</label>
                <input id={`enf-name-${gw.id}`} className="mono" value={name} onChange={(e) => setName(e.target.value.trim())} spellCheck={false} />
                {nameErr && <span className="small field-error">{nameErr}</span>}
              </div>
            )}
            <Tip tip={`Change the shared extension ${shortName(enf.extension)} in place: ${listText(all)} all switch to ${MODE_TEXT[target].toLowerCase()} together.`} block>
              <label className={`enf-choice ${choice === "all" ? "on" : ""}`}>
                <input type="radio" name={`enf-${gw.id}`} checked={choice === "all"} onChange={() => setChoice("all")} />
                <span>
                  <b>Change for all {all.length} gateways</b>
                  <span className="block small muted">{listText(all)} switch together.</span>
                </span>
              </label>
            </Tip>
          </div>
        </>
      )}
      <p className="tiny muted">
        <ClockIcon size={11} /> {PROPAGATION}
        {choice === "own" && shared.length > 0 && ` With its own extension, the policy update comes first (about 20 s); then ${TIMING.dedicate_extension.after}.`}
      </p>
      <div className="row">
        <Tip tip={`Add ${preview.length === 1 ? "this change" : "these 2 steps"} to the cart. Nothing changes in Google Cloud until you apply.${nameErr ? ` Unavailable: ${nameErr}` : ""}`}>
          <button
            className="btn btn-primary btn-small"
            disabled={!!nameErr}
            onClick={() => {
              stage();
              onDone();
            }}
          >
            Stage change
          </button>
        </Tip>
        {!generate && (
          <Tip tip={`Stage it and open Apply on just ${preview.length === 1 ? "this change" : "these steps"}. You'll confirm first${dry ? " and acknowledge that dry run stops blocking" : ""}.${unavailable(nameErr ?? applyReason)}`}>
            <button
              className="btn btn-outline btn-small"
              disabled={!!nameErr || !!applyReason}
              onClick={() => {
                const ids = stage();
                onDone();
                openApply(ids);
              }}
            >
              <PlayIcon size={13} /> Review &amp; apply
            </button>
          </Tip>
        )}
        <button className="btn btn-text btn-small" onClick={onDone}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function registryLabels(inv: ReturnType<typeof useLookup>["inv"]): Map<string, string> {
  const m = new Map<string, string>();
  const tail = (n: string) => (n.includes("/locations/") ? n.slice(n.indexOf("/locations/") + 1) : n);
  for (const x of [...(inv?.agents ?? []), ...(inv?.mcp_servers ?? []), ...(inv?.endpoints ?? [])]) m.set(tail(x.name), x.display_name);
  return m;
}

function WouldDeny({ gw }: { gw: Gateway }) {
  const { ctx } = useStudio();
  const { inv } = useLookup();
  const [data, setData] = useState<GatewayLogsResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [all, setAll] = useState(false);
  const labels = useMemo(() => registryLabels(inv), [inv]);
  const load = useCallback(
    async (refresh: boolean) => {
      setBusy(true);
      setErr(null);
      try {
        setData(await api.gatewayLogs(ctx, gw.name, "24h", refresh));
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [ctx, gw.name],
  );
  useEffect(() => {
    void load(false);
  }, [load]);
  const rows = (data?.entries ?? []).filter((e) => e.decision === "would_deny");
  const unknown = (data?.entries ?? []).filter((e) => e.decision === "unknown");
  // Platform calls: unregistered ones (decision "platform", not checked) and registered ones that were allowed (the
  // aiplatform endpoint, usually through a project-wide grant). A registered one that would be denied stays above.
  const platform = (data?.entries ?? []).filter((e) => e.decision === "platform" || (e.platform && e.decision === "allowed"));
  const platformHosts = [...platform.reduce((m, e) => m.set(e.host, (m.get(e.host) ?? 0) + 1), new Map<string, number>())].sort((a, b) => b[1] - a[1]);
  const checked = (data?.entries ?? []).filter((e) => e.computed && e.decision !== "platform").length;
  // The would-deny list covers the window unless the platform-free query was capped too (older backends: truncated).
  const partial = !!data && (data.checked_truncated ?? data.truncated);
  const shown = all ? rows : rows.slice(0, 6);
  const dest = (e: GatewayLogEntry) => {
    const r = e.registry_resource;
    const t = r && r.includes("/locations/") ? r.slice(r.indexOf("/locations/") + 1) : "";
    return labels.get(t) ?? e.destination ?? e.host;
  };
  const how = (e: GatewayLogEntry) =>
    e.caller?.how === "mtls"
      ? "Request logs don't name the caller; matched by the agent's mTLS client certificate, seen on its own Agent Runtime calls through this gateway."
      : "Request logs don't name the caller; this is the only agent bound to the gateway.";
  const row = (e: GatewayLogEntry, n: number) => (
    <li key={(e.insert_id ?? "") + n} className={e.decision === "unknown" ? "wd-unknown" : ""}>
      <span className="wd-who">
        <RobotIcon size={13} /> {e.agent ?? "unknown caller"}
        {e.agent_inferred && (
          <span className="tiny muted" title={how(e)}>
            {" "}
            (inferred)
          </span>
        )}
      </span>
      <ArrowIcon size={12} />
      <span className="wd-what">
        {dest(e)}
        {e.mcp_tool && <span className="mono tiny"> · {e.mcp_tool}</span>}
      </span>
      <span className="grow" />
      <span className="tiny muted" title={e.timestamp}>
        {fmtTime(e.timestamp)}
      </span>
      {e.console_url && (
        <a className="tiny" href={e.console_url} target="_blank" rel="noreferrer" aria-label="Open this entry in Cloud Logging">
          log
        </a>
      )}
      {e.reason && <span className="wd-why tiny muted">{e.reason}</span>}
    </li>
  );
  return (
    <section className="would-deny" aria-label="Would have been denied in the last 24 hours">
      <div className="would-deny-head">
        <h5>
          Would have been denied <span className="muted">(last 24 h, computed)</span>
        </h5>
        {data && <Badge tone={rows.length ? "amber" : "neutral"}>{rows.length}{partial ? "+" : ""}</Badge>}
        <span className="grow" />
        <Tip tip="Read the gateway's request log again from Cloud Logging (read-only).">
          <button className="icon-btn" aria-label="Refresh the would-be-denied list" onClick={() => void load(true)} disabled={busy}>
            <RefreshIcon size={14} className={busy ? "spin" : ""} />
          </button>
        </Tip>
        {data?.console_url && (
          <Tip tip="Open these log entries in Cloud Logging (new tab).">
            <a className="icon-btn" href={data.console_url} target="_blank" rel="noreferrer" aria-label="Open in Cloud Logging">
              <OpenInNewIcon size={14} />
            </a>
          </Tip>
        )}
      </div>
      <p className="tiny muted wd-caveat">
        Google logs these calls as allowed: in dry run the request log doesn't say what IAP would have denied. Policy Studio computes it from each caller's <b>current</b> roles/iap.egressor grants on the destination (not
        project-level ones), and the caller is inferred, since the log doesn't name it.
      </p>
      {err ? (
        <p className="small field-error">
          Couldn't read the gateway's request log: {err}
          {/permission|403/i.test(err) ? " (reading logs needs roles/logging.viewer)." : ""}
        </p>
      ) : !data ? (
        <Spinner label="Reading the request log…" />
      ) : rows.length === 0 ? (
        <p className="small muted">
          No call in the last 24 hours would have been denied by the current grants ({plural(checked, "allowed call")} checked
          {data.entries.length > checked + platform.length ? `, ${plural(data.entries.length - checked - platform.length, "other entry", "other entries")}` : ""}). Either every call has a grant, or there was little traffic.
        </p>
      ) : (
        <>
          <ul className="would-deny-list">{shown.map(row)}</ul>
          {rows.length > shown.length && (
            <button className="link-btn small" onClick={() => setAll(true)}>
              Show all {rows.length}
            </button>
          )}
        </>
      )}
      {data && data.truncated && (
        <p className="tiny muted wd-caveat">
          {partial
            ? "The log had more entries than Policy Studio reads (up to 1000), so older would-be-denied calls may be missing."
            : "Older platform calls were left out; every other call of the last 24 hours was checked."}
        </p>
      )}
      {data && unknown.length > 0 && (
        <Disclosure summary={<span className="small">{plural(unknown.length, "call")} couldn't be checked</span>}>
          <ul className="would-deny-list">{unknown.slice(0, 20).map(row)}</ul>
        </Disclosure>
      )}
      {data && platform.length > 0 && (
        <Disclosure summary={<span className="small muted">{plural(platform.length, "platform call")}</span>}>
          <p className="tiny muted wd-caveat">
            The agent runtime's own traffic (Agent Platform APIs, internal addresses such as 240.0.0.2). Unregistered hosts aren't covered by roles/iap.egressor grants, so they aren't checked; a registered one (an aiplatform endpoint in Agent Registry) is
            checked like any destination and listed above if it would be denied.
          </p>
          <ul className="would-deny-list wd-platform">
            {platformHosts.map(([h, n]) => (
              <li key={h}>
                <span className="mono tiny">{h || "(no host)"}</span>
                <span className="grow" />
                <span className="tiny muted">× {n}</span>
              </li>
            ))}
          </ul>
        </Disclosure>
      )}
    </section>
  );
}

const fmtTime = (iso: string) => {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

function Enforcement({ gw }: { gw: Gateway }) {
  const { cart } = useStudio();
  const enf = gw.enforcement;
  const [target, setTarget] = useState<EnforcementMode | null>(null);
  if (!enf) return null;
  const mode = enf.mode;
  const staged = cart.find((i) => i.kind === "set_enforcement" && shortName(i.gateway?.name ?? "") === gw.id);
  const sharedBy = cart.find(
    (i) => i.kind === "set_enforcement" && i.scope === "shared" && i.extension && shortName(i.extension) === shortName(enf.extension) && shortName(i.gateway?.name ?? "") !== gw.id,
  );
  const disabledWhy = !enf.editable ? enf.reason ?? "This gateway has no IAP policy whose mode Policy Studio can change." : null;
  const shared = enf.shared_with.map(shortName);
  const TIPS: Record<EnforcementMode, string> = {
    ENFORCE: `Enforce: IAP blocks calls from bound agents that don't hold roles/iap.egressor on the destination (403).${shared.length ? ` Shared with ${listText(shared)}.` : ""}`,
    DRY_RUN: `Dry run: IAP lets every call through, so nothing is blocked.${shared.length ? ` Shared with ${listText(shared)}.` : ""}`,
  };
  return (
    <div className="gw-section enf">
      <h4>
        <Term k="dry-run">Enforcement</Term>
      </h4>
      {mode === "DRY_RUN" && (
        <div className="enf-banner" role="status">
          <WarnIcon size={15} /> <b>Dry run: nothing is blocked on this gateway</b>
        </div>
      )}
      <div className="enf-row">
        <div className={`seg enf-seg ${disabledWhy ? "enf-seg-off" : ""}`} role="radiogroup" aria-label={`Enforcement mode of ${gw.id}`}>
          {(["ENFORCE", "DRY_RUN"] as const).map((m) => (
            <Tip key={m} tip={disabledWhy ? `Unavailable: ${disabledWhy}` : mode === m ? `${TIPS[m]} This is the current mode.` : `${TIPS[m]} Click to stage the change (nothing changes until you apply). ${stageTip("set_enforcement")}`}>
              <button
                type="button"
                role="radio"
                aria-checked={mode === m}
                disabled={!!disabledWhy}
                className={`seg-btn ${mode === m ? `on ${m === "DRY_RUN" ? "on-dry" : "on-enforce"}` : ""} ${target === m ? "pending" : ""}`}
                onClick={() => setTarget(mode === m ? null : m)}
              >
                {m === "ENFORCE" ? <ShieldIcon size={13} /> : <EyeIcon size={13} />} {MODE_TEXT[m]}
              </button>
            </Tip>
          ))}
        </div>
        {!disabledWhy && (
          <span className="tiny muted enf-meta">
            <span className="mono">{shortName(enf.extension)}</span>
            {shared.length > 0 && (
              <Tip tip={`The mode lives on this IAP authz extension, which ${listText(shared)} use${shared.length === 1 ? "s" : ""} too: changing it in place changes all of them.`}>
                <span className="enf-shared" tabIndex={0}>
                  {" "}
                  · shared with {listText(shared)}
                </span>
              </Tip>
            )}
          </span>
        )}
        {staged && <Badge tone="blue">{MODE_TEXT[staged.mode ?? "ENFORCE"]} staged</Badge>}
        {!staged && sharedBy && <Badge tone="blue">{MODE_TEXT[sharedBy.mode ?? "ENFORCE"]} staged (shared)</Badge>}
      </div>
      {disabledWhy && <p className="small muted">{disabledWhy}</p>}
      {target && enf.editable && target !== mode && <EnforcementChange gw={gw} enf={enf} target={target} onDone={() => setTarget(null)} />}
      {mode === "DRY_RUN" &&
        (gw.type === "egress" ? (
          <WouldDeny gw={gw} />
        ) : (
          <p className="tiny muted">Would-be denials are computed for egress gateways only (from the callers' roles/iap.egressor grants); the request log doesn't mark them.</p>
        ))}
    </div>
  );
}

/** "Private egress" row of a gateway card: VPC, private domains, egress mode, template vs inline (detection only). */
export function PrivateEgressRow({ gw }: { gw: Gateway }) {
  const pe = gw.private_egress;
  if (!pe && gw.type !== "egress") return null;
  return (
    <div className="gw-section gw-private" data-testid="private-egress">
      <h4>
        <Term k="private-egress">Private egress</Term>
      </h4>
      {!pe ? (
        <p className="muted small">Public egress only.</p>
      ) : (
        <>
          <div className="row wrap" title={privateEgressSummary(pe)}>
            <Badge tone="blue">{pe.vpc ? `VPC ${pe.vpc}` : "VPC unknown"}</Badge>
            {pe.source === "template" ? (
              <Badge tone="neutral" title={pe.template ?? ""}>
                <Term k="connectivity-template">Template</Term> {shortName(pe.template ?? "")}
              </Badge>
            ) : (
              <Badge tone="amber" title="The older inline form (networkConfig). VPC Service Controls and custom trust need a connectivity template.">
                Inline networkConfig
              </Badge>
            )}
            {pe.vpc_egress && <Badge tone={pe.vpc_egress === "ALL_TRAFFIC" ? "amber" : "neutral"}>{EGRESS_MODE[pe.vpc_egress] ?? pe.vpc_egress}</Badge>}
            {pe.custom_trust && <Badge tone="neutral">Custom trust</Badge>}
          </div>
          {pe.dns_domains.length > 0 && (
            <div className="domain-chips">
              {pe.dns_domains.map((d) => (
                <span key={d} className="domain-chip mono tiny">
                  {d}
                </span>
              ))}
            </div>
          )}
          {pe.error && <p className="small warn-text">Private networking: {pe.error}.</p>}
          {pe.network_attachment && <div className="mono tiny muted wrap">{pe.network_attachment}</div>}
        </>
      )}
    </div>
  );
}

function GatewayCard({ gw }: { gw: Gateway }) {
  const { addIntents, cart } = useStudio();
  const { engineByName } = useLookup();
  const [binding, setBinding] = useState(false);
  const bound = gw.bound_engines.filter((b) => b.direction === gw.type);
  const staged = (e: string) => cart.some((i) => i.kind === "unbind_gateway" && i.engine === e && i.gateway?.name === gw.name);
  const hasIap = gw.authz_policies.some((p) => p.provider === "iap");
  return (
    <article className={`card gw-card ${gw.enforcement?.mode === "DRY_RUN" ? "gw-dry" : ""}`} id={`gw-${gw.id}`}>
      <header className="gw-head">
        <span className={`gw-icon gw-${gw.type}`}>
          <GatewayIcon size={20} />
        </span>
        <div className="gw-titles">
          <h3>{gw.id}</h3>
          <div className="muted small">
            <Badge tone={gw.type === "egress" ? "blue" : "purple"}>{gw.type === "egress" ? "Egress" : "Ingress"}</Badge>{" "}
            <span className="mono tiny">{gw.governed_access_path}</span> · created {fmtDate(gw.create_time)}
          </div>
        </div>
        <ShowOnMap focus={focusForGateway(gw)} what={gw.id} />
      </header>
      <p className="gw-explain">
        {gw.type === "egress" ? (
          <>Checks calls that bound agents make <b>out</b> to other agents, MCP servers and APIs. <Term k="egress">Default deny</Term>: only granted destinations are reachable.</>
        ) : (
          <>Checks calls coming <b>in</b> to bound agents, for example from a Gemini Enterprise app.</>
        )}
      </p>
      {gw.error && <Callout tone="danger" title="Partly unreadable">{gw.error}</Callout>}

      <div className="gw-section">
        <h4>Policies attached</h4>
        {gw.authz_policies.length ? (
          <div className="policy-chips">
            {gw.authz_policies.map((p) => (
              <ProviderChip key={p.name} p={p} />
            ))}
          </div>
        ) : (
          <p className="muted small">None. {gw.type === "ingress" ? `Prompts reach the agent unscreened. You can turn on Model Armor in step ${stepN("model-armor")}.` : "Nothing is checked."}</p>
        )}
        {gw.type === "egress" && !hasIap && <Callout tone="warn" title="No IAP policy">Without an IAP REQUEST_AUTHZ policy, grants are not enforced on this gateway.</Callout>}
      </div>

      <Enforcement gw={gw} />

      <div className="gw-section">
        <h4>
          <Term k="agent-registry">Registry</Term>
        </h4>
        {gw.registries.map((r) => (
          <div key={r} className="mono tiny muted wrap">
            {r}
          </div>
        ))}
      </div>

      <PrivateEgressRow gw={gw} />

      <div className="gw-section">
        <h4>Agents bound to it ({bound.length})</h4>
        {bound.length ? (
          <ul className="bound-list">
            {bound.map((b) => {
              const e = engineByName.get(b.engine);
              return (
                <li key={b.engine}>
                  <RobotIcon size={16} />
                  <div className="grow">
                    <div>
                      {b.display_name}{" "}
                      {e && pscChips(e).slice(1).map((c) => (
                        <Badge key={c.text} tone="red" title={c.tip}>
                          {c.text}
                        </Badge>
                      ))}
                    </div>
                    <div className="mono tiny muted">{shortName(b.engine)}{e ? ` · created ${fmtDate(e.create_time)}` : ""}</div>
                  </div>
                  {staged(b.engine) ? (
                    <Badge tone="amber">Unbind staged</Badge>
                  ) : (
                    <Tip tip={`Stage detaching ${b.display_name} from ${gw.id} in the cart. Nothing changes in Google Cloud until you apply. ${stageTip("unbind_gateway")}`}>
                      <button
                        className="btn btn-small btn-outline"
                        onClick={() => addIntents([{ id: newId(), kind: "unbind_gateway", gateway: { name: gw.name, direction: gw.type }, engine: b.engine, engine_label: b.display_name }])}
                      >
                        Unbind
                      </button>
                    </Tip>
                  )}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="muted small">No agents yet.</p>
        )}
        {binding ? (
          <BindPicker gw={gw} onDone={() => setBinding(false)} />
        ) : (
          <Tip tip={`Pick an agent to send its ${gw.type} traffic through ${gw.id}. Binding is staged in the cart; nothing changes until you apply. ${stageTip("bind_gateway")}`}>
            <button className="btn btn-tonal" onClick={() => setBinding(true)}>
              <PlusIcon size={16} /> Bind an agent…
            </button>
          </Tip>
        )}
      </div>
    </article>
  );
}

function Unprotected({ engines, egress }: { engines: Engine[]; egress?: Gateway }) {
  const { addIntents, cart } = useStudio();
  const loose = engines.filter((e) => !e.gateways.egress);
  if (!loose.length) return null;
  return (
    <Callout tone="warn" title={`${loose.length} agent${loose.length > 1 ? "s are" : " is"} not behind an egress gateway`}>
      <p>Their outbound calls go straight out: grants and Model Armor don't apply to them.</p>
      <ul className="plain-list">
        {loose.map((e) => {
          const staged = cart.some((i) => i.kind === "bind_gateway" && i.engine === e.name);
          return (
            <li key={e.name}>
              <b>{e.display_name}</b>{" "}
              {!e.bindable ? (
                <span className="muted small">can't be bound: {e.bindable_reason ?? `created ${fmtDate(e.create_time)}, before 2026-04-29. Redeploy it to protect it.`}</span>
              ) : staged ? (
                <Badge tone="blue">Bind staged</Badge>
              ) : egress ? (
                <Tip tip={`Stage binding ${e.display_name} to ${egress.id} in the cart. Nothing changes in Google Cloud until you apply. ${stageTip("bind_gateway")}`}>
                  <button
                    className="link-btn"
                    onClick={() => addIntents([{ id: newId(), kind: "bind_gateway", gateway: { name: egress.name, direction: "egress" }, engine: e.name, engine_label: e.display_name } satisfies Intent])}
                  >
                    Stage bind to {egress.id}
                  </button>
                </Tip>
              ) : null}
            </li>
          );
        })}
      </ul>
    </Callout>
  );
}

function EmptyGateways() {
  const { ctx } = useStudio();
  const yaml = `# Coming in P4: Policy Studio will create these for you.
cat > egress.yaml <<'EOF'
name: agents-egress
governedAccessPath: AGENT_TO_ANYWHERE
registries:
- //agentregistry.googleapis.com/projects/${ctx.gateway_project || ctx.project}/locations/${ctx.region}
EOF
gcloud network-services agent-gateways import agents-egress \\
  --source=egress.yaml --location=${ctx.region} --project=${ctx.gateway_project || ctx.project}`;
  return (
    <div className="card empty-card">
      <GatewayIcon size={36} />
      <h3>No gateways in {ctx.region} yet</h3>
      <p>
        A gateway is the checkpoint your agents' traffic flows through. You'll usually want one <b>egress</b> gateway (checks what your agents call) and, if
        Gemini Enterprise calls your agents, one <b>ingress</b> gateway.
      </p>
      <p className="muted small">Creating gateways from Policy Studio arrives in P4. Until then, this is roughly what it takes:</p>
      <CodeView code={yaml} lang="shell" label="Create an egress gateway (preview)" />
    </div>
  );
}

export function GatewaysStep() {
  const { gateways, inventory } = useStudio();
  const { egress } = useLookup();
  return (
    <>
      <StepHeader
        title="Gateways"
        lead={
          <>
            <Term k="agent-gateway">Agent Gateways</Term> are checkpoints for agent traffic. Here you can see which policies each one enforces and which agents use it. Binding and unbinding
            agents is staged in the cart; nothing changes until you run the commands.
          </>
        }
      />
      <Load l={gateways} what="gateways">
        {(d) => (
          <>
            <div className="rules">
              <div className="rule">
                <GatewayIcon size={16} />
                <span>
                  <b>One egress and one ingress gateway</b> per project and region for Agent Runtime agents.
                </span>
              </div>
              <div className="rule">
                <RobotIcon size={16} />
                <span>
                  <Term k="runtime">Agent Runtime agents</Term> created <b>before 2026-04-29</b> can't be bound.
                </span>
              </div>
            </div>
            {d.notes.filter((n) => !/one egress|2026-04-29/i.test(n)).map((n) => (
              <Callout key={n} tone="info">{n}</Callout>
            ))}
            {inventory.data && <Unprotected engines={inventory.data.engines} egress={egress} />}
            {d.gateways.length === 0 ? (
              <EmptyGateways />
            ) : (
              <div className="gw-grid">
                {[...d.gateways].sort((a, b) => (a.type === b.type ? 0 : a.type === "egress" ? -1 : 1)).map((g) => (
                  <GatewayCard key={g.name} gw={g} />
                ))}
              </div>
            )}
            {d.gateways.length > 0 && (
              <Disclosure summary="How do I create another gateway?">
                <p className="muted small">Creating gateways from Policy Studio arrives in P4. Remember the limit: one of each type per project and region.</p>
              </Disclosure>
            )}
          </>
        )}
      </Load>
    </>
  );
}
