// The policy panel (docs/VISUALIZATION_PLAN.md §6.3, §8, §9): a glass overlay on the right of the canvas with the
// details of a clicked line or node and what you can do about it. One card per Reason (the binding, its condition and
// its context); a Client-to-Agent line has no Reason, so it shows its gateway and Model Armor instead. Every action
// only stages: Revoke, Change access (one `modify`), Limit to this agent, Allow…, Bind, Unbind, Model Armor on or off;
// the footer says so and leads to Review. Esc closes it and focus returns to the line or node it was opened from (a line's
// panel takes focus when it opens; a node's doesn't, so the arrow keys keep moving the node).
import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import type { Engine, Gateway, Intent, Inventory } from "../api/types";
import { api } from "../api/client";
import { useLookup, useStudio } from "../store";
import { Badge, Callout, Disclosure, KindIcon } from "../components/ui";
import { CodeView } from "../components/CodeView";
import { CopyButton } from "../components/Glass";
import { Tip } from "../components/Tooltip";
import { RedeployHelp } from "../components/Redeploy";
import { AccessChooser, accessOf, blocking, draftLint, draftOf, type AccessDraft } from "../components/AccessChooser";
import { ArrowIcon, BookIcon, CheckIcon, ClockIcon, CloseIcon, PencilIcon, TrashIcon, WarnIcon } from "../components/Icons";
import { checksFor, type Check } from "../lib/checks";
import { grantToIntent, revokesGrant } from "../lib/grants";
import { KIND_LABEL, ROLE, accessFromCondition, accessWords, intentEnglish, intentKey, shortName } from "../lib/policy";
import { TemplateCard } from "../steps/ModelArmorStep";
import { plural } from "../lib/util";
import type { PEdge, PNode, Reason } from "./graph";
import { evaluateTools } from "./evaluate";
import { PENDING_WORD, VERDICT_LABEL, VIA_LABEL } from "./toFlow";
import { pendingText } from "./diff";
import { allowFor, bindFor, ingressInfo, isGroupGrant, limitToAgent, modifyFor, reachedBy, reasonGrant, revokeFor, sameAccess } from "./actions";

type Props = {
  edge: PEdge | null;
  node: PNode | null;
  inv: Inventory;
  gateways: Gateway[];
  nodeOf: (id: string) => PNode | undefined;
  label: (id: string) => string;
  onClose: () => void;
};

/** The live /render sentence for an intent being built (debounced, as in the builder); the local one meanwhile. */
function useRendered(intent: Intent | null): string | null {
  const { ctx } = useStudio();
  const [text, setText] = useState<string | null>(null);
  const key = intent ? intentKey(intent) : "";
  useEffect(() => {
    setText(null);
    if (!intent) return;
    let live = true;
    const t = setTimeout(() => {
      api
        .render(ctx, [intent])
        .then((r) => live && setText(r.items[0]?.english ?? null))
        .catch(() => undefined);
    }, 300);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, ctx]);
  return intent ? (text ?? intentEnglish(intent)) : null;
}

/** Reaching the gateway card on the Gateways step (the dry run → enforce choice lives there). */
function useOpenGateway() {
  const { goto } = useStudio();
  return (gw: string) => {
    goto("gateways");
    setTimeout(() => document.getElementById(`gw-${gw.split("/").pop()}`)?.scrollIntoView({ behavior: "smooth", block: "start" }), 60);
  };
}

export default function PolicyPanel({ edge, node, inv, gateways, nodeOf, label, onClose }: Props) {
  const { cart, openReview } = useStudio();
  const ref = useRef<HTMLElement>(null);
  const subject = edge?.id ?? node?.id ?? "";
  // A line's panel takes focus; a selected node keeps it, so the arrow keys still move the node.
  useEffect(() => {
    if (edge) ref.current?.focus({ preventScroll: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subject]);
  const onKey = (e: ReactKeyboardEvent) => {
    if (e.key !== "Escape") return;
    e.stopPropagation();
    onClose();
  };
  const from = edge ? label(edge.caller && edge.caller !== edge.target ? edge.caller : edge.source) : "";
  return (
    <aside className="pmap-panel glass" ref={ref} tabIndex={-1} aria-label={edge ? `Policy for the line ${from} to ${label(edge.target)}` : `Details of ${node?.label ?? ""}`} onKeyDown={onKey}>
      <div className="pmap-panel-head">
        <div className="grow">
          <div className="small muted">{edge ? (edge.direction === "egress" ? "Line" : "Client-to-Agent line") : "Selected"}</div>
          <h3>{edge ? `${from} → ${label(edge.target)}` : node?.label}</h3>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close details (Esc)" title="Close (Esc)">
          <CloseIcon size={16} />
        </button>
      </div>
      <div className="pmap-panel-body">
        {edge ? <EdgeDetails edge={edge} inv={inv} gateways={gateways} nodeOf={nodeOf} label={label} /> : node ? <NodeDetails node={node} inv={inv} gateways={gateways} label={label} /> : null}
      </div>
      <div className="pmap-panel-foot">
        <span className="small grow">
          Nothing changes until you Review and Apply. <span className="muted">{plural(cart.length, "item")} in the cart.</span>
        </span>
        <button type="button" className="btn btn-small btn-tonal" onClick={() => openReview(null)} disabled={!cart.length}>
          Review <ArrowIcon size={14} />
        </button>
      </div>
    </aside>
  );
}

// ------------------------------------------------------------------ a line
function EdgeDetails({ edge, inv, gateways, nodeOf, label }: { edge: PEdge; inv: Inventory; gateways: Gateway[]; nodeOf: (id: string) => PNode | undefined; label: (id: string) => string }) {
  const openGateway = useOpenGateway();
  const parts = edge.parts ?? [edge];
  const gwNode = edge.gateway ? nodeOf(edge.gateway) : undefined;
  const caller = edge.caller ? inv.engines.find((e) => e.name === edge.caller) : undefined;
  const dest = nodeOf(edge.target);
  const ma = gwNode?.modelArmor;
  return (
    <>
      <p className="pmap-verdict-row">
        <span className={`pmap-verdict st-${edge.verdict}`}>{VERDICT_LABEL[edge.verdict]}</span>
        {edge.label && edge.label !== "?" && <span className="small muted"> {edge.label}</span>}
      </p>
      {edge.pending && (
        <div className="pmap-staged">
          <div className="small">
            <ClockIcon size={13} /> <b>Staged: {PENDING_WORD[edge.pending]}.</b> {pendingText(edge)}
          </div>
          <StagedList ids={edge.intents ?? []} />
        </div>
      )}

      {/* context: gateway, mode, Model Armor, shared extension */}
      {edge.direction === "egress" && (
        <dl className="pmap-dl">
          <dt>Gateway</dt>
          <dd>
            {edge.gateway ? (
              <>
                <b>{label(edge.gateway)}</b> · {edge.mode === "DRY_RUN" ? "dry run" : edge.mode === "ENFORCE" ? "enforcing" : "no IAP policy"}
              </>
            ) : edge.caller?.startsWith("pseudo:") ? (
              "Each agent's own egress gateway"
            ) : (
              "None: traffic goes straight out, grants aren't checked"
            )}
          </dd>
          {edge.gateway && (
            <>
              <dt>Model Armor</dt>
              <dd>{ma?.enabled ? `On${ma.dryRun ? " (dry run: screening, not blocking)" : ""}${ma.template ? `, template ${ma.template}` : ""}` : "Off: content isn't screened"}</dd>
            </>
          )}
          {gwNode?.shared?.length ? (
            <>
              <dt>Shared extension</dt>
              <dd>The IAP extension also serves {gwNode.shared.map((s) => s.split("/").pop()).join(", ")}: their enforcement mode changes together.</dd>
            </>
          ) : null}
        </dl>
      )}
      {edge.direction === "egress" && ma?.enabled && ma.summary?.length ? (
        <Disclosure summary="Model Armor filters">
          <ul className="plain-list small">
            {ma.summary.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </Disclosure>
      ) : null}
      {edge.mode === "DRY_RUN" && edge.gateway && (
        <Callout tone="warn" title="Dry run: nothing is blocked">
          The gateway decides, but every call passes and is logged as allowed.{" "}
          <button type="button" className="link-btn" onClick={() => openGateway(edge.gateway!)}>
            Enforce it on the gateway card
          </button>
        </Callout>
      )}
      {edge.direction === "ingress" && <IngressDetails edge={edge} inv={inv} gateways={gateways} />}

      {/* default deny: Allow… */}
      {edge.implicit && caller && dest && (
        <>
          <p className="small">
            No grant names {caller.display_name} on {dest.label}, so the gateway denies it by default{edge.mode === "DRY_RUN" ? " (once it enforces; in dry run the call passes and is logged)" : ""}.
          </p>
          <AllowBox engine={caller} dest={dest} inv={inv} />
        </>
      )}

      {/* no gateway: grants are never checked */}
      {(edge.verdict === "dormant" || edge.verdict === "direct") &&
        edge.direction === "egress" &&
        [...new Set(parts.map((p) => p.caller))].map((c) => {
          const e = inv.engines.find((x) => x.name === c);
          return e && !e.gateways.egress ? <BindBox key={e.name} engine={e} gateways={gateways} /> : null;
        })}

      {parts.some((p) => p.reasons.length) && (
        <>
          <h4 className="pmap-h4">{parts.length > 1 ? `Why: ${plural(parts.length, "agent")} on this line` : "Why"}</h4>
          {parts.map((p) =>
            p.reasons.map((r, i) => <ReasonCard key={`${p.caller}|${i}|${r.binding.member}|${r.resource}`} r={r} part={p} multi={parts.length > 1} inv={inv} label={label} />),
          )}
        </>
      )}
    </>
  );
}

/** Lists of agents longer than this are folded (a Client-to-Agent lane can hold dozens). */
const FOLD = 6;

/** A Client-to-Agent line (§6.3): the gateway, its Model Armor template (summary and filters), an IAP policy exactly as
 *  configured, and what can be staged: Model Armor on or off (or the guided setup), Unbind, Bind. There's no allow
 *  policy: the gateway screens content, it doesn't check who calls. */
function IngressDetails({ edge, inv, gateways }: { edge: PEdge; inv: Inventory; gateways: Gateway[] }) {
  const { modelArmor, cart, addIntents, openMaSetup } = useStudio();
  const info = useMemo(() => ingressInfo(edge, inv, gateways, modelArmor.data), [edge, inv, gateways, modelArmor.data]);
  const { gateway: gw, ma, maAction } = info;
  const tmpl = ma?.template ?? null;
  const maDry = !!gw?.authz_policies.some((p) => p.profile === "CONTENT_AUTHZ" && p.enforcement === "DRY_RUN");
  const maStaged = gw ? cart.find((i) => (i.kind === "model_armor_on" || i.kind === "model_armor_off") && i.gateway?.name === gw.name) : undefined;
  const staged = (kind: Intent["kind"], engine: string) => cart.some((i) => i.kind === kind && i.engine === engine && i.gateway?.direction === "ingress");
  const fold = (n: number, body: ReactNode, what: string) => (n > FOLD ? <Disclosure summary={`${plural(n, "agent")} ${what}`}>{body}</Disclosure> : body);
  return (
    <>
      <Callout tone="info" title="No allow policy to show here">
        A Client-to-Agent gateway doesn't check caller identity: it screens content with Model Armor. Who may call an agent is decided by the agent's Agent Runtime IAM, which Policy Studio doesn't read.
      </Callout>
      <dl className="pmap-dl">
        <dt>Gateway</dt>
        <dd>
          {gw ? (
            <>
              <b>{gw.id}</b> · Client-to-Agent
            </>
          ) : (
            "None: calls reach the agent directly and nothing is screened"
          )}
        </dd>
        {gw && (
          <>
            <dt>Model Armor</dt>
            <dd>{ma?.enabled ? `On${maDry ? " (dry run: screening, not blocking)" : ""}${tmpl ? `, template ${tmpl.id}` : ""}` : "Off: prompts and answers aren't screened"}</dd>
          </>
        )}
        {info.iap && (
          <>
            <dt>IAP policy</dt>
            <dd>
              <Badge tone="neutral" title="Configured; Client-to-Agent doesn't check caller identity.">
                IAP REQUEST_AUTHZ{info.iap.enforcement ? ` · ${info.iap.enforcement === "DRY_RUN" ? "dry run" : "enforce"}` : ""}
              </Badge>
              <div className="small muted">Configured; Client-to-Agent doesn't check caller identity.</div>
              <div className="mono tiny muted pmap-wrap">{shortName(info.iap.name)}</div>
            </dd>
          </>
        )}
      </dl>
      {ma?.enabled && tmpl && (
        <>
          {tmpl.summary?.length ? (
            <ul className="plain-list small" aria-label={`What template ${tmpl.id} screens`}>
              {tmpl.summary.map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
          ) : null}
          <Disclosure summary={`Filters of template ${tmpl.id}`}>
            <TemplateCard t={tmpl} />
          </Disclosure>
        </>
      )}
      {ma?.enabled && !tmpl && <p className="small warn-text">The Model Armor policy is attached, but its template couldn't be read.</p>}

      {gw && maAction && (
        <div className="pmap-actions">
          {maStaged ? (
            <Badge tone={maStaged.kind === "model_armor_off" ? "red" : "blue"}>
              <ClockIcon size={11} /> {maStaged.kind === "model_armor_on" ? "Model Armor on staged" : "Model Armor off staged"}
            </Badge>
          ) : maAction.kind === "off" ? (
            <Tip tip={`Stage turning off Model Armor on ${gw.id} (removes its content-screening policy): prompts reach its agents unscreened. Apply asks you to confirm it. Nothing changes until you Review and Apply.`}>
              <button type="button" className="btn btn-small btn-danger" onClick={() => addIntents([maAction.intent])}>
                Turn Model Armor off
              </button>
            </Tip>
          ) : maAction.kind === "on" ? (
            <Tip tip={`Stage turning on Model Armor for ${gw.id} (attaches a content-screening policy). Nothing changes until you Review and Apply.`}>
              <button type="button" className="btn btn-small btn-primary" onClick={() => addIntents([maAction.intent])}>
                Turn Model Armor on
              </button>
            </Tip>
          ) : (
            <Tip tip="This region has no Model Armor authz extension yet. The guided setup stages the template, the extension and the service agent roles, and turning it on here.">
              <button type="button" className="btn btn-small btn-tonal" onClick={openMaSetup}>
                Set up Model Armor <ArrowIcon size={13} />
              </button>
            </Tip>
          )}
        </div>
      )}

      {info.bound.length > 0 &&
        fold(
          info.bound.length,
          <ul className="pmap-agents">
            {info.bound.map(({ engine, unbind }) => (
              <li key={engine.name}>
                <span className="grow small">
                  <b>{engine.display_name}</b> is bound to {gw!.id}
                </span>
                {staged("unbind_gateway", engine.name) ? (
                  <Badge tone="red">
                    <ClockIcon size={11} /> Unbind staged
                  </Badge>
                ) : (
                  <Tip tip={`Stage unbinding ${engine.display_name} from ${gw!.id}: calls then reach it directly, unscreened. The agent redeploys when it's applied, and Apply asks you to confirm it.`}>
                    <button type="button" className="btn btn-small btn-danger" onClick={() => addIntents([unbind])}>
                      Unbind
                    </button>
                  </Tip>
                )}
              </li>
            ))}
          </ul>,
          `bound to ${gw?.id ?? "the gateway"}`,
        )}
      {info.unbound.length > 0 &&
        fold(
          info.unbound.length,
          <ul className="pmap-agents">
            {info.unbound.map(({ engine, why }) => (
              <IngressBind key={engine.name} engine={engine} why={why} ingress={info.ingress} prefer={gw?.name} staged={staged("bind_gateway", engine.name)} />
            ))}
          </ul>,
          "not bound for ingress",
        )}
    </>
  );
}

/** Bind an agent that has no ingress gateway: a gateway choice when there's more than one; disabled with the reason
 *  (and the redeploy help) when it can't be bound. */
function IngressBind({ engine, why, ingress, prefer, staged }: { engine: Engine; why: string | null; ingress: Gateway[]; prefer?: string; staged: boolean }) {
  const { addIntents } = useStudio();
  const [gw, setGw] = useState(prefer && ingress.some((g) => g.name === prefer) ? prefer : (ingress[0]?.name ?? ""));
  const target = ingress.find((g) => g.name === gw);
  return (
    <li>
      <span className="grow small">
        <b>{engine.display_name}</b> has no ingress gateway
        {why && (
          <span className="warn-text">
            {" "}
            <WarnIcon size={12} /> {why}
          </span>
        )}
      </span>
      {staged ? (
        <Badge tone="blue">
          <ClockIcon size={11} /> Binding staged
        </Badge>
      ) : (
        <>
          {ingress.length > 1 && (
            <select className="pmap-select" value={gw} onChange={(e) => setGw(e.target.value)} aria-label={`Ingress gateway for ${engine.display_name}`} disabled={!!why}>
              {ingress.map((g) => (
                <option key={g.name} value={g.name}>
                  {g.id}
                </option>
              ))}
            </select>
          )}
          <Tip tip={why ?? `Stage binding ${engine.display_name} to ${target?.id}: calls to it then go through the gateway. The agent redeploys when it's applied.`}>
            <button type="button" className="btn btn-small btn-primary" disabled={!!why || !target} onClick={() => addIntents([bindFor(engine, target!, "ingress")])}>
              Bind{ingress.length > 1 ? "" : ` to ${target?.id ?? "a gateway"}`}
            </button>
          </Tip>
        </>
      )}
    </li>
  );
}

/** The cart items behind a pending line or node, with Remove from cart / Edit in builder / Review. */
function StagedList({ ids }: { ids: string[] }) {
  const { cart, removeIntent, openBuilder, openReview } = useStudio();
  const items = cart.filter((i) => ids.includes(i.id));
  if (!items.length) return null;
  return (
    <ul className="pmap-staged-list">
      {items.map((i) => (
        <li key={i.id}>
          <span className="badge badge-amber">{KIND_LABEL[i.kind]}</span> <span className="small">{intentEnglish(i)}</span>
          <span className="pmap-staged-actions">
            <Tip tip="Take this item out of the cart. Nothing in Google Cloud changes.">
              <button type="button" className="btn btn-small btn-text" onClick={() => removeIntent(i.id)}>
                <TrashIcon size={13} /> Remove from cart
              </button>
            </Tip>
            {(i.kind === "grant" || i.kind === "revoke") && (
              <Tip tip="Open this item in the builder to change it. Saving replaces it in the cart.">
                <button type="button" className="btn btn-small btn-text" onClick={() => openBuilder(i, { editId: i.id, mode: i.kind === "revoke" ? "revoke" : "grant" })}>
                  <PencilIcon size={13} /> Edit in builder
                </button>
              </Tip>
            )}
            <Tip tip="Open this item in Review & output: its commands, and the diff against the project (the authority on what changes).">
              <button type="button" className="btn btn-small btn-text" onClick={() => openReview(i.id)}>
                Review <ArrowIcon size={13} />
              </button>
            </Tip>
          </span>
        </li>
      ))}
    </ul>
  );
}

const VIA_TEXT: Record<Reason["via"], string> = { member: "a grant to this principal", project_agents: "all agents in this project", public: "public (anyone)", registry_wide: "registry-wide (every entry)", other: "a group or other principal" };
const TOOL_MARK = { allowed: "✓", denied: "✕", unknown: "?" } as const;

/** One binding behind a line: the sentence, the binding, the condition, and the actions on it. */
function ReasonCard({ r, part, multi, inv, label }: { r: Reason; part: PEdge; multi: boolean; inv: Inventory; label: (id: string) => string }) {
  const { cart, addIntents, openBuilder } = useStudio();
  const { engineByPrincipal } = useLookup();
  const [open, setOpen] = useState<"change" | null>(null);
  const g = reasonGrant(r);
  const cond = r.binding.condition;
  const engine = part.caller ? inv.engines.find((e) => e.name === part.caller) : undefined;
  const group = isGroupGrant(r, engine) || part.caller?.startsWith("pseudo:");
  const reached = group ? reachedBy(r.binding.member, inv.engines) : [];
  const mcp = r.resourceKind === "mcp_server" ? inv.mcp_servers.find((m) => m.name === r.resource) : undefined;
  const tools = mcp ? evaluateTools(cond, Object.fromEntries(mcp.tools.map((t) => [t.name, t.read_only]))) : null;
  const revokeStaged = cart.some((i) => revokesGrant(i, g));
  const norm = (e: string | undefined) => (e ?? "").replace(/\s+/g, " ").trim();
  const modifyStaged = cart.some((i) => i.kind === "modify" && i.source?.principal === g.member && i.destination?.name === g.resource && norm(i.access_from?.expression) === norm(cond?.expression));
  const access = accessFromCondition(cond?.expression);
  return (
    <section className="pmap-reason" aria-label={`Grant: ${r.binding.english || r.binding.member_label}`}>
      {multi && <div className="small muted">{label(part.caller ?? part.source)}</div>}
      <p className="pmap-sentence">{r.binding.english || `${r.binding.member_label || r.binding.member} holds ${r.binding.role} on ${r.resourceLabel}.`}</p>
      <dl className="pmap-dl">
        <dt>Role</dt>
        <dd className="mono small">{ROLE}</dd>
        <dt>Member</dt>
        <dd>
          {r.binding.member_label || r.binding.member}
          <div className="pmap-member">
            <span className="mono tiny">{r.binding.member}</span>
            <CopyButton compact className="mini-btn" ariaLabel="Copy the member" getText={() => r.binding.member} />
          </div>
        </dd>
        <dt>Resource</dt>
        <dd>
          <span className="inline-icon">
            <KindIcon kind={r.resourceKind} size={14} /> {r.resourceKind === "registry" ? "Registry-wide: every entry" : r.resourceLabel}
          </span>
          <div className="mono tiny muted pmap-wrap">{r.resource}</div>
        </dd>
        <dt>Via</dt>
        <dd>{VIA_TEXT[r.via] ?? VIA_LABEL[r.via] ?? r.via}</dd>
        <dt>Condition</dt>
        <dd>
          {cond ? (
            <>
              <b>{cond.title || "Custom condition"}</b>: {accessWords(access)}
            </>
          ) : (
            "None: full access"
          )}
        </dd>
      </dl>
      {cond?.expression && (
        <Disclosure summary="The condition (CEL)">
          <CodeView code={cond.expression} lang="python" label="condition.cel" />
        </Disclosure>
      )}
      {mcp && tools && (
        <table className="pmap-tools" aria-label={`Tools of ${mcp.display_name} under this grant`}>
          <tbody>
            {mcp.tools.map((t) => {
              const st = tools.allowed.includes(t.name) ? "allowed" : tools.denied.includes(t.name) ? "denied" : "unknown";
              return (
                <tr key={t.name} className={`st-${st}`}>
                  <td className="pmap-tool-mark" aria-label={st === "allowed" ? "allowed" : st === "denied" ? "denied" : "can't be told here"}>
                    {TOOL_MARK[st]}
                  </td>
                  <td className="mono small">{t.name}</td>
                  <td>{t.read_only ? <Badge tone="green"><BookIcon size={11} /> read-only</Badge> : t.destructive ? <Badge tone="red">destructive</Badge> : <Badge tone="amber">write</Badge>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {group && (
        <Callout tone="warn" title="A group grant">
          It's on {r.binding.member_label || r.binding.member}, not on one agent: revoking or changing it affects{" "}
          {r.via === "public" ? "everyone" : reached.length ? `every agent in the group (${plural(reached.length, "agent")} in this project today${r.via === "project_agents" ? ", and agents created later" : ""})` : "every member of the group"}.
        </Callout>
      )}

      <div className="pmap-actions">
        {revokeStaged ? (
          <Badge tone="red">
            <ClockIcon size={11} /> Revoke staged
          </Badge>
        ) : (
          <Tip tip="Stage removing exactly this binding (its condition included). Nothing changes until you Review and Apply.">
            <button type="button" className="btn btn-small btn-danger" onClick={() => addIntents([revokeFor(r, engineByPrincipal)])}>
              <TrashIcon size={13} /> Revoke
            </button>
          </Tip>
        )}
        {modifyStaged ? (
          <Badge tone="amber">
            <ClockIcon size={11} /> Change staged
          </Badge>
        ) : (
          <button type="button" className={`btn btn-small ${open === "change" ? "btn-primary" : "btn-tonal"}`} aria-expanded={open === "change"} onClick={() => setOpen(open === "change" ? null : "change")}>
            <PencilIcon size={13} /> Change access
          </button>
        )}
        <Tip tip="Open this grant in the builder, to change the caller or the destination. Nothing is staged yet.">
          <button type="button" className="btn btn-small btn-text" onClick={() => openBuilder(grantToIntent(g, engineByPrincipal, "grant"), { mode: "grant" })}>
            Open in builder
          </button>
        </Tip>
        {group && engine && (
          <Tip tip={`Stage two changes: the same access granted to ${engine.display_name} alone, and the revoke of the group grant. Other agents in the group lose this access.`}>
            <button type="button" className="btn btn-small btn-outline" onClick={() => addIntents(limitToAgent(r, engine, engineByPrincipal))}>
              Limit to this agent instead
            </button>
          </Tip>
        )}
      </div>
      {open === "change" && <ChangeAccess r={r} kind={r.resourceKind} inv={inv} onDone={() => setOpen(null)} />}
    </section>
  );
}

/** Change access: the AccessChooser, staging one modify (enabled only when the access differs). */
function ChangeAccess({ r, kind, inv, onDone }: { r: Reason; kind: string; inv: Inventory; onDone: () => void }) {
  const { addIntents } = useStudio();
  const { engineByPrincipal } = useLookup();
  const [draft, setDraft] = useState<AccessDraft>(() => draftOf(r.access, kind));
  const mcp = inv.mcp_servers.find((m) => m.name === r.resource);
  const access = accessOf(draft, kind);
  const lint = draftLint(draft, kind);
  const same = !!access && sameAccess(r, access);
  const intent = useMemo(() => (access && !same ? modifyFor(r, engineByPrincipal, access) : null), [r, engineByPrincipal, access, same]);
  const sentence = useRendered(intent);
  const checks = useChecksFor(intent ? { ...intent, kind: "grant" } : null).filter((c) => c.id === "destructive" || c.id === "broader");
  const why = !access ? "Pick at least one tool, or write a condition." : same ? "That's the access it has today." : blocking(lint) ? "Fix the condition expression first." : null;
  return (
    <div className="pmap-chooser">
      <AccessChooser name={`change-${r.resource}-${r.binding.member}`} dest={{ kind, label: r.resourceLabel }} mcp={mcp} value={draft} onChange={setDraft} compact />
      {sentence && <p className="small pmap-preview">{sentence}</p>}
      <Checks checks={checks} />
      <div className="pmap-actions">
        <Tip tip={why ?? "Stage one change that replaces this binding's condition in a single IAM update. Nothing changes until you Review and Apply."}>
          <button
            type="button"
            className="btn btn-small btn-primary"
            disabled={!!why}
            onClick={() => {
              addIntents([intent!]);
              onDone();
            }}
          >
            Stage change
          </button>
        </Tip>
        <button type="button" className="btn btn-small btn-text" onClick={onDone}>
          Cancel
        </button>
      </div>
    </div>
  );
}

/** checksFor with the studio's lookups (the builder's warnings). */
function useChecksFor(intent: Intent | null): Check[] {
  const { inventory, cart } = useStudio();
  const { engineByName, engineByPrincipal, egress } = useLookup();
  return useMemo(() => checksFor(intent, { inv: inventory.data, cart, engineByName, engineByPrincipal, egress }), [intent, inventory.data, cart, engineByName, engineByPrincipal, egress]);
}

function Checks({ checks, fixes, onFix }: { checks: Check[]; fixes?: Intent[]; onFix?: (i: Intent) => void }) {
  if (!checks.length) return null;
  return (
    <div className="checks">
      {checks.map((c) => (
        <div key={c.id} className={`check-chip chip-${c.tone}`}>
          <WarnIcon size={14} />
          <span className="grow">{c.text}</span>
          {c.fix && onFix && (fixes?.some((f) => f.kind === c.fix!.kind && f.engine === c.fix!.engine) ? <Badge tone="green">fix will be staged</Badge> : (
            <button type="button" className="btn btn-small btn-outline" onClick={() => onFix(c.fix!)}>
              {c.fixLabel ?? "Also stage fix"}
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}

/** Allow… on a default-deny line: the AccessChooser (read-only by hint for MCP, full access otherwise), staging a
 *  grant; or the builder with the caller and destination filled in. */
function AllowBox({ engine, dest, inv }: { engine: Engine; dest: PNode; inv: Inventory }) {
  const { addIntents, openBuilder, cart } = useStudio();
  const [open, setOpen] = useState(false);
  const kind = dest.destKind ?? "endpoint";
  const [draft, setDraft] = useState<AccessDraft>(() => draftOf(undefined, kind));
  const [fixes, setFixes] = useState<Intent[]>([]);
  const mcp = inv.mcp_servers.find((m) => m.name === dest.id);
  const access = accessOf(draft, kind);
  const lint = draftLint(draft, kind);
  const intent = useMemo(() => (access ? allowFor(engine, dest, access) : null), [engine, dest, access]);
  const sentence = useRendered(open ? intent : null);
  const checks = useChecksFor(open ? intent : null).filter((c) => c.id !== "replace");
  const staged = cart.some((i) => i.kind === "grant" && i.source?.principal === engine.principal && i.destination?.name === dest.id);
  const why = !access ? "Pick at least one tool, or write a condition." : blocking(lint) ? "Fix the condition expression first." : null;
  const builderIntent: Partial<Intent> = { kind: "grant", source: intent?.source ?? { type: "engine", principal: engine.principal, label: engine.display_name, engine: engine.name }, destination: allowFor(engine, dest, { mode: "all" }).destination };
  return (
    <div className="pmap-allow">
      <div className="pmap-actions">
        {staged ? (
          <Badge tone="green">
            <ClockIcon size={11} /> Grant staged
          </Badge>
        ) : (
          <button type="button" className={`btn btn-small ${open ? "btn-primary" : "btn-tonal"}`} aria-expanded={open} onClick={() => setOpen(!open)}>
            <CheckIcon size={13} /> Allow…
          </button>
        )}
        <Tip tip="Open the builder with this agent and destination filled in. Nothing is staged yet.">
          <button type="button" className="btn btn-small btn-text" onClick={() => openBuilder(builderIntent, { mode: "grant" })}>
            Open in builder
          </button>
        </Tip>
      </div>
      {open && !staged && (
        <div className="pmap-chooser">
          <AccessChooser name={`allow-${dest.id}`} dest={{ kind, label: dest.label }} mcp={mcp} value={draft} onChange={setDraft} compact />
          {sentence && <p className="small pmap-preview">{sentence}</p>}
          <Checks checks={checks} fixes={fixes} onFix={(f) => setFixes([...fixes, f])} />
          <div className="pmap-actions">
            <Tip tip={why ?? `Stage this grant${fixes.length ? ` plus ${plural(fixes.length, "fix", "fixes")}` : ""}. Nothing changes until you Review and Apply.`}>
              <button
                type="button"
                className="btn btn-small btn-primary"
                disabled={!!why}
                onClick={() => {
                  addIntents([...fixes, intent!]);
                  setOpen(false);
                }}
              >
                Stage grant{fixes.length ? ` (+${fixes.length} fix)` : ""}
              </button>
            </Tip>
            <button type="button" className="btn btn-small btn-text" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/** Bind to <egress>: disabled (with the redeploy help) when the agent can't be bound. */
function BindBox({ engine, gateways }: { engine: Engine; gateways: Gateway[] }) {
  const { addIntents, cart } = useStudio();
  const egress = gateways.filter((g) => g.type === "egress");
  const [gw, setGw] = useState(egress[0]?.name ?? "");
  const target = egress.find((g) => g.name === gw);
  const staged = cart.some((i) => i.kind === "bind_gateway" && i.engine === engine.name && i.gateway?.direction === "egress");
  const why = !engine.bindable ? (engine.bindable_reason ?? "This agent can't be bound to Agent Gateway.") : !target ? "No egress gateway in this region." : null;
  return (
    <div className="pmap-bind">
      <p className="small">
        <b>{engine.display_name}</b> has no egress gateway: its calls go straight out and no grant is checked.
      </p>
      <div className="pmap-actions">
        {staged ? (
          <Badge tone="blue">
            <ClockIcon size={11} /> Binding staged
          </Badge>
        ) : (
          <>
            {egress.length > 1 && (
              <select className="pmap-select" value={gw} onChange={(e) => setGw(e.target.value)} aria-label="Egress gateway" disabled={!engine.bindable}>
                {egress.map((g) => (
                  <option key={g.name} value={g.name}>
                    {g.id}
                  </option>
                ))}
              </select>
            )}
            <Tip tip={why ?? `Stage binding ${engine.display_name} to ${target!.id}. The agent redeploys when it's applied.`}>
              <button type="button" className="btn btn-small btn-primary" disabled={!!why} onClick={() => addIntents([bindFor(engine, target!)])}>
                Bind to {target?.id ?? "an egress gateway"}
              </button>
            </Tip>
          </>
        )}
      </div>
      {!engine.bindable && (
        <>
          <p className="small warn-text">
            <WarnIcon size={12} /> {why}
          </p>
          <RedeployHelp />
        </>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ a node
function NodeDetails({ node, inv, gateways, label }: { node: PNode; inv: Inventory; gateways: Gateway[]; label: (id: string) => string }) {
  const { openBuilder } = useStudio();
  const openGateway = useOpenGateway();
  const engine = node.kind === "engine" ? inv.engines.find((e) => e.name === node.id) : undefined;
  const destKind = node.destKind && node.destKind !== "registry" ? node.destKind : null;
  let body: ReactNode = null;
  if (engine) {
    const egressView = node.column === "callers";
    body = (
      <>
        <dl className="pmap-dl">
          <dt>Identity</dt>
          <dd>{engine.identity_type === "AGENT_IDENTITY" ? "Agent Identity" : "Service account"}</dd>
          <dt>Gateways</dt>
          <dd>
            Egress: {engine.gateways.egress ? label(engine.gateways.egress) : "none"} · Ingress: {engine.gateways.ingress ? label(engine.gateways.ingress) : "none"}
          </dd>
          <dt>Principal</dt>
          <dd>
            <div className="pmap-member">
              <span className="mono tiny">{engine.principal}</span>
              <CopyButton compact className="mini-btn" ariaLabel={`Copy ${engine.display_name}'s principal`} getText={() => engine.principal} />
            </div>
          </dd>
        </dl>
        {egressView && !engine.gateways.egress && <BindBox engine={engine} gateways={gateways} />}
        <div className="pmap-actions">
          <Tip tip={`Open the builder with ${engine.display_name} filled in as the caller. Nothing is staged yet.`}>
            <button type="button" className="btn btn-small btn-tonal" onClick={() => openBuilder({ kind: "grant", source: { type: "engine", principal: engine.principal, label: engine.display_name, engine: engine.name } })}>
              Build a policy for this agent <ArrowIcon size={13} />
            </button>
          </Tip>
        </div>
      </>
    );
  } else if (node.kind === "gateway") {
    body = (
      <>
        <dl className="pmap-dl">
          {node.gwType === "ingress" ? (
            <>
              <dt>Caller identity</dt>
              <dd>Not checked: a Client-to-Agent gateway screens content{node.mode ? `. Its IAP policy (${node.mode === "DRY_RUN" ? "dry run" : "enforce"}) is configured, not an identity check here` : ""}</dd>
            </>
          ) : (
            <>
              <dt>Enforcement</dt>
              <dd>{node.mode === "ENFORCE" ? "Enforcing: default deny" : node.mode === "DRY_RUN" ? "Dry run: nothing is blocked" : "No IAP policy"}</dd>
            </>
          )}
          <dt>Model Armor</dt>
          <dd>{node.modelArmor?.enabled ? `On${node.modelArmor.dryRun ? " (dry run)" : ""}${node.modelArmor.template ? `, template ${node.modelArmor.template}` : ""}` : "Off"}</dd>
        </dl>
        <div className="pmap-actions">
          <button type="button" className="btn btn-small btn-tonal" onClick={() => openGateway(node.id)}>
            {node.mode === "DRY_RUN" && node.gwType !== "ingress" ? "Enforce it on the gateway card" : "Open the gateway card"} <ArrowIcon size={13} />
          </button>
        </div>
      </>
    );
  } else if (destKind) {
    body = (
      <div className="pmap-actions">
        <Tip tip={`Open the builder with ${node.label} filled in as what may be called. Nothing is staged yet.`}>
          <button type="button" className="btn btn-small btn-tonal" onClick={() => openBuilder({ kind: "grant", destination: { kind: destKind, id: node.id.split("/").pop() ?? node.id, name: node.id, label: node.label } })}>
            Build a policy for this <ArrowIcon size={13} />
          </button>
        </Tip>
      </div>
    );
  }
  return (
    <div className="small">
      {node.sub && <p className="muted">{node.sub}</p>}
      {node.pending && (
        <div className="pmap-staged">
          <div>
            <ClockIcon size={13} /> <b>Staged:</b> {node.pending.text.join("; ")}
          </div>
          <StagedList ids={node.pending.intents} />
        </div>
      )}
      {node.unreadable && <p className="warn-text">IAP policy couldn't be read: {node.unreadable}</p>}
      {body}
      {node.members?.length ? (
        <ul className="plain-list">
          {node.members.map((m) => (
            <li key={m.member}>{m.label}</li>
          ))}
        </ul>
      ) : null}
      {node.chips.length > 0 && <p className="muted">{node.chips.map((c) => c.text).join(" · ")}</p>}
    </div>
  );
}
