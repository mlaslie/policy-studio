// Step 1: gateways in the region, their policies and bound agents; stage bind / unbind.
import { Tip } from "../components/Tooltip";
import { useState } from "react";
import { useLookup, useStudio } from "../store";
import type { Engine, Gateway, Intent } from "../api/types";
import { Badge, Callout, Disclosure, Load, StepHeader, Term } from "../components/ui";
import { CodeView } from "../components/CodeView";
import { GatewayIcon, LockIcon, PlusIcon, RobotIcon, ShieldIcon, SparkIcon, WarnIcon } from "../components/Icons";
import { newId, shortName } from "../lib/policy";
import { fmtDate } from "../lib/util";

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
            <option key={e.name} value={e.name} disabled={!e.bindable}>
              {e.display_name}
              {!e.bindable ? " (created before 2026-04-29, can't be bound)" : e.gateways[gw.type] ? ` (now on ${shortName(e.gateways[gw.type]!)})` : ""}
            </option>
          ))}
        </select>
        <Tip tip={chosen ? `Stage binding ${chosen.display_name} to ${gw.id} in the cart. Nothing changes in Google Cloud until you apply.` : "Choose an agent first."}>
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
      {other && <p className="small warn-text"><WarnIcon size={13} /> It is currently bound to {shortName(other)}; this moves it.</p>}
      {!choices.length && <p className="muted small">Every agent is already bound.</p>}
      <p className="muted small">The agent redeploys when this is applied; it takes a few minutes. Nothing changes until you run the generated command.</p>
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
    <article className="card gw-card">
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
          <p className="muted small">None. {gw.type === "ingress" ? "Prompts reach the agent unscreened. You can turn on Model Armor in step 2." : "Nothing is checked."}</p>
        )}
        {gw.type === "egress" && !hasIap && <Callout tone="warn" title="No IAP policy">Without an IAP REQUEST_AUTHZ policy, grants are not enforced on this gateway.</Callout>}
      </div>

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
                    <div>{b.display_name}</div>
                    <div className="mono tiny muted">{shortName(b.engine)}{e ? ` · created ${fmtDate(e.create_time)}` : ""}</div>
                  </div>
                  {staged(b.engine) ? (
                    <Badge tone="amber">Unbind staged</Badge>
                  ) : (
                    <Tip tip={`Stage detaching ${b.display_name} from ${gw.id} in the cart. Nothing changes in Google Cloud until you apply.`}>
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
          <Tip tip={`Pick an agent to send its ${gw.type} traffic through ${gw.id}. Binding is staged in the cart; nothing changes until you apply.`}>
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
                <span className="muted small">created {fmtDate(e.create_time)}, before 2026-04-29: can't be bound. Redeploy it to protect it.</span>
              ) : staged ? (
                <Badge tone="blue">Bind staged</Badge>
              ) : egress ? (
                <Tip tip={`Stage binding ${e.display_name} to ${egress.id} in the cart. Nothing changes in Google Cloud until you apply.`}>
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
