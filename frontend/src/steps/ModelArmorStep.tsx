// Model Armor step: Model Armor per gateway, the template in plain English, stage on / off.
import { Tip } from "../components/Tooltip";
import { useState } from "react";
import { stepN, useStudio } from "../store";
import type { ModelArmorGateway, Template } from "../api/types";
import { Badge, Callout, Disclosure, Load, StepHeader, Term } from "../components/ui";
import { CodeView } from "../components/CodeView";
import { CheckIcon, CloseIcon, SparkIcon } from "../components/Icons";
import { newId, shortName } from "../lib/policy";
import { MaSetupCallout, ModelArmorSetup } from "./ModelArmorSetup";

const LEVEL: Record<string, string> = {
  LOW_AND_ABOVE: "≥ LOW (strictest: blocks even weak signals)",
  MEDIUM_AND_ABOVE: "≥ MEDIUM",
  HIGH: "HIGH only (most lenient)",
};
const levelText = (l?: string) => (l ? LEVEL[l] ?? l : "default level");
const RAI: Record<string, string> = {
  HATE_SPEECH: "Hate speech",
  HARASSMENT: "Harassment",
  DANGEROUS: "Dangerous content",
  SEXUALLY_EXPLICIT: "Sexually explicit",
};

function Row({ on, label, value, help }: { on: boolean; label: string; value: string; help: string }) {
  return (
    <li className={`ma-row ${on ? "on" : "off"}`}>
      <span className={`dot ${on ? "dot-green" : "dot-grey"}`}>{on ? <CheckIcon size={12} /> : <CloseIcon size={12} />}</span>
      <div className="grow">
        <div className="ma-label">{label}</div>
        <div className="muted small">{help}</div>
      </div>
      <span className={`ma-value ${on ? "" : "muted"}`}>{on ? value : "Off"}</span>
    </li>
  );
}

export function TemplateCard({ t }: { t: Template }) {
  const [raw, setRaw] = useState(false);
  const f = t.filters;
  return (
    <div className="template">
      <div className="template-head">
        <span>
          <Term k="model-armor-template">Template</Term> <b className="mono">{t.id}</b>
        </span>
        <button className="link-btn" onClick={() => setRaw(!raw)} aria-expanded={raw}>
          {raw ? "Hide raw JSON" : "Show raw JSON"}
        </button>
      </div>
      <ul className="ma-rows">
        <Row on={f.pi_jailbreak.enabled} label="Prompt injection & jailbreak" value={levelText(f.pi_jailbreak.level)} help="Blocks attempts to override the agent's instructions." />
        <Row on={f.sdp.enabled} label="Sensitive data" value={f.sdp.mode === "advanced" ? "Advanced (custom inspect template)" : "Basic (credit cards, SSNs, keys…)"} help="Finds secrets and personal data in messages." />
        <Row
          on={f.rai.length > 0}
          label="Responsible AI"
          value={f.rai.length ? `${f.rai.length} categor${f.rai.length > 1 ? "ies" : "y"}` : ""}
          help={f.rai.length ? f.rai.map((r) => `${RAI[r.category] ?? r.category}: ${levelText(r.level).split(" (")[0]}`).join(" · ") : "Harmful or abusive content."}
        />
        <Row on={f.malicious_uri.enabled} label="Malicious URLs" value="On" help="Blocks known phishing and malware links." />
      </ul>
      {t.block_message && (
        <div className="block-msg">
          <span className="muted small">Users see this when blocked:</span>
          <q>{t.block_message}</q>
        </div>
      )}
      {raw && <CodeView code={JSON.stringify(t.raw, null, 2)} lang="json" label={`${t.id}.json`} maxHeight={320} />}
    </div>
  );
}

function GatewayMA({ g, setupReady }: { g: ModelArmorGateway; setupReady: boolean }) {
  const { addIntents, cart } = useStudio();
  const staged = cart.find((i) => (i.kind === "model_armor_on" || i.kind === "model_armor_off") && i.gateway?.name === g.gateway);
  const stage = (on: boolean) => addIntents([{ id: newId(), kind: on ? "model_armor_on" : "model_armor_off", gateway: { name: g.gateway, direction: g.type } }]);
  return (
    <article className="card ma-card">
      <header className="gw-head">
        <span className={`gw-icon ${g.enabled ? "ma-on" : "ma-off"}`}>
          <SparkIcon size={20} />
        </span>
        <div className="gw-titles">
          <h3>{shortName(g.gateway)}</h3>
          <div className="small">
            <Badge tone={g.type === "egress" ? "blue" : "purple"}>{g.type === "egress" ? "Egress" : "Ingress"}</Badge>{" "}
            {g.enabled ? <Badge tone="green">Model Armor on</Badge> : <Badge tone="amber">Model Armor off</Badge>}
          </div>
        </div>
        <div className="gw-actions">
          {staged ? (
            <Badge tone="blue">{staged.kind === "model_armor_on" ? "Turn on staged" : "Turn off staged"}</Badge>
          ) : g.enabled ? (
            <Tip tip={`Stage turning off Model Armor on ${shortName(g.gateway)} (removes its content-screening policy). Nothing changes in Google Cloud until you apply.`}>
              <button className="btn btn-outline" onClick={() => stage(false)}>
                Turn off…
              </button>
            </Tip>
          ) : (
            <Tip tip={`Stage turning on Model Armor for ${shortName(g.gateway)} (attaches a content-screening policy). Nothing changes in Google Cloud until you apply.`}>
              <button className="btn btn-primary" onClick={() => stage(true)}>
                Turn on
              </button>
            </Tip>
          )}
        </div>
      </header>
      {g.error && <Callout tone="danger" title="Partly unreadable">{g.error}</Callout>}
      <p className="gw-explain">
        {g.type === "egress"
          ? "Screens what bound agents send to MCP servers and the replies they get back. A2A calls are not screened."
          : "Screens prompts on their way into bound agents (for example from Gemini Enterprise) and the agents' answers."}
      </p>
      {g.enabled ? (
        <>
          <div className="kv-inline">
            <span>
              <Term k="content-authz">Policy</Term>: <span className="mono tiny">{g.policy ? shortName(g.policy) : "?"}</span>
            </span>
            <span>
              Extension: <span className="mono tiny">{g.extension ? shortName(g.extension) : "?"}</span>
            </span>
          </div>
          {g.template ? <TemplateCard t={g.template} /> : <Callout tone="warn" title="Template not readable">The policy is attached but its template couldn't be read.</Callout>}
        </>
      ) : setupReady ? (
        <p className="muted">Nothing is screened on this gateway. “Turn on” stages a CONTENT_AUTHZ policy that uses the Model Armor extension; you'll get the commands in Review.</p>
      ) : (
        <MaSetupCallout text="Nothing is screened on this gateway, and the region doesn't have everything Model Armor needs yet (a template, an extension and permissions for the gateway's service agent). The guided setup stages all of it, including turning it on here." />
      )}
    </article>
  );
}

export function ModelArmorStep() {
  const { modelArmor, maSetupOpen, openMaSetup } = useStudio();
  return (
    <>
      <StepHeader
        title="Model Armor"
        lead={
          <>
            Model Armor reads message <b>content</b> and blocks risky prompts and replies. It's attached to a gateway as a <Term k="content-authz">CONTENT_AUTHZ</Term> policy that uses a{" "}
            <Term k="model-armor-template">template</Term> of filters.
          </>
        }
      />
      <Callout tone="info" title="Egress screening covers MCP, not A2A">
        On an egress gateway, Model Armor screens MCP tool calls and their results. Calls to A2A agents still go through the IAP check, but their content isn't screened.
      </Callout>
      <Load l={modelArmor} what="Model Armor">
        {(d) => (
          <>
            {d.gateways.length === 0 && <p className="muted">No gateways in this region. Create one first (step {stepN("gateways")}).</p>}
            {d.gateways.length > 0 && <ModelArmorSetup data={d} />}
            {d.setup?.ready && !maSetupOpen && d.gateways.length > 0 && (
              <p className="small muted">
                Model Armor is set up in this region (template, extension and service agent roles).{" "}
                <Tip tip="Open the guided setup to stage another template or extension, or turn Model Armor on for more gateways.">
                  <button className="link-btn" onClick={openMaSetup}>
                    Open the setup steps
                  </button>
                </Tip>
              </p>
            )}
            <div className="ma-grid">
              {d.gateways.map((g) => (
                <GatewayMA key={g.gateway} g={g} setupReady={d.setup?.ready ?? true} />
              ))}
            </div>
            {d.templates.length > 0 && (
              <Disclosure summary={`All templates in this region (${d.templates.length})`}>
                <div className="tmpl-list">
                  {d.templates.map((t) => (
                    <div key={t.name} className="card">
                      <TemplateCard t={t} />
                      <p className="muted small">
                        Used by: {d.gateways.filter((g) => g.template?.name === t.name).map((g) => shortName(g.gateway)).join(", ") || "no gateway"}
                      </p>
                    </div>
                  ))}
                </div>
              </Disclosure>
            )}
          </>
        )}
      </Load>
    </>
  );
}
