// "How to redeploy with Agent Identity": shown wherever an Agent Runtime engine can't be bound to Agent Gateway
// (no Agent Identity, or created before 2026-04-29). Mirrors gcp/engines.py REDEPLOY_SNIPPET.
import { Disclosure } from "./ui";
import { CodeView } from "./CodeView";
import { PSC_BIND_REASON, REDEPLOY_NO_PSC } from "../lib/networking";

export const NO_IDENTITY_REASON =
  "Created without Agent Identity: Agent Gateway needs identity_type=AGENT_IDENTITY, which can't be changed. Redeploy the agent with Agent Identity.";

export const REDEPLOY_SNIPPET = `import vertexai
from vertexai import types

client = vertexai.Client(project="PROJECT_ID", location="REGION")
remote = client.agent_engines.create(
    agent=app,                     # your ADK app / agent object
    config={
        "identity_type": types.IdentityType.AGENT_IDENTITY,   # required for Agent Gateway; can't be changed later
        "display_name": "my-agent",
        "requirements": ["google-cloud-aiplatform[agent_engines,adk]"],
        # ... the rest of your existing deployment config
    },
)
# Then bind the new engine to the gateway (Policy Studio, Gateways step) and move grants to its new identity.`;

/** `reason`: why the agent can't be bound; a PSC interface gets the "redeploy without the PSC interface" variant. */
export function RedeployHelp({ code, summary, reason }: { code?: string | null; summary?: string; reason?: string | null }) {
  const psc = !!reason && reason.includes(PSC_BIND_REASON);
  return (
    <Disclosure summary={summary ?? (psc ? "How to redeploy without the PSC interface" : "How to redeploy with Agent Identity")}>
      <CodeView code={code || (psc ? REDEPLOY_NO_PSC : REDEPLOY_SNIPPET)} lang="python" label="redeploy.py" maxHeight={320} />
    </Disclosure>
  );
}

/** Guidance Policy Studio doesn't apply (audit N3: move a gateway from inline networkConfig to a template). */
export function GuidanceHelp({ code, summary }: { code: string; summary: string }) {
  return (
    <Disclosure summary={summary}>
      <CodeView code={code} lang="shell" label="guidance.sh" maxHeight={320} />
    </Disclosure>
  );
}
