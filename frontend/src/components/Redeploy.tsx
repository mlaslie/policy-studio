// "How to redeploy with Agent Identity": shown wherever an Agent Runtime engine can't be bound to Agent Gateway
// (no Agent Identity, or created before 2026-04-29). Mirrors gcp/engines.py REDEPLOY_SNIPPET.
import { Disclosure } from "./ui";
import { CodeView } from "./CodeView";

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

export function RedeployHelp({ code }: { code?: string | null }) {
  return (
    <Disclosure summary="How to redeploy with Agent Identity">
      <CodeView code={code || REDEPLOY_SNIPPET} lang="python" label="redeploy.py" maxHeight={320} />
    </Disclosure>
  );
}
