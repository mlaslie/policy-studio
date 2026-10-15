// Private networking, detection only (docs/PRIVATE_NETWORKING_PLAN.md): labels for the Gateways step, the map and
// Inventory, and a port of the audit rules N1–N5 (backend gcp/networking.py) for the mock. Both sides read
// backend/tests/fixtures/networking_cases.json, so a wording change on one side fails the other side's test.
import type { Engine, Finding, Gateway, PrivateEgress, PscInterface } from "../api/types";

const short = (name: string) => (name || "").replace(/\/+$/, "").split("/").pop() ?? "";

export const PSC_BIND_REASON =
  "This agent has its own private networking (PSC interface). Google rejects or breaks agents with both; redeploy it without the PSC interface.";
export const TEMPLATE_PERMISSION = "networkservices.agentConnectivityTemplates.get";

export const EGRESS_MODE: Record<string, string> = {
  PRIVATE_RANGES_ONLY: "Private ranges only",
  ALL_TRAFFIC: "All traffic",
};

/** "corp-vpc", or "a VPC" when the attachment couldn't be read. */
export const vpcName = (p: { vpc?: string | null } | null | undefined) => p?.vpc || "a VPC";

/** Gateway node chip: "Private egress · corp-vpc" (null for public egress only). */
export function privateEgressChip(pe: PrivateEgress | null | undefined): string | null {
  if (!pe) return null;
  return pe.vpc ? `Private egress · ${pe.vpc}` : "Private egress";
}

/** Tooltip / one-line summary of a gateway's private egress. */
export function privateEgressSummary(pe: PrivateEgress | null | undefined): string {
  if (!pe) return "Public egress only: this gateway has no connectivity template or inline networkConfig.";
  if (pe.error) return `Private egress through the connectivity template ${short(pe.template ?? "")}, but Policy Studio ${pe.error}.`;
  const how = pe.source === "template" ? `connectivity template ${short(pe.template ?? "")}` : "inline networkConfig (older form)";
  const doms = pe.dns_domains.length ? `Private domains: ${pe.dns_domains.join(", ")}.` : "No private domains.";
  const mode = pe.vpc_egress ? ` Egress mode: ${EGRESS_MODE[pe.vpc_egress] ?? pe.vpc_egress}.` : "";
  return `Reaches ${pe.vpc ? `the VPC ${pe.vpc}` : "a VPC"} through its ${how}. ${doms}${mode}`;
}

/** Agent node chips: red "Own VPC access (bypasses gateway)" for a PSC interface, plus "Broken: PSC interface +
 *  gateway" when it is also bound to an egress gateway. */
export function pscChips(e: Pick<Engine, "psc_interface" | "gateways">): { text: string; tip: string }[] {
  const p = e.psc_interface;
  if (!p) return [];
  const out = [{ text: "Own VPC access (bypasses gateway)", tip: pscSummary(p) }];
  if (e.gateways.egress)
    out.push({ text: "Broken: PSC interface + gateway", tip: "Google rejects an agent with both a PSC interface and a gateway binding; set by a later update, it can't reach Google APIs at all. Redeploy it without the PSC interface." });
  return out;
}

export function pscSummary(p: PscInterface): string {
  return `Its own PSC interface into ${p.vpc ? `the VPC ${p.vpc}` : "a VPC"} (attachment ${short(p.network_attachment)}${p.dns_domains.length ? `; DNS ${p.dns_domains.join(", ")}` : ""}). Calls into that VPC skip the gateway: no registry, no IAP grant, no gateway logs.`;
}

// ------------------------------------------------------------------ audit rules N1–N5 (port of networking.py)
export const REDEPLOY_NO_PSC = `import vertexai
from vertexai import types

client = vertexai.Client(project="PROJECT_ID", location="REGION")
remote = client.agent_engines.create(
    agent=app,                     # your ADK app / agent object
    config={
        "identity_type": types.IdentityType.AGENT_IDENTITY,   # required for Agent Gateway; can't be changed later
        "display_name": "my-agent",
        # No "psc_interface_config": its VPC calls would skip the gateway. Reach the VPC through the egress
        # gateway's private egress (a connectivity template) instead.
        "agent_gateway_config": {"agent_to_anywhere_config": {
            "agent_gateway": "projects/PROJECT_ID/locations/REGION/agentGateways/GATEWAY_ID"}},
        "env_vars": {"GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES": "false"},  # needed behind a gateway
        "requirements": ["google-cloud-aiplatform[agent_engines,adk]"],
        # ... the rest of your existing deployment config
    },
)
# Then grant the new identity roles/iap.egressor on the destinations it needs (Builder), and delete the old agent.`;

export const TEMPLATE_STEPS = `# Two steps (a direct PATCH from no networking to a template fails today; from inline it works).
# 1. A connectivity template with the same attachment and DNS. The template takes project IDs.
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\
  "https://networkservices.googleapis.com/v1/projects/PROJECT_ID/locations/REGION/agentConnectivityTemplates?agentConnectivityTemplateId=TEMPLATE_ID" \\
  -d '{"accessPath": "AGENT_TO_ANYWHERE", "deploymentModel": "CENTRALIZED",
       "egressNetworkConfig": {
         "networkAttachment": "ATTACHMENT",
         "dnsPeeringConfig": {"domains": [DOMAINS], "targetNetwork": "projects/PROJECT_ID/global/networks/VPC"},
         "vpcEgress": "PRIVATE_RANGES_ONLY"}}'
# 2. Point the gateway at it and clear networkConfig (the mask needs both). The gateway takes the project NUMBER.
curl -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\
  "https://networkservices.googleapis.com/v1/GATEWAY?updateMask=agentConnectivityTemplate,networkConfig,labels" \\
  -d '{"agentConnectivityTemplate": "projects/PROJECT_NUMBER/locations/REGION/agentConnectivityTemplates/TEMPLATE_ID",
       "labels": {}}'   # send the gateway's current labels: a PATCH can drop them
# About 3 minutes. Policy Studio doesn't apply this; check it on a gateway without bound agents first.`;

const vpcPhrase = (p: { vpc?: string | null }) => (p.vpc ? `the VPC ${p.vpc}` : "a VPC");

type EngineLike = Pick<Engine, "name" | "display_name" | "gateways" | "psc_interface">;
type GatewayLike = Pick<Gateway, "name" | "id" | "private_egress">;

/** N1 (PSC interface, no egress gateway) and N2 (PSC interface and an egress gateway binding). */
export function rulePscEngines(engines: EngineLike[]): Finding[] {
  const out: Finding[] = [];
  for (const e of engines) {
    const psc = e.psc_interface;
    if (!psc) continue;
    const label = e.display_name || short(e.name);
    const egress = e.gateways?.egress;
    if (!egress)
      out.push({
        rule: "N1",
        severity: "high",
        resource: e.name,
        redeploy: REDEPLOY_NO_PSC,
        title: `Own VPC access, bypasses the gateway: ${label}`,
        detail: `${label} has its own private networking (a PSC interface into ${vpcPhrase(psc)}) and no egress gateway. Its calls into the VPC skip every check: no Agent Registry, no roles/iap.egressor grant and no gateway logs apply, so its grants in Policy Studio mean nothing for that traffic. Redeploy it without the PSC interface, with Agent Identity, bound to the egress gateway.`,
      });
    else
      out.push({
        rule: "N2",
        severity: "high",
        resource: e.name,
        redeploy: REDEPLOY_NO_PSC,
        title: `Broken: PSC interface and gateway binding on ${label}`,
        detail: `${label} has a PSC interface and is bound to the egress gateway ${short(egress)}. Google rejects that combination when an agent is created; it is only reachable by a later update, and an agent in this state can't reach Google APIs at all (sessions and model calls time out). Redeploy it without the PSC interface.`,
      });
  }
  return out;
}

/** N3 (inline networkConfig), N4 (template unreadable), N5 (vpcEgress ALL_TRAFFIC). */
export function ruleGateways(gateways: GatewayLike[]): Finding[] {
  const out: Finding[] = [];
  for (const g of gateways) {
    const pe = g.private_egress;
    if (!pe) continue;
    const gid = g.id || short(g.name);
    if (pe.source === "inline")
      out.push({
        rule: "N3",
        severity: "info",
        resource: g.name,
        guidance: TEMPLATE_STEPS,
        title: `Inline private egress on ${gid}`,
        detail: `Gateway ${gid} reaches ${vpcPhrase(pe)} through an inline networkConfig, the older form. VPC Service Controls and custom trust (your own CA) need a connectivity template. Moving takes two updates and keeps the gateway and its bound agents.`,
      });
    if (pe.error)
      out.push({
        rule: "N4",
        severity: "medium",
        resource: g.name,
        title: `Can't read the connectivity template of ${gid}`,
        detail: `Gateway ${gid} uses the connectivity template ${short(pe.template ?? "")}, but Policy Studio can't read it, so its VPC, private domains and egress mode are unknown. Ask for ${TEMPLATE_PERMISSION} (in roles/networkservices.viewer) on the gateway's project.`,
      });
    if (pe.vpc_egress === "ALL_TRAFFIC")
      out.push({
        rule: "N5",
        severity: "info",
        resource: g.name,
        title: `All of ${gid}'s traffic goes into the VPC`,
        detail: `The connectivity template of ${gid} uses egress mode ALL_TRAFFIC: every call through the gateway, public destinations included, leaves through ${vpcPhrase(pe)}, which then needs Cloud NAT to reach the internet. This is the mode used with VPC Service Controls.`,
      });
  }
  return out;
}

export const auditRules = (engines: EngineLike[], gateways: GatewayLike[]): Finding[] => [...rulePscEngines(engines), ...ruleGateways(gateways)];
