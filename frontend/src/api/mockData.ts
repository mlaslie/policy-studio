// Realistic mock state for `npm run dev:mock` (VITE_MOCK=1). Built from the context so project and
// region edits show up everywhere. Defaults: my-demo-project / us-east4.
// Region us-central1 has no Model Armor set up (no template, no extension, service agents without the roles), to
// exercise the "Set up Model Armor in this region" wizard.
// Enforcement: in us-east4 corp-egress and corp-ingress share one IAP authz extension in DRY_RUN (shared case + dry
// run with "would have been denied" log entries); in us-central1 corp-egress enforces on its own extension and
// corp-ingress has no IAP policy (switch disabled).
// Policy map cases (docs/VISUALIZATION_PLAN.md §11): a registry-wide grant (a service account on the whole Agent
// Registry), a custom-CEL grant, a group grant, an endpoint whose IAP policy can't be read, and two agents bound for
// ingress. A platform allowlist of Google APIs (PLATFORM_HOSTS: each API registered as host, host.mtls and host:443,
// named "acme-prod <host>", all granted to every agent in the project) shows the map's "Google APIs" group, next to
// two endpoints that aren't Google APIs.
// Private networking (detection only): corp-egress reaches corp-vpc through a connectivity template (us-central1:
// the older inline networkConfig, N3; europe-west1: a template Policy Studio can't read, N4; us-west1: west-egress
// sends ALL_TRAFFIC into the VPC, N5); simple-agent-with-psc has its own PSC interface and no gateway (N1); Ops
// Copilot has a PSC interface and an egress binding (N2, broken). Seen in traffic (mockPaths.ts): Tickets MCP
// private through corp-egress's template, HR Directory MCP public, Knowledge Base Agent mixed. Region us-west1 is the scale scenario (mockScale.ts): about 50 agents and 500 grants, two egress gateways
// (one in dry run), and corp-ingress with Model Armor on (screened Client-to-Agent lines).
import type { AuditResp, Binding, ContextInfo, Ctx, EnforcementMode, Finding, Gateway, Grant, Inventory, MaSetup, McpTool, ModelArmorResp, RegistryService, ServiceAgent, Template, TemplateFilters } from "./types";
import { READ_ONLY_EXPR, ROLE, toolsExpr } from "../lib/policy";
import { PSC_BIND_REASON, auditRules } from "../lib/networking";
import { SCALE_REGION, addScale, scaleFactor } from "./mockScale";

export const MOCK_NUMBER = "482915730164";
const ORG = "739104826351";

export type World = ReturnType<typeof buildWorld>;

export function principalOf(region: string, engineId: string) {
  return `principal://agents.global.org-${ORG}.system.id.goog/resources/aiplatform/projects/${MOCK_NUMBER}/locations/${region}/reasoningEngines/${engineId}`;
}

function tool(name: string, description: string, read_only: boolean, destructive = false): McpTool {
  return {
    name,
    description,
    read_only,
    destructive,
    annotations: { readOnlyHint: read_only, destructiveHint: destructive, idempotentHint: read_only, openWorldHint: false },
  };
}

const ENDPOINT_HOSTS = [
  ["aiplatform", "Vertex AI"],
  ["storage", "Cloud Storage"],
  ["bigquery", "BigQuery"],
  ["logging", "Cloud Logging"],
  ["monitoring", "Cloud Monitoring"],
  ["cloudtrace", "Cloud Trace"],
  ["telemetry", "Telemetry"],
  ["secretmanager", "Secret Manager"],
  ["pubsub", "Pub/Sub"],
  ["firestore", "Firestore"],
  ["spanner", "Spanner"],
  ["sqladmin", "Cloud SQL Admin"],
  ["translate", "Cloud Translation"],
  ["documentai", "Document AI"],
  ["discoveryengine", "Vertex AI Search"],
  ["modelarmor", "Model Armor"],
  ["dlp", "Sensitive Data Protection"],
  ["places", "Places"],
  ["routes", "Routes"],
  ["calendar-json", "Google Calendar"],
  ["gmail", "Gmail"],
  ["drive", "Google Drive"],
  ["sheets", "Google Sheets"],
  ["people", "People"],
  ["iamcredentials", "IAM Credentials"],
] as const;

/** A platform allowlist of Google APIs, as an organization registers it: the same API in several forms (plain, .mtls,
 *  .mtls with :443). `{R}` is the region. */
export const PLATFORM_PREFIX = "acme-prod";
const PLATFORM_HOSTS = [
  "agentregistry.googleapis.com",
  "agentregistry.mtls.googleapis.com",
  "aiplatform.{R}.rep.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "cloudresourcemanager.mtls.googleapis.com",
  "cloudresourcemanager.mtls.googleapis.com:443",
  "cloudtrace.mtls.googleapis.com",
  "cloudtrace.mtls.googleapis.com:443",
  "iamcredentials.mtls.googleapis.com",
  "iamcredentials.mtls.googleapis.com:443",
  "sts.googleapis.com",
  "sts.mtls.googleapis.com",
  "telemetry.mtls.googleapis.com",
] as const;

export const MA_ROLES = ["roles/modelarmor.calloutUser", "roles/modelarmor.user", "roles/serviceusage.serviceUsageConsumer"];
const LEVEL_TEXT: Record<string, string> = { LOW_AND_ABOVE: "low and above", MEDIUM_AND_ABOVE: "medium and above", HIGH: "high" };

/** A Template (as GET /model-armor returns it) from the wizard's friendly filter choices. */
export function templateFrom(name: string, f: TemplateFilters, block?: string): Template {
  const rai = Object.entries(f.rai).filter(([, l]) => l !== "off").map(([category, level]) => ({ category, level }));
  const filterConfig: Record<string, unknown> = {};
  if (f.pi_jailbreak !== "off") filterConfig.piAndJailbreakFilterSettings = { filterEnforcement: "ENABLED", confidenceLevel: f.pi_jailbreak };
  if (f.sdp === "basic") filterConfig.sdpSettings = { basicConfig: { filterEnforcement: "ENABLED" } };
  if (f.sdp === "advanced") filterConfig.sdpSettings = { advancedConfig: { inspectTemplate: "INSPECT_TEMPLATE" } };
  if (f.malicious_uri) filterConfig.maliciousUriFilterSettings = { filterEnforcement: "ENABLED" };
  if (rai.length) filterConfig.raiSettings = { raiFilters: rai.map((r) => ({ filterType: r.category, confidenceLevel: r.level })) };
  return {
    name,
    id: name.split("/").pop() ?? name,
    filters: {
      pi_jailbreak: f.pi_jailbreak === "off" ? { enabled: false } : { enabled: true, level: f.pi_jailbreak },
      sdp: f.sdp === "off" ? { enabled: false } : { enabled: true, mode: f.sdp },
      rai,
      malicious_uri: { enabled: f.malicious_uri },
    },
    block_message: block,
    raw: { name, filterConfig, templateMetadata: block ? { customPromptSafetyErrorMessage: block, customLlmResponseSafetyErrorMessage: block, logSanitizeOperations: true, logTemplateOperations: true } : {} },
  };
}
export const levelText = (l: string) => LEVEL_TEXT[l] ?? l;

/** An IAP authz extension: its mode and the gateways whose REQUEST_AUTHZ policy calls it. */
export type IapExt = { name: string; mode: EnforcementMode; gateways: string[]; policies: Record<string, string> };

/** Recompute every gateway's `enforcement` (and its IAP policy chip) from the IAP extensions. */
export function refreshEnforcement(gateways: Gateway[], exts: IapExt[]) {
  for (const g of gateways) {
    const x = exts.find((e) => e.gateways.includes(g.name));
    g.authz_policies = g.authz_policies.filter((p) => p.provider !== "iap");
    if (!x) {
      g.enforcement = { mode: null, extension: "", policy: "", failOpen: false, shared_with: [], editable: false, reason: "No IAP REQUEST_AUTHZ policy on this gateway, so nothing is checked against roles/iap.egressor grants." };
      continue;
    }
    const policy = x.policies[g.name];
    g.authz_policies.unshift({ name: policy, profile: "REQUEST_AUTHZ", provider: "iap", extension: x.name, enforcement: x.mode });
    g.enforcement = { mode: x.mode, extension: x.name, policy, failOpen: x.mode === "DRY_RUN", shared_with: x.gateways.filter((n) => n !== g.name), editable: true, reason: null };
  }
}

/** The page's ?case=merge (mock mode only; never in tests, which have no page). */
export function mergeCase(search = typeof window === "undefined" ? "" : (window.location?.search ?? "")): boolean {
  return new URLSearchParams(search).get("case") === "merge";
}

export function buildWorld(ctx: Ctx) {
  const P = ctx.project || "my-demo-project";
  const R = ctx.region || "us-east4";
  /** us-central1: Model Armor not set up yet. */
  const noMA = R === "us-central1";
  const GP = ctx.gateway_project || P;
  const loc = `projects/${P}/locations/${R}`;
  const reg = `projects/${GP}/locations/${R}`;
  const egress = `projects/${GP}/locations/${R}/agentGateways/corp-egress`;
  const ingress = `${loc}/agentGateways/corp-ingress`;
  const eng = (id: string) => `projects/${MOCK_NUMBER}/locations/${R}/reasoningEngines/${id}`;
  const pscAttachment = `projects/${P}/regions/${R}/networkAttachments/psc-agents`;

  const engines: Inventory["engines"] = [
    {
      name: eng("5527104938261504"),
      id: "5527104938261504",
      display_name: "Helpdesk Agent",
      principal: principalOf(R, "5527104938261504"),
      identity_type: "AGENT_IDENTITY",
      gateways: { egress, ingress },
      create_time: "2026-06-11T14:02:51Z",
      bindable: true,
    },
    {
      name: eng("8840217731518464"),
      id: "8840217731518464",
      display_name: "HR Assistant",
      principal: principalOf(R, "8840217731518464"),
      identity_type: "AGENT_IDENTITY",
      gateways: { egress, ingress },
      create_time: "2026-07-23T09:41:07Z",
      bindable: true,
    },
    {
      name: eng("3318840192745472"),
      id: "3318840192745472",
      display_name: "Travel Planner",
      principal: principalOf(R, "3318840192745472"),
      identity_type: "AGENT_IDENTITY",
      gateways: {},
      create_time: "2026-08-30T17:15:22Z",
      bindable: true,
    },
    {
      // Its own PSC interface into corp-vpc and a service account instead of Agent Identity: it can never be bound
      // to Agent Gateway, and its VPC calls skip the gateway (N1).
      name: eng("5555555555555555555"),
      id: "5555555555555555555",
      display_name: "simple-agent-with-psc",
      principal: `serviceAccount:simple-agent@${P}.iam.gserviceaccount.com`,
      identity_type: "SERVICE_ACCOUNT",
      gateways: {},
      create_time: "2026-09-12T08:20:00Z",
      bindable: false,
      bindable_reason: PSC_BIND_REASON,
      psc_interface: { network_attachment: pscAttachment, vpc: "corp-vpc", dns_domains: ["corp.internal."] },
    },
    {
      // A PSC interface and an egress binding (added by a later update): broken, can't reach Google APIs (N2).
      name: eng("7203391846117376"),
      id: "7203391846117376",
      display_name: "Ops Copilot",
      principal: principalOf(R, "7203391846117376"),
      identity_type: "AGENT_IDENTITY",
      gateways: { egress },
      create_time: "2026-09-02T11:48:30Z",
      bindable: false,
      bindable_reason: PSC_BIND_REASON,
      psc_interface: { network_attachment: pscAttachment, vpc: "corp-vpc", dns_domains: [] },
    },
  ];
  const [helpdesk, hr, travel, , ops] = engines;

  const gateways: Gateway[] = [
    {
      name: egress,
      id: "corp-egress",
      type: "egress",
      governed_access_path: "AGENT_TO_ANYWHERE",
      registries: [`//agentregistry.googleapis.com/${reg}`],
      authz_policies: [
        ...(noMA
          ? []
          : [{ name: `projects/${GP}/locations/${R}/authzPolicies/corp-egress-ma-policy`, profile: "CONTENT_AUTHZ" as const, provider: "model_armor" as const, extension: `projects/${GP}/locations/${R}/authzExtensions/corp-ma-authz`, enforcement: "ENFORCE" as const }]),
      ],
      bound_engines: [
        { engine: helpdesk.name, display_name: helpdesk.display_name, direction: "egress" },
        { engine: hr.name, display_name: hr.display_name, direction: "egress" },
        { engine: ops.name, display_name: ops.display_name, direction: "egress" },
      ],
      create_time: "2026-05-04T10:12:00Z",
      private_egress: noMA
        ? { source: "inline", network_attachment: `projects/${GP}/regions/${R}/networkAttachments/gateway-egress`, vpc: "corp-vpc", dns_domains: ["run.app."] }
        : R === "europe-west1"
          ? { source: "template", template: `projects/${GP}/locations/${R}/agentConnectivityTemplates/corp-private`, network_attachment: "", dns_domains: [], error: "can't read details: HTTP 403: Permission 'networkservices.agentConnectivityTemplates.get' denied" }
          : {
              source: "template",
              template: `projects/${GP}/locations/${R}/agentConnectivityTemplates/corp-private`,
              network_attachment: `projects/${GP}/regions/${R}/networkAttachments/gateway-egress`,
              vpc: "corp-vpc",
              dns_domains: ["run.app.", "corp.internal."],
              vpc_egress: "PRIVATE_RANGES_ONLY",
              custom_trust: false,
            },
    },
    {
      name: ingress,
      id: "corp-ingress",
      type: "ingress",
      governed_access_path: "CLIENT_TO_AGENT",
      registries: [`//agentregistry.googleapis.com/${loc}`],
      authz_policies: [],
      bound_engines: [
        { engine: helpdesk.name, display_name: helpdesk.display_name, direction: "ingress" },
        { engine: hr.name, display_name: hr.display_name, direction: "ingress" },
      ],
      create_time: "2026-05-04T10:31:00Z",
      private_egress: null,
    },
  ];

  // IAP authz extensions (the enforcement mode lives here, not on the gateway).
  const iapExts: IapExt[] = noMA
    ? [{ name: `projects/${GP}/locations/${R}/authzExtensions/corp-egress-iap-authz`, mode: "ENFORCE", gateways: [egress], policies: { [egress]: `projects/${GP}/locations/${R}/authzPolicies/corp-egress-iap-policy` } }]
    : [
        {
          name: `projects/${GP}/locations/${R}/authzExtensions/corp-iap-authz`,
          mode: "DRY_RUN",
          gateways: [egress, ingress],
          policies: { [egress]: `projects/${GP}/locations/${R}/authzPolicies/corp-egress-iap-policy`, [ingress]: `${loc}/authzPolicies/corp-ingress-iap-policy` },
        },
      ];
  refreshEnforcement(gateways, iapExts);

  const template: Template = {
    name: `${loc}/templates/corp-agent-shield`,
    id: "corp-agent-shield",
    filters: {
      pi_jailbreak: { enabled: true, level: "MEDIUM_AND_ABOVE" },
      sdp: { enabled: true, mode: "basic" },
      rai: [
        { category: "HATE_SPEECH", level: "MEDIUM_AND_ABOVE" },
        { category: "HARASSMENT", level: "MEDIUM_AND_ABOVE" },
        { category: "DANGEROUS", level: "HIGH" },
        { category: "SEXUALLY_EXPLICIT", level: "LOW_AND_ABOVE" },
      ],
      malicious_uri: { enabled: true },
    },
    block_message: "Sorry, this request was blocked by your organization's AI safety policy.",
    summary: [
      "Blocks prompt injection and jailbreak attempts (medium confidence and above).",
      "Finds sensitive data (basic: credit card numbers, ID numbers and the like).",
      "Blocks hate speech and harassment (medium and above), dangerous content (high) and sexually explicit content (low and above).",
      "Blocks known malicious URLs.",
    ],
    raw: {},
  };
  template.raw = {
    name: template.name,
    filterConfig: {
      piAndJailbreakFilterSettings: { filterEnforcement: "ENABLED", confidenceLevel: "MEDIUM_AND_ABOVE" },
      sdpSettings: { basicConfig: { filterEnforcement: "ENABLED" } },
      raiSettings: { raiFilters: template.filters.rai.map((r) => ({ filterType: r.category, confidenceLevel: r.level })) },
      maliciousUriFilterSettings: { filterEnforcement: "ENABLED" },
    },
    templateMetadata: { customPromptSafetyErrorMessage: template.block_message, logTemplateOperations: true },
    createTime: "2026-05-04T10:40:12Z",
  };
  const strictTemplate: Template = {
    name: `${loc}/templates/strict-pii`,
    id: "strict-pii",
    filters: {
      pi_jailbreak: { enabled: true, level: "LOW_AND_ABOVE" },
      sdp: { enabled: true, mode: "advanced" },
      rai: [{ category: "DANGEROUS", level: "MEDIUM_AND_ABOVE" }],
      malicious_uri: { enabled: false },
    },
    summary: ["Blocks prompt injection and jailbreak attempts (low confidence and above).", "Finds sensitive data with your inspect template (advanced).", "Blocks dangerous content (medium and above)."],
    raw: { name: `${loc}/templates/strict-pii`, filterConfig: { piAndJailbreakFilterSettings: { filterEnforcement: "ENABLED", confidenceLevel: "LOW_AND_ABOVE" }, sdpSettings: { advancedConfig: { inspectTemplate: `${loc}/inspectTemplates/pii`, deidentifyTemplate: "" } } } },
  };

  const modelArmor: ModelArmorResp = {
    gateways: [
      noMA
        ? { gateway: egress, type: "egress", enabled: false, policy: null, extension: null, template: null }
        : { gateway: egress, type: "egress", enabled: true, policy: gateways[0].authz_policies[1].name, extension: gateways[0].authz_policies[1].extension, template },
      { gateway: ingress, type: "ingress", enabled: false, policy: null, extension: null, template: null },
    ],
    templates: noMA ? [] : [template, strictTemplate],
  };
  // Model Armor authz extensions in the region, and the gateways' service agents with the roles they hold.
  const maExtensions: { name: string; templates: string[] }[] = noMA ? [] : [{ name: `projects/${GP}/locations/${R}/authzExtensions/corp-ma-authz`, templates: [template.name] }];
  const serviceAgents: ServiceAgent[] = [
    {
      email: `service-${MOCK_NUMBER}@gcp-sa-dep.iam.gserviceaccount.com`,
      member: `serviceAccount:service-${MOCK_NUMBER}@gcp-sa-dep.iam.gserviceaccount.com`,
      gateway: egress,
      gateways: [egress],
      project: GP,
      source: "agentGatewayCard.serviceExtensionsServiceAccount",
      note: "The gateway's service extensions service account (from the gateway resource).",
      roles: Object.fromEntries(MA_ROLES.map((r) => [r, !noMA])),
    },
    {
      email: `service-${MOCK_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com`,
      member: `serviceAccount:service-${MOCK_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com`,
      gateway: ingress,
      gateways: [ingress],
      project: P,
      source: "ingress",
      note: "Agent Runtime service agent used by ingress gateways (verified in one project; check yours).",
      roles: Object.fromEntries(MA_ROLES.map((r) => [r, !noMA])),
    },
  ];
  const setup = (): MaSetup => {
    const missing: MaSetup["missing"] = [];
    if (!modelArmor.templates.length) missing.push("template");
    if (!maExtensions.length) missing.push("extension");
    if (serviceAgents.some((a) => Object.values(a.roles).some((v) => v === false))) missing.push("service_agent_roles");
    const used = maExtensions.flatMap((x) => x.templates);
    const ids = new Set(modelArmor.templates.map((t) => t.id));
    const exts = new Set(maExtensions.map((x) => x.name.split("/").pop()));
    const uniq = (n: string, taken: Set<string | undefined>) => {
      if (!taken.has(n)) return n;
      let k = 2;
      while (taken.has(`${n}-${k}`)) k++;
      return `${n}-${k}`;
    };
    return {
      ready: !missing.length,
      missing,
      region: R,
      extensions: maExtensions,
      templates: modelArmor.templates,
      service_agents: serviceAgents,
      roles: MA_ROLES,
      suggested: { template_id: uniq("corp-shield", ids), template: used[0] ?? modelArmor.templates[0]?.name ?? null, extension_name: uniq("corp-ma-authz", exts) },
    };
  };

  const regName = (kind: string, id: string) => `${reg}/${kind}/${id}`;
  const agents: Inventory["agents"] = [
    { name: regName("agents", "helpdesk-agent-rt"), id: "helpdesk-agent-rt", display_name: "Helpdesk Agent", kind: "runtime", engine: helpdesk.name, skills: [{ id: "triage", name: "Triage a ticket", description: "Classifies and routes an IT request." }] },
    { name: regName("agents", "hr-assistant-rt"), id: "hr-assistant-rt", display_name: "HR Assistant", kind: "runtime", engine: hr.name, skills: [{ id: "pto", name: "PTO questions", description: "Answers leave and PTO questions." }] },
    { name: regName("agents", "travel-planner-rt"), id: "travel-planner-rt", display_name: "Travel Planner", kind: "runtime", engine: travel.name, skills: [{ id: "itinerary", name: "Plan an itinerary", description: "Builds a trip plan within policy." }] },
    {
      name: regName("agents", "kb-agent-4c1e"),
      id: "kb-agent-4c1e",
      display_name: "Knowledge Base Agent",
      kind: "a2a",
      url: `https://kb-agent-a1b2c3-uk.a.run.app`,
      skills: [
        { id: "search_kb", name: "Search articles", description: "Full-text search across the IT knowledge base." },
        { id: "summarize_article", name: "Summarize article", description: "Summarizes a KB article for the user." },
        { id: "suggest_fix", name: "Suggest a fix", description: "Suggests troubleshooting steps for an error." },
      ],
    },
    {
      name: regName("agents", "billing-agent-91d0"),
      id: "billing-agent-91d0",
      display_name: "Billing Agent",
      kind: "a2a",
      url: `https://billing-agent-d4e5f6-uk.a.run.app`,
      skills: [
        { id: "lookup_invoice", name: "Look up invoice", description: "Finds an invoice by number or customer." },
        { id: "refund_request", name: "Request a refund", description: "Opens a refund request for review." },
      ],
    },
    {
      name: regName("agents", "calendar-agent-2b7f"),
      id: "calendar-agent-2b7f",
      display_name: "Calendar Agent",
      kind: "a2a",
      url: `https://calendar-agent-778899-uk.a.run.app`,
      skills: [
        { id: "find_slot", name: "Find a free slot", description: "Finds meeting times across calendars." },
        { id: "book_meeting", name: "Book a meeting", description: "Creates a calendar event." },
      ],
    },
  ];

  const mcp_servers: Inventory["mcp_servers"] = [
    {
      name: regName("mcpServers", "tickets-mcp-6a21"),
      id: "tickets-mcp-6a21",
      display_name: "Tickets MCP",
      url: "https://tickets-mcp-a1b2c3-uk.a.run.app/mcp",
      tools: [
        tool("list_tickets", "List open tickets for a queue.", true),
        tool("get_ticket", "Get one ticket with its history.", true),
        tool("search_tickets", "Search tickets by text.", true),
        tool("create_ticket", "Open a new ticket.", false),
        tool("update_ticket", "Change status, assignee or priority.", false),
        tool("close_ticket", "Close a ticket permanently.", false, true),
      ],
    },
    {
      name: regName("mcpServers", "hr-directory-mcp-0f3c"),
      id: "hr-directory-mcp-0f3c",
      display_name: "HR Directory MCP",
      url: "https://hr-directory-mcp-a1b2c3-uk.a.run.app/mcp",
      tools: [
        tool("lookup_employee", "Find an employee by name or email.", true),
        tool("list_org_chart", "Show someone's reporting chain.", true),
        tool("get_pto_balance", "Read an employee's PTO balance.", true),
        tool("submit_pto_request", "Submit a PTO request for approval.", false),
        tool("update_employee_record", "Change HR record fields.", false, true),
        tool("delete_employee_record", "Delete an employee record.", false, true),
      ],
    },
  ];

  const endpoints: Inventory["endpoints"] = ENDPOINT_HOSTS.map(([h, label]) => ({
    name: regName("endpoints", `${h}-googleapis`),
    id: `${h}-googleapis`,
    display_name: `${label} API`,
    url: `https://${h}.googleapis.com`,
  }));
  const platform: Inventory["endpoints"] = PLATFORM_HOSTS.map((t) => {
    const host = t.replace("{R}", R);
    const id = `platform-${host.replace(/[.:]/g, "-")}`;
    return { name: regName("endpoints", id), id, display_name: `${PLATFORM_PREFIX} ${host}`, url: `https://${host}` };
  });
  // Endpoints that aren't Google APIs: never grouped on the map.
  const weather = { name: regName("endpoints", "weather-api"), id: "weather-api", display_name: "Weather API", url: "https://api.weather.example.com/v1" };
  const payments = { name: regName("endpoints", "partner-payments"), id: "partner-payments", display_name: "Partner payments", url: "https://payments.partner.example.net:8443" };
  endpoints.push(...platform, weather, payments);

  const projectSet = `principalSet://agents.global.org-${ORG}.system.id.goog/attribute.platformContainer/aiplatform/projects/${MOCK_NUMBER}`;
  const deleted = principalOf(R, "9001772810240000");
  const b = (member: string, member_label: string, english: string, condition?: Binding["condition"]): Binding => ({ role: ROLE, member, member_label, condition: condition ?? null, english });

  const kb = agents[3], billing = agents[4], cal = agents[5];
  const tickets = mcp_servers[0], hrdir = mcp_servers[1];
  const access: Record<string, Binding[]> = {
    [kb.name]: [
      b(helpdesk.principal, "Helpdesk Agent (Agent Identity)", "Helpdesk Agent can call Knowledge Base Agent (full access)."),
      // A group member: whether an agent is in the group can't be told here (conditional on the map).
      b("group:support-agents@example.com", "Group support-agents@example.com", "Members of support-agents@example.com can call Knowledge Base Agent."),
    ],
    [tickets.name]: [
      b(helpdesk.principal, "Helpdesk Agent (Agent Identity)", "Helpdesk Agent can call only the read-only tools of Tickets MCP.", { title: "MCP read-only tools (by hint)", expression: READ_ONLY_EXPR }),
      b(hr.principal, "HR Assistant (Agent Identity)", "HR Assistant can call only get_ticket and create_ticket on Tickets MCP.", { title: "MCP tools: get_ticket, create_ticket", expression: toolsExpr(["get_ticket", "create_ticket"]) }),
    ],
    [hrdir.name]: [b(hr.principal, "HR Assistant (Agent Identity)", "HR Assistant can call every tool of HR Directory MCP, including destructive ones.")],
    [cal.name]: [
      b(travel.principal, "Travel Planner (Agent Identity)", "Travel Planner can call Calendar Agent (full access)."),
      b("allAuthenticatedUsers", "Any signed-in Google account", "Any signed-in Google account can call Calendar Agent."),
    ],
    [billing.name]: [
      b(deleted, "Deleted agent (reasoningEngines/9001772810240000)", "A deleted agent can still call Billing Agent."),
      // A custom CEL condition: not evaluated client-side (conditional on the map).
      b(hr.principal, "HR Assistant (Agent Identity)", "HR Assistant can call Billing Agent until 2026-12-31 (custom condition).", { title: "Until end of 2026", expression: "request.time < timestamp('2026-12-31T00:00:00Z')" }),
    ],
    // Registry-wide (every entry in this region's Agent Registry), held by a service account.
    [reg]: [b(`serviceAccount:ops-bot@${P}.iam.gserviceaccount.com`, "ops-bot (service account)", "ops-bot can call every agent, MCP server and endpoint in the Agent Registry (registry-wide).")],
  };
  for (const h of ["aiplatform", "logging", "telemetry"]) {
    const e = endpoints.find((x) => x.id === `${h}-googleapis`)!;
    access[e.name] = [b(projectSet, "All agents in project (Agent Identity)", `All agents in this project can call ${e.display_name}.`)];
  }

  for (const e of platform) access[e.name] = [b(projectSet, "All agents in project (Agent Identity)", `All agents in this project can call ${e.display_name}.`)];
  access[weather.name] = [b(travel.principal, "Travel Planner (Agent Identity)", "Travel Planner can call Weather API (full access).")];

  for (const x of [...agents, ...mcp_servers, ...endpoints]) access[x.name] ??= [];
  // One endpoint whose IAP policy couldn't be read: no key in `access`, the reason in `access_errors` (API.md).
  const unreadable = endpoints.find((e) => e.id === "sqladmin-googleapis")!;
  delete access[unreadable.name];
  const access_errors: Record<string, string> = { [unreadable.name]: "Permission denied on iap.webServices.getIamPolicy for this endpoint (403)." };

  // ?case=merge (mock mode only): the Helpdesk Agent holds a second, separate grant on Tickets MCP (close_ticket) next to
  // its read-only one, and every agent inherits search_tickets from a project-wide grant: the Build step's "change
  // existing access" merges the two own grants into one, and shows search_tickets locked.
  if (mergeCase()) {
    const t = mcp_servers[0].name;
    access[t].push(
      b(helpdesk.principal, "Helpdesk Agent (Agent Identity)", "Helpdesk Agent can call only close_ticket on Tickets MCP.", { title: "MCP tools: close_ticket", expression: toolsExpr(["close_ticket"]) }),
      b(projectSet, "All agents in project (Agent Identity)", "All agents in this project can call only search_tickets on Tickets MCP.", { title: "MCP tools: search_tickets", expression: toolsExpr(["search_tickets"]) }),
    );
  }

  // us-west1: the scale scenario (§11.5–11.6) on top of the base world.
  if (R === SCALE_REGION) {
    addScale({ P, R, GP, reg, inventory: { engines, mcp_servers, endpoints, access }, gateways, iapExts, modelArmor, template, principalOf, engineName: eng, projectSet }, scaleFactor());
    refreshEnforcement(gateways, iapExts);
  }

  const labelOf = (name: string) =>
    name === reg ? "Agent Registry (all entries)" : (agents.find((a) => a.name === name)?.display_name ?? mcp_servers.find((m) => m.name === name)?.display_name ?? endpoints.find((e) => e.name === name)?.display_name ?? name);
  const kindOf = (name: string): Grant["resource_kind"] => (name === reg ? "registry" : name.includes("/mcpServers/") ? "mcp_server" : name.includes("/endpoints/") ? "endpoint" : "agent");

  // Writable registry Services behind the entries registered by hand (the Google API endpoints and the Agent Runtime
  // agents are registered by the platform here). The registry projects each into an entry with its own id.
  const services: RegistryService[] = [];
  const serve = (x: { name: string; display_name: string; url?: string; urls?: string[]; service?: string | null }, sid: string, kind: RegistryService["kind"], urls: string[]) => {
    const svc: RegistryService = { name: `${reg}/services/${sid}`, id: sid, kind, display_name: x.display_name, description: "", interfaces: urls.map((url) => ({ url, protocol_binding: kind === "mcp_server" ? "JSONRPC" : "HTTP_JSON" })), registry_resource: x.name.replace(/^projects\/[^/]+\//, `projects/${MOCK_NUMBER}/`) };
    services.push(svc);
    x.service = svc.name;
    x.urls = urls;
  };
  serve(tickets, "tickets-mcp", "mcp_server", [tickets.url!, `https://tickets-mcp-${MOCK_NUMBER}.${R}.run.app/mcp`]);
  serve(hrdir, "hr-directory-mcp", "mcp_server", [hrdir.url!]);
  serve(weather, "weather-api", "endpoint", [weather.url]);
  serve(payments, "partner-payments", "endpoint", [payments.url]);
  services[0].tool_spec = { tools: tickets.tools.map((t) => ({ name: t.name, annotations: t.annotations })) };

  const inventory: Inventory = { engines, agents, mcp_servers, endpoints, access, access_errors, services, project_agents_principal: projectSet, errors: [] };

  const grants = (): Grant[] =>
    Object.entries(inventory.access).flatMap(([res, bs]) => bs.map((x) => ({ ...x, resource: res, resource_kind: kindOf(res), resource_label: labelOf(res) })));

  const findings = (): Finding[] => [
    ...iapExts
      .filter((x) => x.mode === "DRY_RUN")
      .map((x): Finding => {
        const ids = x.gateways.map((n) => n.split("/").pop()!);
        const names = ids.length > 1 ? `${ids.slice(0, -1).join(", ")} and ${ids[ids.length - 1]}` : ids[0];
        return {
          severity: "high",
          title: ids.length > 1 ? `Gateways ${names} are in dry run: nothing is blocked` : `Gateway ${names} is in dry run: nothing is blocked`,
          detail: `The IAP authz extension ${x.name.split("/").pop()} runs in dry run (metadata.iamEnforcementMode DRY_RUN, failOpen true): IAP still decides, but every call passes and is logged as allowed and every request goes through. Switch it to enforce${ids.length > 1 ? ` (the extension is shared, so the fix switches ${names} together; to change one gateway only, give it its own extension on the Gateways step)` : ""}. Check the “would have been denied” log on the Gateways step first.`,
          resource: x.name,
          fix: { id: `fix-enforce-${x.name.split("/").pop()}`, kind: "set_enforcement", gateway: { name: x.gateways[0], direction: x.gateways[0] === ingress ? "ingress" : "egress" }, extension: x.name, mode: "ENFORCE", scope: x.gateways.length > 1 ? "shared" : "dedicated" },
        };
      }),
    {
      severity: "high",
      title: "Travel Planner is not behind an egress gateway",
      detail: "Its outbound calls skip Agent Gateway, so IAP grants and Model Armor screening are never checked. Its grant to Calendar Agent has no gateway in the path.",
      resource: travel.name,
      fix: { id: "fix-bind-travel", kind: "bind_gateway", gateway: { name: egress, direction: "egress" }, engine: travel.name, engine_label: travel.display_name },
    },
    // Private networking N1–N5 (lib/networking.ts, the port of gcp/networking.py). simple-agent-with-psc's PSC
    // interface replaces its "Unprotected egress" finding, as on the backend.
    ...auditRules(inventory.engines, gateways),
    {
      severity: "high",
      title: "Any signed-in Google account can call Calendar Agent",
      detail: "allAuthenticatedUsers holds roles/iap.egressor on Calendar Agent. Egress grants should name agent identities, not public groups.",
      resource: cal.name,
      fix: { id: "fix-revoke-allauth", kind: "revoke", source: { type: "custom", principal: "allAuthenticatedUsers", label: "Any signed-in Google account" }, destination: { kind: "agent", id: cal.id, name: cal.name, label: cal.display_name }, access: { mode: "all" } },
    },
    {
      severity: "medium",
      title: "HR Assistant has unconditional access to an MCP server with destructive tools",
      detail: "HR Directory MCP has update_employee_record and delete_employee_record (destructiveHint). Limit HR Assistant to read-only tools unless it really needs to write.",
      resource: hrdir.name,
      fix: { id: "fix-hr-ro", kind: "grant", source: { type: "engine", principal: hr.principal, label: hr.display_name, engine: hr.name }, destination: { kind: "mcp_server", id: hrdir.id, name: hrdir.name, label: hrdir.display_name }, access: { mode: "read_only_hint" } },
    },
    ...(modelArmor.gateways.find((g) => g.gateway === ingress)?.enabled
      ? []
      : [
          {
            severity: "medium" as const,
            title: "Ingress gateway corp-ingress has no Model Armor",
            detail: "Prompts coming from Gemini Enterprise into Helpdesk Agent and HR Assistant are not screened for prompt injection or sensitive data.",
            resource: ingress,
            fix: { id: "fix-ma-ingress", kind: "model_armor_on" as const, gateway: { name: ingress, direction: "ingress" as const } },
          },
        ]),
    {
      severity: "info",
      title: "A grant points at an agent that no longer exists",
      detail: "reasoningEngines/9001772810240000 was deleted but still holds roles/iap.egressor on Billing Agent. It is harmless today but confusing; remove it.",
      resource: billing.name,
      fix: { id: "fix-revoke-deleted", kind: "revoke", source: { type: "custom", principal: deleted, label: "Deleted agent (…/9001772810240000)" }, destination: { kind: "agent", id: billing.id, name: billing.name, label: billing.display_name } },
    },
    {
      severity: "info",
      title: "Model Armor egress screening does not cover A2A calls",
      detail: "Calls from agents to A2A agents (Knowledge Base, Billing, Calendar) pass through the egress gateway's IAP check, but Model Armor only screens MCP traffic today.",
    },
  ];

  const context = (): ContextInfo => ({
    project: P,
    project_number: MOCK_NUMBER,
    region: R,
    gateway_project: GP,
    principal: "user:alex.admin@example.com",
    apis: {
      "networkservices.googleapis.com": true,
      "networksecurity.googleapis.com": true,
      "agentregistry.googleapis.com": true,
      "iap.googleapis.com": true,
      "aiplatform.googleapis.com": true,
      "modelarmor.googleapis.com": R !== "europe-west1",
      "discoveryengine.googleapis.com": true,
    },
    permissions: [
      { permission: "networkservices.agentGateways.list", granted: true, needed_for: "List gateways (Gateways step)" },
      { permission: "networksecurity.authzPolicies.list", granted: true, needed_for: "See IAP and Model Armor policies on gateways" },
      { permission: "agentregistry.agents.list", granted: true, needed_for: "Inventory: agents, MCP servers, endpoints" },
      { permission: "iap.webServices.getIamPolicy", granted: true, needed_for: "Read who can reach each registry entry" },
      { permission: "aiplatform.reasoningEngines.list", granted: true, needed_for: "List Agent Runtime agents and their identities" },
      { permission: "modelarmor.templates.list", granted: R !== "europe-west1", needed_for: "Read Model Armor templates (Model Armor step)", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/modelarmor.viewer` },
      { permission: "networkservices.agentConnectivityTemplates.get", granted: R !== "europe-west1", needed_for: "Read a gateway's connectivity template (private egress: VPC, domains, egress mode)", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/networkservices.viewer` },
      { permission: "compute.networkAttachments.get", granted: true, needed_for: "Name the VPC behind private networking (optional)" },
      { permission: "iap.webServices.setIamPolicy", granted: false, needed_for: "Apply grants (P3; not needed to generate commands)", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/iap.admin` },
      { permission: "aiplatform.reasoningEngines.update", granted: null, needed_for: "Bind agents to gateways (P3; not checked)" },
    ],
    can_apply: false,
  });

  const audit = (): AuditResp => ({ grants: grants(), findings: findings(), synced_at: new Date().toISOString() });

  return { P, R, GP, gateways, iapExts, modelArmor, maExtensions, serviceAgents, setup, inventory, context, audit, projectSet };
}
