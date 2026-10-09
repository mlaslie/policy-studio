// Realistic mock state for `npm run dev:mock` (VITE_MOCK=1). Built from the context so project and
// region edits show up everywhere. Defaults: my-demo-project / us-east4.
import type { AuditResp, Binding, ContextInfo, Ctx, Finding, Gateway, Grant, Inventory, McpTool, ModelArmorResp, Template } from "./types";
import { READ_ONLY_EXPR, ROLE, toolsExpr } from "../lib/policy";

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

export function buildWorld(ctx: Ctx) {
  const P = ctx.project || "my-demo-project";
  const R = ctx.region || "us-east4";
  const GP = ctx.gateway_project || P;
  const loc = `projects/${P}/locations/${R}`;
  const reg = `projects/${GP}/locations/${R}`;
  const egress = `projects/${GP}/locations/${R}/agentGateways/corp-egress`;
  const ingress = `${loc}/agentGateways/corp-ingress`;
  const eng = (id: string) => `projects/${MOCK_NUMBER}/locations/${R}/reasoningEngines/${id}`;

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
      gateways: { egress },
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
  ];
  const [helpdesk, hr, travel] = engines;

  const gateways: Gateway[] = [
    {
      name: egress,
      id: "corp-egress",
      type: "egress",
      governed_access_path: "AGENT_TO_ANYWHERE",
      registries: [`//agentregistry.googleapis.com/${reg}`],
      authz_policies: [
        { name: `projects/${GP}/locations/${R}/authzPolicies/corp-egress-iap-policy`, profile: "REQUEST_AUTHZ", provider: "iap", extension: `projects/${GP}/locations/${R}/authzExtensions/corp-egress-iap-authz`, enforcement: "ENFORCE" },
        { name: `projects/${GP}/locations/${R}/authzPolicies/corp-egress-ma-policy`, profile: "CONTENT_AUTHZ", provider: "model_armor", extension: `projects/${GP}/locations/${R}/authzExtensions/corp-ma-authz`, enforcement: "ENFORCE" },
      ],
      bound_engines: [
        { engine: helpdesk.name, display_name: helpdesk.display_name, direction: "egress" },
        { engine: hr.name, display_name: hr.display_name, direction: "egress" },
      ],
      create_time: "2026-05-04T10:12:00Z",
    },
    {
      name: ingress,
      id: "corp-ingress",
      type: "ingress",
      governed_access_path: "CLIENT_TO_AGENT",
      registries: [`//agentregistry.googleapis.com/${loc}`],
      authz_policies: [],
      bound_engines: [{ engine: helpdesk.name, display_name: helpdesk.display_name, direction: "ingress" }],
      create_time: "2026-05-04T10:31:00Z",
    },
  ];

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
    raw: { name: `${loc}/templates/strict-pii`, filterConfig: { piAndJailbreakFilterSettings: { filterEnforcement: "ENABLED", confidenceLevel: "LOW_AND_ABOVE" }, sdpSettings: { advancedConfig: { inspectTemplate: `${loc}/inspectTemplates/pii`, deidentifyTemplate: "" } } } },
  };

  const modelArmor: ModelArmorResp = {
    gateways: [
      { gateway: egress, type: "egress", enabled: true, policy: gateways[0].authz_policies[1].name, extension: gateways[0].authz_policies[1].extension, template },
      { gateway: ingress, type: "ingress", enabled: false, policy: null, extension: null, template: null },
    ],
    templates: [template, strictTemplate],
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

  const projectSet = `principalSet://agents.global.org-${ORG}.system.id.goog/attribute.platformContainer/aiplatform/projects/${MOCK_NUMBER}`;
  const deleted = principalOf(R, "9001772810240000");
  const b = (member: string, member_label: string, english: string, condition?: Binding["condition"]): Binding => ({ role: ROLE, member, member_label, condition: condition ?? null, english });

  const kb = agents[3], billing = agents[4], cal = agents[5];
  const tickets = mcp_servers[0], hrdir = mcp_servers[1];
  const access: Record<string, Binding[]> = {
    [kb.name]: [b(helpdesk.principal, "Helpdesk Agent (Agent Identity)", "Helpdesk Agent can call Knowledge Base Agent (full access).")],
    [tickets.name]: [
      b(helpdesk.principal, "Helpdesk Agent (Agent Identity)", "Helpdesk Agent can call only the read-only tools of Tickets MCP.", { title: "MCP read-only tools (by hint)", expression: READ_ONLY_EXPR }),
      b(hr.principal, "HR Assistant (Agent Identity)", "HR Assistant can call only get_ticket and create_ticket on Tickets MCP.", { title: "MCP tools: get_ticket, create_ticket", expression: toolsExpr(["get_ticket", "create_ticket"]) }),
    ],
    [hrdir.name]: [b(hr.principal, "HR Assistant (Agent Identity)", "HR Assistant can call every tool of HR Directory MCP, including destructive ones.")],
    [cal.name]: [
      b(travel.principal, "Travel Planner (Agent Identity)", "Travel Planner can call Calendar Agent (full access)."),
      b("allAuthenticatedUsers", "Any signed-in Google account", "Any signed-in Google account can call Calendar Agent."),
    ],
    [billing.name]: [b(deleted, "Deleted agent (reasoningEngines/9001772810240000)", "A deleted agent can still call Billing Agent.")],
  };
  for (const h of ["aiplatform", "logging", "telemetry"]) {
    const e = endpoints.find((x) => x.id === `${h}-googleapis`)!;
    access[e.name] = [b(projectSet, "All agents in project (Agent Identity)", `All agents in this project can call ${e.display_name}.`)];
  }

  for (const x of [...agents, ...mcp_servers, ...endpoints]) access[x.name] ??= [];

  const labelOf = (name: string) =>
    agents.find((a) => a.name === name)?.display_name ?? mcp_servers.find((m) => m.name === name)?.display_name ?? endpoints.find((e) => e.name === name)?.display_name ?? name;
  const kindOf = (name: string): Grant["resource_kind"] => (name.includes("/mcpServers/") ? "mcp_server" : name.includes("/endpoints/") ? "endpoint" : "agent");

  const inventory: Inventory = { engines, agents, mcp_servers, endpoints, access };

  const grants = (): Grant[] =>
    Object.entries(inventory.access).flatMap(([res, bs]) => bs.map((x) => ({ ...x, resource: res, resource_kind: kindOf(res), resource_label: labelOf(res) })));

  const findings = (): Finding[] => [
    {
      severity: "high",
      title: "Travel Planner is not behind an egress gateway",
      detail: "Its outbound calls skip Agent Gateway, so IAP grants and Model Armor screening are never checked. Its grant to Calendar Agent has no gateway in the path.",
      resource: travel.name,
      fix: { id: "fix-bind-travel", kind: "bind_gateway", gateway: { name: egress, direction: "egress" }, engine: travel.name, engine_label: travel.display_name },
    },
    {
      severity: "high",
      title: "Any signed-in Google account can call Calendar Agent",
      detail: "allAuthenticatedUsers holds roles/iap.egressor on Calendar Agent. Egress grants should name agent identities, not public groups.",
      resource: cal.name,
      fix: { id: "fix-revoke-allauth", kind: "revoke", source: { type: "custom", principal: "allAuthenticatedUsers", label: "Any signed-in Google account" }, destination: { kind: "agent", id: cal.id, name: cal.name, label: cal.display_name } },
    },
    {
      severity: "medium",
      title: "HR Assistant has unconditional access to an MCP server with destructive tools",
      detail: "HR Directory MCP has update_employee_record and delete_employee_record (destructiveHint). Limit HR Assistant to read-only tools unless it really needs to write.",
      resource: hrdir.name,
      fix: { id: "fix-hr-ro", kind: "grant", source: { type: "engine", principal: hr.principal, label: hr.display_name, engine: hr.name }, destination: { kind: "mcp_server", id: hrdir.id, name: hrdir.name, label: hrdir.display_name }, access: { mode: "read_only_hint" } },
    },
    {
      severity: "medium",
      title: "Ingress gateway corp-ingress has no Model Armor",
      detail: "Prompts coming from Gemini Enterprise into Helpdesk Agent are not screened for prompt injection or sensitive data.",
      resource: ingress,
      fix: { id: "fix-ma-ingress", kind: "model_armor_on", gateway: { name: ingress, direction: "ingress" } },
    },
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
      { permission: "networkservices.agentGateways.list", granted: true, needed_for: "List gateways (step 1)" },
      { permission: "networksecurity.authzPolicies.list", granted: true, needed_for: "See IAP and Model Armor policies on gateways" },
      { permission: "agentregistry.agents.list", granted: true, needed_for: "Inventory: agents, MCP servers, endpoints" },
      { permission: "iap.webServices.getIamPolicy", granted: true, needed_for: "Read who can reach each registry entry" },
      { permission: "aiplatform.reasoningEngines.list", granted: true, needed_for: "List Agent Runtime agents and their identities" },
      { permission: "modelarmor.templates.list", granted: R !== "europe-west1", needed_for: "Read Model Armor templates (step 2)", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/modelarmor.viewer` },
      { permission: "iap.webServices.setIamPolicy", granted: false, needed_for: "Apply grants (P3; not needed to generate commands)", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/iap.admin` },
      { permission: "aiplatform.reasoningEngines.update", granted: null, needed_for: "Bind agents to gateways (P3; not checked)" },
    ],
    can_apply: false,
  });

  const audit = (): AuditResp => ({ grants: grants(), findings: findings(), synced_at: new Date().toISOString() });

  return { P, R, GP, gateways, modelArmor, inventory, context, audit, projectSet };
}
