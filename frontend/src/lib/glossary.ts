// Glossary for the Learn panel and inline <Term> links. Short = hover text; long = glossary entry.
export type GlossaryEntry = { term: string; short: string; long: string };

export const GLOSSARY: Record<string, GlossaryEntry> = {
  "dry-run": {
    term: "Enforce vs dry run",
    short: "Enforce blocks calls without a grant; dry run lets every call through (for testing grants).",
    long: "A gateway's IAP check (its REQUEST_AUTHZ policy) calls an IAP authz extension, and the mode lives on that extension, not on the gateway. Enforce: failOpen false and no iamEnforcementMode, so calls without a roles/iap.egressor grant get a 403. Dry run: metadata iamEnforcementMode DRY_RUN (and failOpen true): every call goes through, and the request log shows the ones IAP would deny as allowed (Policy Studio computes them from the grants). One extension can serve several gateways; changing it changes all of them, so Policy Studio can give a gateway its own copy first. A change takes effect about 2–3 minutes after Apply (measured), sometimes before the operation reports done.",
  },
  "agent-gateway": {
    term: "Agent Gateway",
    short: "A managed checkpoint that agent traffic passes through, where access and content rules are enforced.",
    long: "Agent Gateway sits in the network path of your agents. It doesn't run your agents; it checks their traffic. An egress gateway checks calls your agents make; an ingress gateway checks calls made to your agents. Rules are attached to a gateway as authz policies (IAP for who-can-call-what, Model Armor for content screening).",
  },
  egress: {
    term: "Egress",
    short: "Outbound: calls your agent makes to other agents, MCP servers and APIs.",
    long: "Egress is traffic leaving your agent (mode AGENT_TO_ANYWHERE). Once an agent is bound to an egress gateway, everything it calls is denied by default; only destinations it has been granted roles/iap.egressor on are allowed.",
  },
  ingress: {
    term: "Ingress",
    short: "Inbound: calls made to your agent, for example from a Gemini Enterprise app.",
    long: "Ingress is traffic arriving at your agent (mode CLIENT_TO_AGENT). The ingress gateway can screen prompts with Model Armor before they reach the agent.",
  },
  "agent-identity": {
    term: "Agent Identity (principal)",
    short: "The agent's own identity, a long principal://… string you grant access to.",
    long: "Every Agent Runtime agent created with identity type AGENT_IDENTITY gets its own principal, like principal://agents.global.org-…/resources/aiplatform/projects/<number>/locations/<region>/reasoningEngines/<id>. You never type it by hand: pick the agent and Policy Studio fills it in. It is what IAM checks when the agent makes a call.",
  },
  "principal-set": {
    term: "All agents in project (principalSet)",
    short: "A group that matches every Agent Runtime agent in a project, now and in the future.",
    long: "principalSet://…/attribute.platformContainer/aiplatform/projects/<number> matches every agent identity in the project. It's handy for shared destinations such as Google APIs, but it is broad: new agents get the access automatically.",
  },
  "agent-registry": {
    term: "Agent Registry",
    short: "The catalog of agents, MCP servers and API endpoints a gateway knows about.",
    long: "The gateway only routes to destinations that are registered in its Agent Registry. Each registry entry (an agent, an MCP server, or an endpoint) is also an IAM resource: its policy says who may reach it.",
  },
  "iap-egressor": {
    term: "roles/iap.egressor",
    short: "The IAM role that means 'may send traffic to this destination through the gateway'.",
    long: "roles/iap.egressor is the one role that matters for egress. Granting it to an agent's principal on a registry entry lets that agent call it through the egress gateway. Without it, the gateway's IAP check denies the call.",
  },
  "iam-condition": {
    term: "IAM condition",
    short: "An optional rule on a grant that narrows when it applies, e.g. only read-only tools.",
    long: "A condition is a small CEL expression evaluated on each request. For MCP servers the gateway exposes the tool being called (iap.googleapis.com/mcp.toolName) and whether the server marked it read-only (iap.googleapis.com/mcp.tool.isReadOnly). A grant with a condition only allows requests where the expression is true.",
  },
  "empty-tool": {
    term: "The '' in conditions",
    short: "Lets MCP setup calls through: initialize and tools/list carry no tool name.",
    long: "Before calling a tool, an MCP client sends setup requests (initialize, tools/list). Those have no tool name, so mcp.toolName is ''. Every tool-based condition therefore also allows '', otherwise the agent couldn't even connect.",
  },
  "mcp-hints": {
    term: "MCP hints",
    short: "Labels an MCP server puts on each tool: readOnlyHint, destructiveHint, …",
    long: "MCP tools carry annotations. readOnlyHint=true says the tool only reads; destructiveHint=true says it may delete or overwrite. 'Read-only by hint' grants trust the server's readOnlyHint, so new read-only tools are covered automatically, and new write tools are not.",
  },
  "model-armor-template": {
    term: "Model Armor template",
    short: "A saved set of content filters: prompt injection, sensitive data, harmful content, malicious URLs.",
    long: "A Model Armor template lists which filters run and how sensitive they are (e.g. 'block prompt injection at MEDIUM confidence and above'). A gateway uses a template through a Model Armor authz extension and a CONTENT_AUTHZ policy.",
  },
  "content-authz": {
    term: "CONTENT_AUTHZ",
    short: "A gateway policy type that screens message content (used for Model Armor).",
    long: "Gateways have two kinds of authz policies: REQUEST_AUTHZ decides who may call what (IAP), CONTENT_AUTHZ looks at what is being said (Model Armor). Turning Model Armor on for a gateway means attaching a CONTENT_AUTHZ policy.",
  },
  "authz-extension": {
    term: "Authz extension (Model Armor)",
    short: "A Network Services resource that tells the gateway which service to ask, here Model Armor with a template.",
    long: "An authz extension points the gateway at a policy service. A Model Armor extension has service modelarmor.<region>.rep.googleapis.com and metadata.model_armor_settings naming the template used for requests and responses. On its own it does nothing: a CONTENT_AUTHZ policy attaches it to a gateway. failOpen false means traffic is blocked (not let through unscreened) if Model Armor can't be reached.",
  },
  "ma-service-agent": {
    term: "Gateway service agent",
    short: "The Google-managed identity a gateway uses to call Model Armor; it needs three roles on the project.",
    long: "When a gateway screens content it calls Model Armor as its service agent, named in the gateway resource (agentGatewayCard.serviceExtensionsServiceAccount, service-…@gcp-sa-dep.iam.gserviceaccount.com). Ingress gateways also use the Agent Runtime service agent (service-<project number>@gcp-sa-aiplatform-re.iam.gserviceaccount.com; verified in one project, check yours). Each needs roles/modelarmor.calloutUser, roles/modelarmor.user and roles/serviceusage.serviceUsageConsumer on the project that holds the template, otherwise every screened request fails.",
  },
  "request-authz": {
    term: "REQUEST_AUTHZ (IAP)",
    short: "A gateway policy type that checks who may call what, using IAP and IAM grants.",
    long: "The egress gateway's REQUEST_AUTHZ policy hands each call to Identity-Aware Proxy, which checks whether the calling agent's principal holds roles/iap.egressor on the destination's registry entry.",
  },
  a2a: {
    term: "A2A agent",
    short: "Another agent your agent can call using the Agent2Agent protocol.",
    long: "A2A (Agent2Agent) is a protocol for agents to call each other. A2A agents are registered with an agent card listing their skills.",
  },
  mcp: {
    term: "MCP server",
    short: "A server that exposes tools to agents using the Model Context Protocol.",
    long: "An MCP server offers named tools (list_tickets, create_ticket, …). Grants on MCP servers can be narrowed to some of those tools with an IAM condition.",
  },
  "psc-interface": {
    term: "PSC interface (agent)",
    short: "An agent's own private network connection into a VPC. Those calls skip the gateway.",
    long: "Agent Runtime can give an agent its own Private Service Connect interface (pscInterfaceConfig) into a VPC. Calls through it don't go through the gateway, so no registry check, no IAP grant and no gateway logs apply to them: the agent's grants mean nothing for its VPC traffic. Google rejects an agent with both a PSC interface and a gateway binding (one added by a later update can't reach Google APIs), so an agent like this can't be bound. To govern it, redeploy it without the PSC interface and reach the VPC through the gateway's private egress.",
  },
  "connectivity-template": {
    term: "Connectivity template",
    short: "A reusable network setup that lets an egress gateway reach into a VPC.",
    long: "An agent connectivity template names a network attachment in your VPC, the private DNS domains the gateway resolves there (e.g. run.app., corp.internal.) and the egress mode: private ranges only, or all traffic (used with VPC Service Controls; needs Cloud NAT for the internet). A gateway references it by project number. The older form puts the same settings inline on the gateway (networkConfig); VPC Service Controls and custom trust need a template. Policy Studio shows them; it doesn't create them.",
  },
  "private-egress": {
    term: "Private egress",
    short: "The egress gateway can reach destinations inside a VPC, still checked by IAP.",
    long: "With a connectivity template (or inline networkConfig) the egress gateway reaches private destinations in a VPC, such as internal Cloud Run services or on-prem APIs. Unlike an agent's own PSC interface, these calls still go through the gateway: registry, roles/iap.egressor grants and gateway logs all apply. Without it, the gateway has public egress only.",
  },
  "seen-in-traffic": {
    term: "Path (seen in traffic)",
    short: "Where a destination's calls actually went: a private or a public address, from the gateway logs.",
    long: "Each gateway request log entry records the address the gateway connected to (httpRequest.serverIp). Over the last 7 days, a destination is Private (seen in traffic) when calls reached it at a private address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7), which means through the gateway's private egress, and Public (seen in traffic) when they only reached public ones. Mixed paths means both: usually several hostnames, only some of them resolving into the VPC, or a DNS change inside the window. No label means no calls were seen. Denied calls don't count (they never connect). Sync reads it.",
  },
  runtime: {
    term: "Agent Runtime engine",
    short: "A deployed agent on Vertex AI Agent Runtime (a 'reasoning engine').",
    long: "Agent Runtime hosts your agent. Each deployment is an engine with its own Agent Identity. Engines are bound to gateways with a PATCH of agentGatewayConfig; engines created before 2026-04-29 can't be bound.",
  },
};
