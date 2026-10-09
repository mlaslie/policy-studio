// Types for the Policy Studio API (studio/docs/API.md). Keep in sync with the backend.

export type Ctx = {
  project: string;
  region: string;
  gateway_project?: string;
  ge_app?: string;
  ge_location?: string;
};

export type Direction = "egress" | "ingress";

export type Health = { ok: boolean; version: string };
export type Defaults = { project: string; region: string };

export type PermissionCheck = {
  permission: string;
  granted: boolean | null;
  needed_for: string;
  role?: string;
  /** Needed for Apply (P3) only. */
  write?: boolean;
  project?: string;
  fix?: string | null;
  error?: string;
};
export type ContextInfo = {
  project: string;
  project_number: string;
  region: string;
  gateway_project: string;
  principal: string;
  apis: Record<string, boolean>;
  permissions: PermissionCheck[];
  can_apply: boolean;
  can_apply_reason?: string | null;
  error?: string;
};

export type AuthzPolicy = {
  name: string;
  profile: "REQUEST_AUTHZ" | "CONTENT_AUTHZ";
  provider: "iap" | "model_armor" | "other";
  extension: string;
  enforcement?: "ENFORCE" | "DRY_RUN";
};
export type BoundEngine = { engine: string; display_name: string; direction: Direction };
export type Gateway = {
  name: string;
  id: string;
  type: Direction;
  governed_access_path: string;
  registries: string[];
  authz_policies: AuthzPolicy[];
  bound_engines: BoundEngine[];
  create_time: string;
  error?: string;
};
export type GatewaysResp = { gateways: Gateway[]; notes: string[] };

export type Template = {
  name: string;
  id: string;
  filters: {
    pi_jailbreak: { enabled: boolean; level?: string };
    sdp: { enabled: boolean; mode?: "basic" | "advanced" };
    rai: { category: string; level: string }[];
    malicious_uri: { enabled: boolean };
  };
  block_message?: string;
  raw: object;
};
export type ModelArmorGateway = {
  gateway: string;
  type: Direction;
  enabled: boolean;
  policy: string | null;
  extension: string | null;
  template: Template | null;
  error?: string;
};
export type ModelArmorResp = { gateways: ModelArmorGateway[]; templates: Template[] };

export type Engine = {
  name: string;
  id: string;
  display_name: string;
  principal: string;
  identity_type: string;
  gateways: { egress?: string; ingress?: string };
  create_time: string;
  bindable: boolean;
  error?: string;
};
export type Skill = { id: string; name: string; description: string };
export type RegAgent = {
  name: string;
  id: string;
  display_name: string;
  kind: "runtime" | "a2a";
  url?: string;
  skills: Skill[];
  engine?: string;
};
export type McpTool = {
  name: string;
  description: string;
  read_only: boolean;
  destructive: boolean;
  annotations: Record<string, unknown>;
};
export type McpServer = { name: string; id: string; display_name: string; url?: string; tools: McpTool[] };
export type Endpoint = { name: string; id: string; display_name: string; url: string };

export type Binding = {
  role: string;
  member: string;
  member_label: string;
  condition?: { title: string; expression: string } | null;
  english: string;
};
export type Inventory = {
  engines: Engine[];
  agents: RegAgent[];
  mcp_servers: McpServer[];
  endpoints: Endpoint[];
  access: Record<string, Binding[]>;
};

export type ResourceKind = "agent" | "mcp_server" | "endpoint";
export type Grant = Binding & {
  resource: string;
  resource_kind: ResourceKind | "registry";
  resource_label: string;
};
export type Severity = "high" | "medium" | "info";
export type Finding = { severity: Severity; title: string; detail: string; resource?: string; fix?: Intent };
export type AuditResp = { grants: Grant[]; findings: Finding[]; synced_at: string };

export type IntentKind = "grant" | "revoke" | "bind_gateway" | "unbind_gateway" | "model_armor_on" | "model_armor_off";
export type SourceType = "engine" | "project_agents" | "custom";
export type AccessMode = "all" | "read_only_hint" | "tools" | "custom";
export type Intent = {
  id: string;
  kind: IntentKind;
  source?: { type: SourceType; principal: string; label: string; engine?: string };
  destination?: { kind: ResourceKind; id: string; name: string; label: string };
  access?: { mode: AccessMode; tools?: string[]; expression?: string; title?: string };
  gateway?: { name: string; direction: Direction; extension?: string; policy?: string };
  engine?: string;
  /** Client-only: display label for the engine (bind/unbind). Ignored by the backend. */
  engine_label?: string;
};

export type Outputs = { terraform: string; gcloud: string; rest: string; python: string };
export type Anatomy = { resource: string; role: string; member: string; condition?: string | null; notes: string[] };
export type RenderItem = { intent_id: string; english: string; anatomy: Anatomy; outputs: Outputs; warnings: string[] };
export type RenderResult = {
  items: RenderItem[];
  bundle: { terraform: { "main.tf": string; "variables.tf": string }; gcloud: string; rest: string; python: string };
};

export type DiffStatus = "add" | "present" | "replace" | "remove" | "absent";
export type DiffItem = { intent_id: string; status: DiffStatus; current: Binding[] | null; after?: Binding[] | null; detail: string; error?: string };
export type DiffResult = { items: DiffItem[] };

// ---- P3: run modes, credentials and apply (API.md "Run modes and credentials") ----
export type RunMode = "generate" | "apply";
export type CheckStatus = "ok" | "warn" | "error";
export type AuthCheck = { id: string; status: CheckStatus; title: string; detail: string; fix?: string | null };
export type AdcInfo = {
  ok: boolean;
  type: "user" | "service_account" | "impersonated" | "external_account" | "compute_engine" | "unknown";
  account?: string | null;
  quota_project?: string | null;
  adc_project?: string | null;
  source?: string | null;
  error?: string | null;
};
export type AuthInfo = {
  mode: RunMode;
  runtime: "cloud_run" | "local";
  adc: AdcInfo;
  gcloud: { available: boolean; account?: string | null; project?: string | null };
  target_project: string;
  gateway_project?: string;
  /** Which intent kinds the signed-in user can apply (testIamPermissions). Missing = unknown. */
  writable?: Partial<Record<IntentKind, boolean>>;
  checks: AuthCheck[];
  can_apply: boolean;
  can_apply_reason?: string | null;
};
export type ApplyState = "running" | "done" | "verified" | "failed" | "skipped";
/** `progress: true` with state "done" = a long-running operation is still being polled (not final). */
export type ApplyItemEvent = { intent_id: string; state: ApplyState; detail?: string; operation?: string; progress?: boolean; undo?: Intent | Intent[] | null };
export type ApplyDoneEvent = { type: "done"; summary?: unknown };
export type ApplyEvent = ApplyItemEvent | ApplyDoneEvent;
export type ApplyConfirm = { project: string; acknowledge_destructive: boolean };
