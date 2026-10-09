# Policy Studio: API contract (P1 + P2)

Policy Studio is a standalone app: Python package `policy_studio` (FastAPI) in `backend/`, and a Vite + React app in `frontend/`.
- The backend imports only the standard library and its declared dependencies (a test enforces it).
- In P1 and P2 every endpoint is **read-only** against GCP.
- The backend calls Google APIs with Application Default Credentials (your gcloud login when run locally).

Run it locally with `./studio-app` (backend :8090, serving the built UI). For UI development: `cd frontend && npm run dev` (Vite :5174, which proxies `/api` to :8090), or `npm run dev:mock` (no backend).

## Context

Every request carries the context as query params (GET) or a `context` object (POST):

```json
{"project": "my-project", "region": "us-east4",
 "gateway_project": "",            // optional: project of the egress gateway / Agent Registry (defaults to project)
 "ge_app": "", "ge_location": "us" // optional: Gemini Enterprise app id + location (used in generated commands)
}
```

`project_number` is resolved by the backend and echoed back.

## Endpoints

| Method | Path | Returns |
|---|---|---|
| GET | `/api/studio/health` | `{ok, version}` |
| GET | `/api/studio/defaults` | `{project, region}` from env `STUDIO_PROJECT` / `STUDIO_REGION`, or the gcloud config |
| GET | `/api/studio/context` | `{project, project_number, region, gateway_project, gateway_project_number, ge_app, ge_location, principal, principal_set, apis: {"networkservices.googleapis.com": true, …}, permissions: [PermissionCheck], can_apply: false, errors: [str]}` |
| GET | `/api/studio/gateways` | `{gateways: [Gateway], notes: [str], errors: [str], synced_at}` |
| GET | `/api/studio/model-armor` | `{gateways: [{gateway, type, enabled, policy, extension, template: Template \| null, available_extensions?: [str], error?}], templates: [Template], extensions: [{name, templates}], notes, errors}` |
| GET | `/api/studio/inventory` | `Inventory` |
| GET | `/api/studio/audit` | `{grants: [Grant], findings: [Finding], synced_at}` |
| POST | `/api/studio/render` | `{context, intents: [Intent]}` → `RenderResult` |
| POST | `/api/studio/diff` | `{context, intents: [Intent]}` → `{items: [DiffItem]}` |

GET responses are cached for 30 s per context. `?refresh=1` bypasses the cache; the **Sync** button uses it. Partial failures appear per item as `error: "…"` and never fail the whole request. A failure of the whole request (no credentials, network) is HTTP 502 `{detail}`.

- `principal_set`: every Agent Runtime agent (Agent Identity) in the project, the verified format `principalSet://agents.global.org-<ORG_ID>.system.id.goog/attribute.platformContainer/aiplatform/projects/<PROJECT_NUMBER>` (`null` if the org id can't be found). Use it as `source.principal` for `type: "project_agents"`.
- Engine names use one format everywhere: `projects/<NUMBER>/locations/<R>/reasoningEngines/<ID>` (`Inventory.engines[].name`, `agents[].engine`, `Gateway.bound_engines[].engine`, `Intent.engine`). An engine's `principal` is exactly the IAM member string that appears in `Binding.member` (`principal://…` for Agent Identity, `serviceAccount:…` otherwise).
- `Inventory.access` has a key for **every** agent, MCP server and endpoint (`[]` when nobody has access) plus the registry itself (`projects/<P>/locations/<R>`). A key is omitted only when that IAM policy couldn't be read; the item then has `error` and `access_errors[name]` holds the reason.

## Types

```ts
PermissionCheck = { permission, granted: boolean | null /* null = not checked (call failed or unknown permission) */,
                    needed_for, role, write: boolean /* needed for Apply (later phase) */, project, fix: string | null,
                    error? }
Gateway = { name, id, project, type: "egress" | "ingress", governed_access_path, registries: string[],
            authz_policies: [{name, profile: "REQUEST_AUTHZ"|"CONTENT_AUTHZ", provider: "iap"|"model_armor"|"other",
                              extension, enforcement?: "ENFORCE"|"DRY_RUN"}],
            bound_engines: [{engine, display_name, direction: "egress"|"ingress"}], create_time }
Template = { name, id, filters: {
               pi_jailbreak: {enabled, level?},            // e.g. MEDIUM_AND_ABOVE
               sdp: {enabled, mode?: "basic"|"advanced"},
               rai: [{category, level}],
               malicious_uri: {enabled} },
             block_message?: string, summary: string[] /* plain-English lines */, raw: object }
Inventory = {
  engines: [{ name, id, display_name, principal, identity_type /* AGENT_IDENTITY|SERVICE_AGENT|SERVICE_ACCOUNT */,
              gateways: {egress?, ingress?}, create_time, bindable: boolean /* created on/after 2026-04-29 */ }],
  agents:  [{ name, id, display_name, kind: "runtime"|"a2a", url?, skills: [{id, name, description}], engine?, error? }],
  mcp_servers: [{ name, id, display_name, url?, tools: [{name, description, read_only, destructive, annotations}], error? }],
  endpoints: [{ name, id, display_name, url, error? }],
  access: { [registryResourceName]: Binding[] }, access_errors: { [registryResourceName]: string },
  project_agents_principal: string | null, errors: string[], synced_at }
Binding = { role, member, member_label, condition?: {title, expression}, english }
Grant  = Binding & { resource, resource_kind: "agent"|"mcp_server"|"endpoint"|"registry", resource_label }
Finding = { severity: "high"|"medium"|"info", title, detail, resource?, fix?: Intent, fixes?: Intent[] }
  // fix intents for grant/revoke carry full source and destination objects with labels; bind fixes carry source too

Intent = { id, kind: "grant"|"revoke"|"bind_gateway"|"unbind_gateway"|"model_armor_on"|"model_armor_off",
  source?:      { type: "engine"|"project_agents"|"custom", principal, label, engine? },
  destination?: { kind: "agent"|"mcp_server"|"endpoint"|"registry", id, name, label },
  access?:      { mode: "all"|"read_only_hint"|"tools"|"custom", tools?: string[], expression?: string,
                  title?: string /* exact condition title, e.g. when revoking an existing binding */ },
  gateway?:     { name, direction: "egress"|"ingress", extension?: string, policy?: string },
  engine?:      string }
  // Unknown fields (e.g. a client-only engine_label) are ignored.
  // destination.kind "registry" = a registry-wide grant: id "", name "projects/<P>/locations/<R>" (the Grant.resource
  // of a resource_kind "registry" grant). Rendered on the IAP resource .../iap_web/agentRegistry, gcloud without
  // --agent/--mcp-server/--endpoint, Terraform google_iap_agent_registry_iam_member.
  // gateway.extension / gateway.policy (Model Armor) are filled in by the backend from discovery when omitted.

RenderResult = { context /* resolved, incl. project_number */,
                 items: [{ intent_id, english, error?: string /* this intent failed; others still render */,
                           anatomy: {resource, role, member, condition?, notes: string[] /* explanations */},
                           outputs: {terraform, gcloud, rest, python}, warnings: string[] /* problems only */ }],
                 bundle: { terraform: {"main.tf", "variables.tf"}, gcloud: string /* apply.sh */,
                           rest: string, python: string } }
  // Intents are validated one by one: an invalid intent (or one that fails to render) gets an item with `error`,
  // in its original position, and the others still render. Items with an error are left out of the bundle. Binding changes to the same engine are chained in cart order
  // and the bundle sends them as one PATCH.

DiffItem = { intent_id, status: "add"|"present"|"replace"|"remove"|"absent", detail, error? /* invalid intent */,
             current: Binding[] | null /* the member's roles/iap.egressor bindings on the resource today */,
             after:   Binding[] | null /* the same after the change; null for gateway / Model Armor intents */ }
  // "replace": the member already has a different condition. IAM ORs bindings, so after = current + the new one;
  // revoke the old binding to really replace it.
```

## Conditions

- **`read_only_hint`:** `api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''`
- **`tools`:** `api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['t1', 't2', '']`

The `''` keeps MCP setup traffic (initialize, tools/list) allowed. Both forms are verified live against Agent Gateway.

## Run modes and credentials (P3)

Policy Studio runs in one of two modes:

| Mode | When | Apply |
|---|---|---|
| `generate` | Default on Cloud Run (`K_SERVICE` is set), or `STUDIO_MODE=generate` | **Disabled.** Discovery, audit, builder and command/Terraform generation only. The backend has no write path at all in this mode (the write client is never constructed). |
| `apply` | Default when run locally (no `K_SERVICE`), or `STUDIO_MODE=apply` | **Enabled**, using Application Default Credentials (ADC). Only after the credential checks pass and the user confirms. |

`STUDIO_MODE=apply` on Cloud Run is refused at startup unless `STUDIO_ALLOW_APPLY_ON_CLOUD_RUN=1` is set, which is intentionally awkward.

### `GET /api/studio/auth?project=`

```json
{"mode": "generate"|"apply",
 "runtime": "cloud_run"|"local",
 "adc": {"ok": true, "type": "user"|"service_account"|"impersonated"|"external_account"|"compute_engine"|"unknown",
         "account": "me@example.com", "quota_project": "proj-a", "adc_project": "proj-a",
         "source": "~/.config/gcloud/application_default_credentials.json" | "metadata server" | "GOOGLE_APPLICATION_CREDENTIALS=…",
         "error": null},
 "gcloud": {"available": true, "account": "me@example.com", "project": "proj-a"},
 "target_project": "proj-b",
 "checks": [{"id": "adc_present"|"adc_valid"|"account_matches_gcloud"|"quota_project"|"project_matches"|"can_write",
             "status": "ok"|"warn"|"error", "title": "…", "detail": "…", "fix": "gcloud auth application-default login"}],
 "can_apply": false, "can_apply_reason": "Generate-only mode (Cloud Run service account)"}
```

Checks:
- **ADC present and valid:** the token refreshes.
- **Account:** ADC's account vs gcloud's active account. Warn if they differ.
- **Quota project:** warn if it's missing or differs from the target. Fix: `gcloud auth application-default set-quota-project <target>`.
- **Project match:** the ADC/gcloud project vs the target project. Warn on a mismatch. Apply always uses the *target* project explicitly, but this catches people working in the wrong project.
- **Can write:** `testIamPermissions` on the target project for the write permissions each intent kind needs.

`can_apply` is true only in `apply` mode with no `error` checks.

### `POST /api/studio/apply`

Available only when `can_apply`; otherwise it returns 403 with the reason.

```json
{"context": {...}, "intents": [Intent], "confirm": {"project": "proj-b", "acknowledge_destructive": false}}
```

`confirm.project` must equal `context.project`. Revokes, unbinds and `model_armor_off` need `acknowledge_destructive: true`.

The response streams NDJSON or SSE events per intent: `{intent_id, state: "running"|"done"|"verified"|"failed"|"skipped", detail, operation?, undo?: Intent}`, then `{type: "done", summary}`.

Each intent is applied, then read back and verified:
- **IAP grant/revoke:** getIamPolicy → modify → setIamPolicy with the etag, version 3, and the condition preserved; read back and confirm the binding is there (or gone).
- **bind/unbind gateway:** an engine PATCH that keeps the other direction, one PATCH per engine at a time. It's a long-running operation; the result reports the operation, and a later read-back confirms `agentGatewayConfig`.
- **model_armor_on/off:** create or delete the `CONTENT_AUTHZ` authz policy (long-running operation, about 4 min).

Every applied intent returns its inverse in `undo`, which the UI keeps as an "Undo last apply" list. An apply log is appended to `~/.policy-studio/apply-log.jsonl` (locally).
