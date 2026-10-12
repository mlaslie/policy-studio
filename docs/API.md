# Policy Studio: API contract (P1 + P2)

Policy Studio is a standalone app: Python package `policy_studio` (FastAPI) in `backend/`, and a Vite + React app in `frontend/`.
- The backend imports only the standard library and its declared dependencies (a test enforces it).
- In P1 and P2 every endpoint is **read-only** against GCP.
- The backend calls Google APIs with Application Default Credentials (your gcloud login when run locally).

Run it locally with `./studio-app` (backend :8090, serving the built UI). For UI development: `cd frontend && npm run dev` (Vite :5174, which proxies `/api` to :8090), or `npm run dev:mock` (no backend).

The policy map (UI step 1, [VISUALIZATION_PLAN.md](VISUALIZATION_PLAN.md)) has no endpoint of its own: it is built in
the browser from `/inventory`, `/gateways` and `/model-armor` (plus the saved context), and its staged-change preview applies the
cart in the browser too. The only backend change it needed is the `modify` intent (see Intent below), which its
"Change access" action stages.

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
| GET | `/api/studio/model-armor` | `{gateways: [{gateway, type, enabled, policy, extension, template: Template \| null, available_extensions?: [str], error?}], templates: [Template], extensions: [{name, templates}], setup: MaSetup, notes, errors}` |
| GET | `/api/studio/inventory` | `Inventory` |
| GET | `/api/studio/audit` | `{grants: [Grant], findings: [Finding], synced_at}` |
| POST | `/api/studio/render` | `{context, intents: [Intent]}` → `RenderResult` |
| POST | `/api/studio/diff` | `{context, intents: [Intent]}` → `{items: [DiffItem]}` |
| POST | `/api/studio/preflight` | `{context, intents: [Intent]}` → `{items: [PreflightItem]}` (read-only; the checks `/apply` enforces) |
| GET | `/api/studio/gateway-logs?gateway=&since=24h&limit=200` | `GatewayLogs` (read-only Cloud Logging `entries:list`; see below) |

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
            bound_engines: [{engine, display_name, direction: "egress"|"ingress"}], create_time,
            enforcement: GatewayEnforcement }
GatewayEnforcement = { mode: "ENFORCE" | "DRY_RUN" | null, extension /* the IAP authz extension */,
                       policy /* the REQUEST_AUTHZ policy that calls it */, failOpen: boolean,
                       shared_with: string[] /* other gateways (full names) whose IAP policy uses the same extension */,
                       editable: boolean, reason?: string /* why not: no IAP policy, extension unreadable, ... */ }
  // The mode lives on the IAP authz extension (service iap.googleapis.com), not the gateway:
  //   ENFORCE = failOpen false, metadata {iapPolicyVersion: "V1"} (no iamEnforcementMode)
  //   DRY_RUN = failOpen true,  metadata {iapPolicyVersion: "V1", iamEnforcementMode: "DRY_RUN"}
  // Several gateways can share an extension: changing it in place changes all of them.
MaSetup = { ready: boolean, missing: ("template"|"extension"|"service_agent_roles")[], region,
            extensions: [{name, templates}], templates: [Template],
            service_agents: [{email, member, gateway, gateways: [str], project, source, note,
                              roles: {"roles/modelarmor.calloutUser"|"roles/modelarmor.user"|
                                      "roles/serviceusage.serviceUsageConsumer": boolean | null /* null = IAM unreadable */},
                              error?}],
            roles: [str], suggested: {template_id /* for a new template */, template /* existing one to reuse */ | null,
                                      extension_name} }
  // service agents: each gateway's agentGatewayCard.serviceExtensionsServiceAccount, plus for ingress gateways
  // service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com (verified in one project; check yours).
  // Roles are read with project getIamPolicy (read-only); only unconditional bindings count.
Template = { name, id, filters: {
               pi_jailbreak: {enabled, level?},            // e.g. MEDIUM_AND_ABOVE
               sdp: {enabled, mode?: "basic"|"advanced"},
               rai: [{category, level}],
               malicious_uri: {enabled} },
             block_message?: string, summary: string[] /* plain-English lines */, raw: object }
Inventory = {
  engines: [{ name, id, display_name, principal, identity_type /* AGENT_IDENTITY|SERVICE_AGENT|SERVICE_ACCOUNT */,
              gateways: {egress?, ingress?}, create_time,
              bindable: boolean /* identity_type AGENT_IDENTITY and created on/after 2026-04-29 */,
              bindable_reason: string | null }],
  agents:  [{ name, id, display_name, kind: "runtime"|"a2a", url?, skills: [{id, name, description}], engine?, error? }],
  mcp_servers: [{ name, id, display_name, url?, tools: [{name, description, read_only, destructive, annotations}], error? }],
  endpoints: [{ name, id, display_name, url, error? }],
  access: { [registryResourceName]: Binding[] }, access_errors: { [registryResourceName]: string },
  project_agents_principal: string | null, errors: string[], synced_at }
Binding = { role, member, member_label, condition?: {title, expression}, english }
Grant  = Binding & { resource, resource_kind: "agent"|"mcp_server"|"endpoint"|"registry", resource_label }
  // To revoke a Grant, send its exact condition: access {mode: "custom", expression: <condition.expression>,
  // title: <condition.title>} ({mode: "all"} when it has none) and destination.kind = resource_kind (id "" for
  // "registry"). IAM matches the binding by its exact expression; a revoke without access removes only the
  // unconditional binding, and regenerating the expression from the mode (tools, read_only_hint) may not match.
Finding = { severity: "high"|"medium"|"info", title, detail, resource?, fix?: Intent, fixes?: Intent[],
            redeploy?: string /* Python: redeploy with Agent Identity, for engines that can't be bound (no fix) */ }
  // fix intents for grant/revoke carry full source and destination objects with labels; bind fixes carry source too

Intent = { id, kind: "grant"|"revoke"|"modify"|"bind_gateway"|"unbind_gateway"|"model_armor_on"|"model_armor_off"
              |"model_armor_template"|"model_armor_extension"|"iam_project_grant"
              |"set_enforcement"|"dedicate_extension",
  source?:      { type: "engine"|"project_agents"|"custom", principal, label, engine? },
  destination?: { kind: "agent"|"mcp_server"|"endpoint"|"registry", id, name, label },
  access?:      { mode: "all"|"read_only_hint"|"tools"|"custom", tools?: string[], expression?: string,
                  title?: string /* exact condition title, e.g. when revoking an existing binding */ },
                  // grant/revoke: no access = unconditional. Revoke fixes (/audit) and the undo of a revoke carry
                  // the binding's condition verbatim as mode "custom"; its English describes what it is.
                  // modify: the new access.
  access_from?: Access /* modify (required): the existing binding's condition, exact, as a revoke carries it:
                          {mode: "custom", expression, title}, or {mode: "all"} when it has none */,
  gateway?:     { name, direction: "egress"|"ingress", extension?: string, policy?: string },
  engine?:      string,
  params?:      SetupParams /* the Model Armor setup kinds */,
  // set_enforcement
  extension?: string /* the IAP authz extension (default: the gateway's) */, mode?: "ENFORCE"|"DRY_RUN",
  scope?: "shared" /* update the extension in place: every gateway in shared_with changes too */
        | "dedicated" /* the extension is (or is about to be) this gateway's own */,
  // dedicate_extension
  source_extension?: string /* default: the gateway's extension */, new_name?: string /* default <gateway>-iap-authz */,
  revert?: boolean /* the undo: point the policy back at source_extension, delete new_name */ }
  // set_enforcement: PATCH .../authzExtensions/NAME?updateMask=metadata,failOpen (metadata replaced wholesale: every
  //   other key is re-sent); gcloud service-extensions authz-extensions import (full spec built from the current
  //   extension); Terraform google_network_services_authz_extension with an import block; Python
  //   DepServiceClient.update_authz_extension + FieldMask. DRY_RUN is destructive (stops blocking), ENFORCE isn't.
  // dedicate_extension: create a copy of the extension (same service, timeout, failOpen, metadata, labels), then
  //   PATCH the gateway's REQUEST_AUTHZ policy ?updateMask=customProvider.authzExtension.resources,labels with body
  //   {customProvider: {authzExtension: {resources: [COPY]}}, labels: <the policy's current labels>}: a PATCH of
  //   customProvider alone clears the policy's labels (seen live), so labels is in the mask and re-sent (REST, Python
  //   and the gcloud YAML; Terraform's imported google_network_security_authz_policy repeats them). Verified live: the
  //   PATCH updates the policy in place (~20 s operation); Terraform plans 1 import, 1 add, 1 change, 0 destroy. Not
  //   verified: gcloud authz-policies import updating the existing policy in place. The UI stages it with a
  //   set_enforcement of the copy (extension = the copy's name, scope "dedicated"); render folds that into the copy's
  //   Terraform resource. revert is destructive (deletes the copy; kept if another policy still uses it).
  // A mode change takes effect in about 2–3 minutes (measured), and can take effect before the operation reports
  // done.
SetupParams = { project? /* default: the gateway project */, delete?: boolean /* the inverse (undo) */,
  // model_armor_template
  template_id?, block_message?, inspect_template? /* sdp "advanced" */,
  filters?: { pi_jailbreak: "LOW_AND_ABOVE"|"MEDIUM_AND_ABOVE"|"HIGH"|"off", sdp: "basic"|"advanced"|"off",
              rai: {HATE_SPEECH|HARASSMENT|SEXUALLY_EXPLICIT|DANGEROUS: level|"off"}, malicious_uri: boolean },
  // model_armor_extension
  name?, template? /* id or projects/P/locations/R/templates/T */,
  // iam_project_grant (only the three Model Armor roles)
  member?, roles?: string[], gateway? }
  // model_armor_on without gateway.extension uses an extension a model_armor_extension in the same request creates
  // (no placeholder, no warning); otherwise the one discovery finds; otherwise MODEL_ARMOR_EXTENSION with a warning.
  // Bundle / apply order: bindings, template -> extension -> service agent roles -> Model Armor on/off, grants;
  // setup deletes after Model Armor off, in reverse.
  // Duplicates (same kind + gateway / engine / source / destination / access / params) render with a warning
  // and are left out of the bundle; /apply skips them. bind_gateway of an engine that can't be bound renders as an
  // item error.
  // Unknown fields (e.g. a client-only engine_label) are ignored.
  // destination.kind "registry" = a registry-wide grant: id "", name "projects/<P>/locations/<R>" (the Grant.resource
  // of a resource_kind "registry" grant). Rendered on the IAP resource .../iap_web/agentRegistry, gcloud without
  // --agent/--mcp-server/--endpoint, Terraform google_iap_agent_registry_iam_member.
  // gateway.extension / gateway.policy (Model Armor) are filled in by the backend from discovery when omitted.
  // modify = change a grant's condition (source, destination, access_from and access are required; otherwise the
  // item is invalid). IAM adds bindings rather than replacing them, so a grant alone would leave the old access in
  // place; a modify removes the binding matching access_from exactly and adds the new one in ONE setIamPolicy.
  // English: "Change <source>'s access to <destination>: full access → only read-only tools." Rendered as one
  // read-modify-write: gcloud iap web get-iam-policy → jq → set-iam-policy (not remove- + add-iam-policy-binding;
  // not verified live for --resource-type=agent-registry), REST getIamPolicy → jq → setIamPolicy, Python modify();
  // Terraform: an _iam_member is keyed by its condition, so it is a destroy + create there: the item shows the
  // block with the new condition and lifecycle { create_before_destroy = true }, and suggests the _iam_policy
  // resource for whole-policy management. Not destructive (no acknowledge_destructive); render warns and preflight
  // adds a `warning` when it widens access (e.g. read-only tools → full access).

RenderResult = { context /* resolved, incl. project_number */,
                 items: [{ intent_id, english, error?: string /* this intent failed; others still render */,
                           anatomy: {resource, role, member, condition?, notes: string[] /* explanations */},
                           outputs: {terraform, gcloud, rest, python}, warnings: string[] /* problems only */ }],
                 bundle: { terraform: {"main.tf", "variables.tf"}, gcloud: string /* apply.sh */,
                           rest: string, python: string } }
  // Intents are validated one by one: an invalid intent (or one that fails to render) gets an item with `error`,
  // in its original position, and the others still render. Items with an error are left out of the bundle. Binding changes to the same engine are chained in cart order
  // and the bundle sends them as one PATCH.

PreflightItem = { intent_id, status: "ok"|"blocked"|"duplicate"|"invalid", reason?,
                  fix?: "ma_setup"|"redeploy"|"permission"|"already"|"", duplicate_of?,
                  warning? /* ok, but affects more than it names: a shared IAP extension */ }
  // blocked: bind_gateway of an engine that can't be bound; model_armor_on with no Model Armor extension in the
  // region and none staged; a kind the caller can't write (apply mode, /auth writable); set_enforcement /
  // dedicate_extension on a gateway with no IAP REQUEST_AUTHZ policy; set_enforcement to the mode the extension is
  // already in (fix "already"); dedicate_extension to a name that exists, or whose policy targets other gateways too;
  // modify whose access equals access_from (fix "already"), or whose access_from binding isn't in the current
  // inventory ("The grant changed since you looked; Sync and try again").

DiffItem = { intent_id, status: "add"|"present"|"replace"|"remove"|"absent", detail, error? /* invalid intent */,
             current: Binding[] | null /* the member's roles/iap.egressor bindings on the resource today */,
             after:   Binding[] | null /* the same after the change; null for gateway / Model Armor intents */ }
  // "replace": the member already has a different condition. IAM ORs bindings, so after = current + the new one;
  // revoke the old binding to really replace it (or stage a modify).
  // modify: "replace" (detail "full access → only read-only tools"; after = the member's other bindings + the new
  // one), "present" (same access, or already changed: the new binding is there and the old one isn't), "absent"
  // (the binding matching access_from isn't there: it changed since it was read).
  // set_enforcement: "replace" (mode changes; detail "gw: Dry run → Enforce", plus shared gateways), "present" (same
  // mode), with current_mode / target_mode. dedicate_extension: "add" / "present"; revert: "remove" / "absent".

GatewayLogs = { gateway, since /* RFC 3339 */, filter, console_url, notes: [str], errors: [str],
                truncated /* some entries of the window aren't in entries (see notes for which) */,
                checked_truncated /* dry run: even the platform-free second query hit its cap (1000), so older
                                     would-be-denied calls may be missing; false when not dry run */,
                dry_run /* egress gateway in dry run: allowed entries were checked against the grants */,
                counts: {allowed, denied, would_deny, unknown, platform},
                entries: [{ decision: "allowed"|"denied"|"would_deny"|"unknown"|"platform", status, host, mcp_tool,
                            mcp_method,
                            registry_resource, destination, policies: [{name, result}], authz_result, timestamp,
                            method, url, insert_id, console_url /* this entry in Cloud Logging */,
                            client_cert /* jsonPayload.mtls.clientCertSha256Fingerprint */,
                            caller: {engine, display_name, how: "mtls"|"only_bound_agent"} | null,
                            agent /* = caller.display_name (inferred: logs don't name the caller) */,
                            agent_inferred, computed /* decision computed from the grants */,
                            platform /* the agent runtime's own traffic, by host (below) */,
                            reason /* why would_deny / allowed / unknown / platform, when computed */ }] }
  // filter: logName="projects/P/logs/networkservices.googleapis.com%2Fgateway_requests"
  //         AND resource.labels.gateway_name="GATEWAY" AND timestamp>="SINCE"   (since: 24h, 30m, 7d or RFC 3339)
  // Live format (enforcing gateway): jsonPayload.authzPolicyInfo {result ALLOWED|DENIED, policies[{name, result}]},
  // jsonPayload.agentGatewayInfo {agentRegistryResource, mcpInfo {method "tools/call", parameter TOOL}},
  // httpRequest.status 403 on an IAP denial, jsonPayload.mtls.clientCertSha256Fingerprint. Logged decision: denied =
  // a DENIED result or status 403, else allowed.
  // Dry run (seen live): calls IAP would deny are logged exactly like allowed ones (status 200, result ALLOWED, every
  // policy ALLOWED, matchedRules default_denied in every mode), so would_deny is NOT reported by Google. On an egress
  // gateway whose IAP extension is in DRY_RUN, each allowed entry is computed (computed: true) from current grants:
  //   caller   the fingerprint matched to an engine by a second entries:list over the bound engines' own platform
  //            calls (httpRequest.requestUrl:"reasoningEngines/ID/", from 2 h before `since`; only when more than one
  //            agent is bound), else the only bound agent, else unknown.
  //   grants   roles/iap.egressor on the destination (agentRegistryResource) and registry-wide, matching the caller's
  //            principal, its project's "all agents" principalSet, allUsers / allAuthenticatedUsers. Conditions:
  //            toolName in [...] and the read-only-hint form are evaluated (the tool from mcpInfo.parameter on
  //            tools/call, '' otherwise); other conditions, tools missing from the inventory, group / domain members,
  //            unreadable IAP policies and destinations outside the inventory give "unknown", never would_deny.
  //            Project-level (and higher) grants aren't read.
  // Platform traffic (seen live): much of an egress gateway's log is the agent runtime's own calls, e.g. to
  //   <region>-aiplatform.mtls.googleapis.com (registered in Agent Registry as an endpoint, so it has an
  //   agentRegistryResource) and to 240.0.0.2:443 (an internal platform address, none). platform: true when the
  //   host is an IP literal (240.0.0.0/4 is the platform's range), *.google.internal or aiplatform*.googleapis.com,
  //   or, with no agentRegistryResource, any *.googleapis.com host. Decision "platform" (dry run, computed: true) =
  //   a platform entry with no agentRegistryResource: no grant names it, so it isn't checked, and it isn't "unknown".
  //   Registered platform hosts (the aiplatform endpoint) are checked like any destination (usually "allowed"
  //   through a project-wide grant) and keep platform: true, so the UI can group them. "platform" is only computed in
  //   dry run; on an enforcing gateway entries stay allowed / denied (as logged) with the flag.
  // Window coverage (dry run): when the newest `limit` entries don't cover the window (often: mostly platform
  //   calls), a second entries:list adds the window's other entries, newest first, up to 1000 (at most 10 pages):
  //     <filter> AND NOT jsonPayload.enforcedGatewaySecurityPolicy.hostname=~"^([a-z0-9-]*aiplatform[a-z0-9.-]*[.]
  //     googleapis[.]com|[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)(:[0-9]+)?$"            (one line; verified live)
  //   merged by insertId, so entries can exceed `limit`. truncated stays true (older platform calls were left out);
  //   checked_truncated says whether the non-platform entries were capped too. notes say which entries were left out.
  // Needs logging.logEntries.list (roles/logging.viewer).
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

`confirm.project` must equal `context.project`. Revokes, unbinds, `model_armor_off`, setup deletes (`params.delete`), `set_enforcement` to `DRY_RUN` and `dedicate_extension` with `revert` need `acknowledge_destructive: true`.

The response streams NDJSON or SSE events per intent: `{intent_id, state: "running"|"done"|"verified"|"failed"|"skipped", detail, operation?, undo?: Intent, raw_error?, blocked?, fix?}`, then `{type: "done", summary}` (`summary.blocked` counts preflight refusals).

Before any call, duplicates are `skipped` and the `/preflight` blockers `failed` with `blocked: true`. Known Google Cloud errors get a plain-English `detail` (e.g. the AGENT_IDENTITY 400 on a bind) with the original in `raw_error`.

Each intent is applied, then read back and verified:
- **IAP grant/revoke:** getIamPolicy → modify → setIamPolicy with the etag, version 3, and the condition preserved; read back and confirm the binding is there (or gone).
- **modify:** one getIamPolicy → remove the member from the binding matching `access_from` exactly (by expression, whitespace-insensitive) → add the binding for `access` (unless it's already there) → one setIamPolicy with the etag (version 3, other bindings untouched; an etag conflict retries from a fresh read) → read back: the new binding is there and the old one is gone. `access_from` not found: `failed` ("The grant changed since you looked"), or `skipped` when the new binding is already there. Undo: the reverse modify (`access_from` = the new condition verbatim, `access` = the removed one verbatim).
- **bind/unbind gateway:** an engine PATCH that keeps the other direction, one PATCH per engine at a time. It's a long-running operation; the result reports the operation, and a later read-back confirms `agentGatewayConfig`.
- **model_armor_on/off:** create or delete the `CONTENT_AUTHZ` authz policy (long-running operation, about 4 min).
- **model_armor_template:** create (or delete) the template on `modelarmor.<R>.rep.googleapis.com`; read back.
- **model_armor_extension:** create (or delete) the authz extension (long-running; waited for, so a `model_armor_on` in the same request can use it); read back that it names the template.
- **set_enforcement:** GET the extension (must be `iap.googleapis.com`; skipped if already in the mode) → PATCH `?updateMask=metadata,failOpen` with the live metadata (only `iamEnforcementMode` added or removed) → wait for the operation → read back mode and failOpen. Undo: the previous mode.
- **dedicate_extension:** GET the source extension and the gateway's REQUEST_AUTHZ policy (must use the source and target only this gateway) → create the copy (waited for) → PATCH the policy `?updateMask=customProvider.authzExtension.resources` (waited for) → read back. Runs before other kinds, so a `set_enforcement` of the copy in the same request finds it (and is skipped if the copy failed). Undo: `revert` (PATCH back, delete the copy unless another policy uses it). The policy PATCH uses `?updateMask=customProvider.authzExtension.resources,labels` with the current labels re-sent (a PATCH without labels in the mask clears them), and the read-back checks the labels are unchanged. A `set_enforcement` of the copy a dedicate created in the same request gets no undo of its own (the revert deletes the copy); and a `set_enforcement` of a copy that a revert in the same request deletes is skipped (it still runs when the copy is kept because another policy uses it). The writer allows only these two PATCH masks, with bodies limited to those fields.
- **iam_project_grant:** project getIamPolicy → add (or remove) the member in the Model Armor roles only → setIamPolicy with the etag (retried on a conflict); read back. The writer refuses any other change to the project policy.

Every applied intent returns its inverse in `undo`, which the UI keeps as an "Undo last apply" list. An apply log is appended to `~/.policy-studio/apply-log.jsonl` (locally).
