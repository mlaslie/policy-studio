# Policy Studio

Policy Studio is a tool designed to help Google Cloud Agent Platform administrators more easily audit agentic endpoints (A2A agents, MCP servers and API endpoints) within Agent Registry, and understand which agents have Agent Gateway policy enforced and what that enforced policy is.

In addition to auditing Agent Registry and Agent Gateway, Policy Studio also helps administrators construct and apply new policies through an intuitive graphical interface. When Policy Studio runs locally with Application Default Credentials (ADC), the policies you create can be applied directly. Or you can apply them yourself using the generated Terraform, API calls, Python or gcloud commands.

Finally, Policy Studio is also meant to be a learning tool: it helps administrators understand the various policy components involved and what each one does.

The setup instructions below cover both a local installation and a centralized Cloud Run service. When deployed to Cloud Run, auditing and command generation are available but applying policy is not. To have Policy Studio apply policy directly, install it locally, so that every policy change can be audited back to a named user.

See [Modes](#modes-generate-and-apply) for how the two modes differ, and [docs/API.md](docs/API.md) for the API contract.

> **Note:** Policy Studio is very green, so if you find a bug, please [report it](https://github.com/mlaslie/policy-studio/issues).

```
./
  backend/policy_studio/   FastAPI app (api.py router at /api/studio, app.py = router + static UI)
    gcp/                   read-only REST: discovery, gateways, engines, registry (+ IAP IAM), model_armor;
                           auth.py (credential checks); writer.py (the only write path, apply mode only)
    settings.py apply.py   run mode (generate | apply); Apply with read-back, undo and an apply log
    render.py hcl.py       Intent -> Terraform / gcloud / REST / Python (+ anatomy, English, warnings, bundle)
    audit.py diff.py       findings with suggested fixes; staged intents vs current IAM
  backend/tests/           pytest (GCP faked; no network)
  frontend/                Vite + React UI
  Dockerfile deploy.sh     Cloud Run image / deployment behind IAP
```

## Run locally

Credentials: Application Default Credentials (`gcloud auth application-default login`). Defaults for the Context
step come from `STUDIO_PROJECT` / `STUDIO_REGION`, or your gcloud config.

With [uv](https://docs.astral.sh/uv/) and Node 20+:

```bash
cd frontend && npm install && npm run build && cd ..   # build the UI once
./studio-app                                           # API + UI on http://localhost:8090
cd frontend && npm run dev                             # UI development on :5174 (proxies /api to :8090)
uv run --project backend pytest backend/tests -q       # tests (GCP is faked; no network)
```

With plain pip:

```bash
pip install ./backend
uvicorn policy_studio.app:app --port 8090        # STUDIO_FRONTEND_DIST=<dir> to serve a built UI
pip install pytest && pytest backend/tests -q
```

Embed the API in another FastAPI app: `app.include_router(policy_studio.api.router)`.

## Modes: generate and apply

| Mode | When | Apply |
|---|---|---|
| `generate` | Default on Cloud Run (`K_SERVICE` set), or `STUDIO_MODE=generate` | Off. The write client is never constructed; `POST /api/studio/apply` returns 403. |
| `apply` | Default locally, or `STUDIO_MODE=apply` | On, with your Application Default Credentials, once the credential checks pass and you confirm. |

`STUDIO_MODE=apply` on Cloud Run is refused (logged, falls back to generate) unless
`STUDIO_ALLOW_APPLY_ON_CLOUD_RUN=1` is also set. `deploy.sh` sets `STUDIO_MODE=generate` explicitly.

### Credentials (ADC)

Apply calls Google APIs with Application Default Credentials, which are separate from your gcloud CLI login:

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <target-project>   # avoids quota/billing surprises
gcloud config set project <target-project>                            # optional: keeps gcloud on the same project
```

`GET /api/studio/auth?project=<target>` (the Context step shows it) reports, without changing anything: the ADC type
(user, service account, impersonated, external account, metadata server), its account, quota project, project and
source file; gcloud's account and project when the CLI is installed; and these checks, each with a copyable fix:

- **ADC present / valid**: the credentials exist and the token refreshes (error otherwise).
- **Account**: warns when ADC and gcloud are logged in as different accounts (changes are made as the ADC account).
- **Quota project**: warns when user ADC has none or a different one than the target.
- **Project**: warns when your ADC/gcloud default project isn't the target (Apply always names the target explicitly).
- **Can write**: `testIamPermissions` for each kind of change (IAP `setIamPolicy` for grants,
  `aiplatform.reasoningEngines.update` for gateway binds, `networksecurity.authzPolicies.create/delete` for Model
  Armor). Error when nothing is writable, warning when only some kinds are.

Apply is available when the mode is `apply` and no check is an error.

### Apply safety

- The request must repeat the project (`confirm.project == context.project`); revokes, unbinds and Model Armor off
  also need `confirm.acknowledge_destructive`.
- Every write goes through `gcp/writer.py`, which allows only: IAP `setIamPolicy` on Agent Registry resources, the
  engine `PATCH` of `agentGatewayConfig`, create/delete of authz policies, and for Model Armor setup create/delete of
  Model Armor templates and authz extensions plus project `setIamPolicy`, which is checked so that it can only add or
  remove members of the three Model Armor roles (anything else in the policy must be unchanged).
- Before any call, Apply skips duplicate items and refuses items that would certainly fail (a bind of an engine
  without Agent Identity, Model Armor on with no extension in the region and none staged, a kind you can't write);
  the Apply step runs the same preflight (`POST /api/studio/preflight`) and shows them as **Blocked** with a fix.
  Known Google Cloud errors are shown in plain English with the raw error alongside.
- Grants and revokes are read-modify-write with the policy etag and version 3 (retried up to 3 times on an etag
  conflict). Other bindings are untouched; a revoke removes only the member from the binding with that role and
  condition.
- Engine binds read the engine first and keep the other direction; changes to one engine run one at a time. Binds and
  Model Armor are long-running operations: the stream reports the operation, polls it (up to 10 minutes) and reads the
  result back.
- Each change is applied exactly as the generated commands would do it (same specs as the code generator), read back,
  and returned with its inverse (`undo`). Results are appended to `~/.policy-studio/apply-log.jsonl`
  (`STUDIO_APPLY_LOG` overrides the path).

## Model Armor

Model Armor on a gateway is a `CONTENT_AUTHZ` authz policy that points at a Model Armor authz extension. It needs, in
the gateway's region:

1. a Model Armor **template** (the filters: prompt injection & jailbreak, sensitive data, responsible AI, malicious
   URLs, and the message people see when blocked);
2. a Model Armor **authz extension** (`service: modelarmor.<region>.rep.googleapis.com`, `failOpen: false`,
   `metadata.model_armor_settings` naming the template for requests and responses);
3. **permissions** for each gateway's service agent on the template's project: `roles/modelarmor.calloutUser`,
   `roles/modelarmor.user` and `roles/serviceusage.serviceUsageConsumer`. The identity is the gateway resource's
   `agentGatewayCard.serviceExtensionsServiceAccount`; ingress gateways also use
   `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com` (verified in one project; check yours);
4. then **Model Armor on** for the gateway.

`GET /api/studio/model-armor` reports what's there in `setup` (templates, extensions, each service agent with ✓/✗ per
role from the project IAM policy, and suggested names). When something is missing, the Model Armor step shows
**"Model Armor isn't set up in <region> yet"** with a guided four-step setup (pick or create a template with friendly
controls, name the extension, grant only the missing roles, pick the gateways). "Stage all steps" adds them to the
cart in order; Review renders them as Terraform (`google_model_armor_template`,
`google_network_services_authz_extension`, `google_project_iam_member`, with `depends_on` into the policy), gcloud
(`gcloud model-armor templates create` with its regional endpoint override, `gcloud service-extensions
authz-extensions import`, `gcloud projects add-iam-policy-binding`), REST and Python. Wherever Model Armor on would
otherwise use the `MODEL_ARMOR_EXTENSION` placeholder, a **"Set up Model Armor in this region →"** button opens the
setup. In apply mode each step is applied, read back, and undoable (delete template / delete extension / remove the
roles). Model Armor egress screening covers MCP traffic, not A2A.

## Permissions

Read access: the Context step lists what your credentials can read (`testIamPermissions`) with the role and the
command to grant it. Reading needs roughly: `roles/browser`, `roles/serviceusage.serviceUsageViewer`, `roles/networkservices.viewer`,
`roles/networksecurity.viewer`, `roles/aiplatform.viewer`, `roles/agentregistry.viewer`, `roles/modelarmor.viewer`
and an IAP role that can read IAM policies (`roles/iap.admin` includes it).

Apply additionally needs `roles/iap.admin` (grants / revokes, on the Agent Registry project), `roles/aiplatform.user`
(gateway binds) and `roles/networksecurity.editor` (Model Armor on/off); Model Armor setup also needs
`roles/modelarmor.admin` (templates), `roles/networkservices.admin` (authz extensions) and
`roles/resourcemanager.projectIamAdmin` (service agent roles). The **Can write** check names what's missing. Reading
the service agents' roles uses `resourcemanager.projects.getIamPolicy` (`roles/browser`).

## Generated code

- Terraform targets `hashicorp/google >= 8.1.0`; the bundle passes `terraform fmt -check` and `terraform validate`
  (`STUDIO_TF_VALIDATE=1 pytest …` runs validate too). Engine gateway bindings have no Terraform resource, so they
  use `terraform_data` + `local-exec` (PATCH), with the `google_vertex_ai_reasoning_engine` alternative commented.
- gcloud: `gcloud iap web add-/remove-iam-policy-binding --resource-type=agent-registry` with `--condition` (custom
  delimiter, since conditions contain commas and `||`) or `--condition-from-file`; Model Armor via
  `gcloud network-security authz-policies import/delete`. There is no gcloud command to bind an engine to a gateway,
  so that tab shows the curl PATCH.
- Python uses `google-cloud-iap` and `google-cloud-network-security`, and `AuthorizedSession` for the engine PATCH.
