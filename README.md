# Policy Studio

A guided tool for Gemini Enterprise Agent Gateway: discover what's in a project and region (gateways, authz
policies, Model Armor, Agent Registry entries, Agent Runtime agents, IAP grants), audit it in plain English, build
policies (agent → A2A agent / MCP server / API endpoint, with MCP tool conditions), and generate Terraform, gcloud,
REST (curl) and Python for them.

Discovery, audit and code generation are read-only. Applying changes (P3) is possible only in **apply mode**, which
is the default when you run it locally; on Cloud Run it runs in **generate mode** and has no write path at all (see
[Modes](#modes-generate-and-apply)). Plan: [docs/PLAN.md](docs/PLAN.md). API contract: [docs/API.md](docs/API.md).

Policy Studio started as a companion to the [Agent Gateway & Agent Registry demo](https://github.com/mlaslie/agent-gateway-demo) and is fully standalone: the backend package `policy_studio` has no dependency on the demo (a test enforces it).

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
- Every write goes through `gcp/writer.py`, which allows exactly four calls: IAP `setIamPolicy` on Agent Registry
  resources, the engine `PATCH` of `agentGatewayConfig`, and create/delete of authz policies.
- Grants and revokes are read-modify-write with the policy etag and version 3 (retried up to 3 times on an etag
  conflict). Other bindings are untouched; a revoke removes only the member from the binding with that role and
  condition.
- Engine binds read the engine first and keep the other direction; changes to one engine run one at a time. Binds and
  Model Armor are long-running operations: the stream reports the operation, polls it (up to 10 minutes) and reads the
  result back.
- Each change is applied exactly as the generated commands would do it (same specs as the code generator), read back,
  and returned with its inverse (`undo`). Results are appended to `~/.policy-studio/apply-log.jsonl`
  (`STUDIO_APPLY_LOG` overrides the path).

## Permissions

Read access: the Context step lists what your credentials can read (`testIamPermissions`) with the role and the
command to grant it. Reading needs roughly: `roles/browser`, `roles/serviceusage.serviceUsageViewer`, `roles/networkservices.viewer`,
`roles/networksecurity.viewer`, `roles/aiplatform.viewer`, `roles/agentregistry.viewer`, `roles/modelarmor.viewer`
and an IAP role that can read IAM policies (`roles/iap.admin` includes it).

Apply additionally needs `roles/iap.admin` (grants / revokes, on the Agent Registry project), `roles/aiplatform.user`
(gateway binds) and `roles/networksecurity.editor` (Model Armor on/off); the **Can write** check names what's missing.

## Generated code

- Terraform targets `hashicorp/google >= 8.1.0`; the bundle passes `terraform fmt -check` and `terraform validate`
  (`STUDIO_TF_VALIDATE=1 pytest …` runs validate too). Engine gateway bindings have no Terraform resource, so they
  use `terraform_data` + `local-exec` (PATCH), with the `google_vertex_ai_reasoning_engine` alternative commented.
- gcloud: `gcloud iap web add-/remove-iam-policy-binding --resource-type=agent-registry` with `--condition` (custom
  delimiter, since conditions contain commas and `||`) or `--condition-from-file`; Model Armor via
  `gcloud network-security authz-policies import/delete`. There is no gcloud command to bind an engine to a gateway,
  so that tab shows the curl PATCH.
- Python uses `google-cloud-iap` and `google-cloud-network-security`, and `AuthorizedSession` for the engine PATCH.
