# P0 findings: private networking live spike

Status: **done, torn down** (see [Cleanup](#cleanup)). Run on 2026-10-15, 14:06–15:28 UTC, in the shared test project, in **us-west1** (not a demo region), with throwaway resources prefixed `pnt-` and labelled `app=pnt-spike`. Plan: [PRIVATE_NETWORKING_PLAN.md](PRIVATE_NETWORKING_PLAN.md) §10 P0.

Placeholders: project `acme-prod` (number `123456789012`), org `000000000000`, VPC `pnt-vpc`, region `us-west1`. Engine IDs, tenant project numbers and Cloud Run hashes are replaced with `<ENGINE>`, `<TENANT>`, `<hash>`.

Tooling: plain `gcloud` + REST (curl / Python `urllib`) + the `vertexai` 2.4.0 SDK for engine creation. The probe agent is a minimal ADK `LlmAgent` whose `before_model_callback` never calls a model: `__FETCH__ {"urls":[...]}` does an HTTPS GET of each URL from inside the runtime and returns status, body snippet, DNS resolution and proxy env vars; any other message is echoed (`ECHO: ...`).

---

## 0. Summary

| Test | Question | Answer |
|---|---|---|
| T1 | Egress gateway with a connectivity template reaches an `internal` Cloud Run service through a PSC endpoint for Google APIs (`run.app` override)? | **Yes.** Denied (403) without `roles/iap.egressor`, allowed (200) about 2 min after the grant. The gateway log shows the upstream IP is the PSC endpoint (`serverIp 10.x.x.x:443`); an unbound engine gets 404 from the same service. Required an extra env var on the engine (see T1.4). |
| T2 | Can a template be attached to an existing gateway by PATCH? | **Bare → template: no** (LRO `code 13 INTERNAL`, reproducible, and it drops the gateway's labels). **Bare → inline `networkConfig`: yes** (3.5 min). **Inline → template: yes** (mask `agentConnectivityTemplate,networkConfig`, 2m49s). **Template → template swap: yes** (11 s). Referenced templates can't be modified (except `description`) or deleted. |
| T3 | Does a VPC client calling `:streamQuery` over Private Google Access or a PSC endpoint for Google APIs go through the ingress gateway? | **Yes, it can:** Model Armor on the `CLIENT_TO_AGENT` gateway blocked the injection over PGA, over the PSC endpoint, and over a narrow or full `googleapis.com` DNS override. **But enforcement was inconsistent:** only ~50–70% of identical requests to the bound engine were screened, ~15–30% of requests to an **unbound** engine in the same project+region were screened too (20+ min after binding), and screening lingered ~12 min after every engine was unbound. |
| T4 | Agent Runtime PSC-I together with an egress gateway binding? | **Create: rejected** (`400 ... psc_interface_config and agent_gateway_config cannot be both set`). **PATCH of a gateway onto a PSC-I engine: accepted** (4 min), but the engine then can't reach Google APIs at all (TLS handshake timeouts, no gateway log entries). A PSC-I-only engine reaches private destinations **ungoverned** (no registry, no IAP). |
| T5 | VPC-SC feasibility (read only) | The account holds org-level Access Context Manager permissions (list/get **and** create/update). Listing policies needs the Access Context Manager API enabled on a quota project; it isn't, and wasn't enabled. Nothing created. |

---

## 1. Setup (shared by all tests)

All in `acme-prod`, region `us-west1`, created in about 4 minutes:

```bash
gcloud compute networks create pnt-vpc --subnet-mode=custom
gcloud compute networks subnets create pnt-att    --network pnt-vpc --region us-west1 --range 10.70.0.0/28 --enable-private-ip-google-access
gcloud compute networks subnets create pnt-client --network pnt-vpc --region us-west1 --range 10.70.1.0/28 --enable-private-ip-google-access
gcloud compute networks subnets create pnt-psci   --network pnt-vpc --region us-west1 --range 10.70.2.0/28 --enable-private-ip-google-access
gcloud compute network-attachments create pnt-att      --region us-west1 --subnets pnt-att  --connection-preference ACCEPT_AUTOMATIC
gcloud compute network-attachments create pnt-att-psci --region us-west1 --subnets pnt-psci --connection-preference ACCEPT_AUTOMATIC
gcloud compute firewall-rules create pnt-allow-iap-ssh  --network pnt-vpc --allow tcp:22 --source-ranges 35.235.240.0/20
gcloud compute firewall-rules create pnt-allow-internal --network pnt-vpc --allow tcp,udp,icmp --source-ranges 10.70.0.0/16
# PSC endpoint for Google APIs. The forwarding rule name must be 1-20 lowercase letters/digits: no hyphen, so no "pnt-" prefix.
gcloud compute addresses create pnt-psc-ip --global --purpose PRIVATE_SERVICE_CONNECT --addresses 10.70.250.10 --network pnt-vpc
gcloud compute forwarding-rules create pntpsc --global --network pnt-vpc --address pnt-psc-ip --target-google-apis-bundle all-apis
# run.app override
gcloud dns managed-zones create pnt-run-app --dns-name run.app. --visibility private --networks pnt-vpc
gcloud dns record-sets create run.app.   --zone pnt-run-app --type A --ttl 60 --rrdatas 10.70.250.10
gcloud dns record-sets create '*.run.app.' --zone pnt-run-app --type A --ttl 60 --rrdatas 10.70.250.10
```

Service agent roles added (attachment and DNS in the gateway project itself):

```bash
gcloud projects add-iam-policy-binding acme-prod --member serviceAccount:service-123456789012@gcp-sa-agentgateway.iam.gserviceaccount.com --role roles/compute.networkAdmin
gcloud projects add-iam-policy-binding acme-prod --member serviceAccount:service-123456789012@gcp-sa-agentgateway.iam.gserviceaccount.com --role roles/dns.peer
gcloud projects add-iam-policy-binding acme-prod --member serviceAccount:service-123456789012@gcp-sa-aiplatform.iam.gserviceaccount.com   --role roles/dns.peer   # T4 PSC-I DNS peering
```

The `gcp-sa-agentgateway` agent already existed with `roles/agentgateway.serviceAgent`. The `gcp-sa-aiplatform` agent already had `roles/compute.networkAdmin` from an earlier PSC-I engine.

Destination: `gcloud run deploy pnt-hello --image us-docker.pkg.dev/cloudrun/container/hello --ingress internal --allow-unauthenticated`. It has two URLs, `https://pnt-hello-123456789012.us-west1.run.app` and `https://pnt-hello-<hash>-uw.a.run.app`. From the internet both return **404**.

---

## 2. T1: egress through a connectivity template to private Cloud Run

### 2.1 API shapes that worked

Template (LRO done in under 1 s):

```http
POST https://networkservices.googleapis.com/v1/projects/acme-prod/locations/us-west1/agentConnectivityTemplates?agentConnectivityTemplateId=pnt-tmpl
{
  "accessPath": "AGENT_TO_ANYWHERE",
  "deploymentModel": "CENTRALIZED",
  "labels": {"app": "pnt-spike"},
  "egressNetworkConfig": {
    "networkAttachment": "projects/acme-prod/regions/us-west1/networkAttachments/pnt-att",
    "dnsPeeringConfig": {"domains": ["run.app."], "targetNetwork": "projects/acme-prod/global/networks/pnt-vpc"},
    "vpcEgress": "PRIVATE_RANGES_ONLY"
  }
}
```

Gateway (LRO **3m39s**):

```http
POST https://networkservices.googleapis.com/v1/projects/acme-prod/locations/us-west1/agentGateways?agentGatewayId=pnt-egress
{
  "googleManaged": {"governedAccessPath": "AGENT_TO_ANYWHERE"},
  "registries": ["//agentregistry.googleapis.com/projects/acme-prod/locations/us-west1"],
  "agentConnectivityTemplate": "projects/123456789012/locations/us-west1/agentConnectivityTemplates/pnt-tmpl",
  "labels": {"app": "pnt-spike"}
}
```

**The template reference must use the project number.** With the project ID the create fails immediately:

> `400 INVALID_ARGUMENT "Config validation failed" field resource.agent_connectivity_template: invalid agent connectivity template format: incorrect resource name: got "//networkservices.googleapis.com/projects/acme-prod/...", want "//<service name URI>/projects/<project number>/locations/<location ID>/agentConnectivityTemplates/<resource ID>"`

The template body, on the other hand, takes the attachment and `targetNetwork` by project **ID** (with a number, validation fails; see T2.3).

After creation:
- the gateway GET shows `agentConnectivityTemplate` (the number form) and no `networkConfig`;
- the attachment shows one consumer: `connectionEndpoints[{projectIdOrNum: <TENANT>, ipAddress: 10.70.0.2, status: ACCEPTED}]`;
- `<TENANT>` is **the same number as in the gateway's `agentGatewayCard.serviceExtensionsServiceAccount`** (`service-<TENANT>@gcp-sa-dep...`). That's how discovery can map an attachment consumer to a gateway.

Authorization (as in the demo):
- an IAP `authzExtension` (`iap.googleapis.com`, `failOpen: false`, `metadata.iapPolicyVersion: V1`, i.e. enforce);
- a `REQUEST_AUTHZ` `authzPolicy` targeting `pnt-egress`.

Registry, in the us-west1 registry:
- 25 platform endpoints (the demo's list for us-west1, plus `storage` and `oauth2`), with `roles/iap.egressor` for the project's Agent Identity principalSet;
- the destination as **one service with both hostname variants**:

```json
{"displayName": "pnt-hello", "endpointSpec": {"type": "NO_SPEC"},
 "interfaces": [{"url": "https://pnt-hello-123456789012.us-west1.run.app", "protocolBinding": "HTTP_JSON"},
                {"url": "https://pnt-hello-<hash>-uw.a.run.app",           "protocolBinding": "HTTP_JSON"}]}
```

Agent: `client.agent_engines.create(agent=AdkApp(...), config={"identity_type": "AGENT_IDENTITY", "agent_gateway_config": {"agent_to_anywhere_config": {"agent_gateway": "projects/acme-prod/locations/us-west1/agentGateways/pnt-egress"}}, "env_vars": {"GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES": "false"}, ...})`. Creation took about 4.5–7 min.

### 2.2 Results

| Case | Result |
|---|---|
| Unbound control engine → both run.app URLs | **404** (public path; Cloud Run `internal` rejects). Names resolve to public Google IPs |
| Bound engine, **no** egressor on `pnt-hello` | **403** `Egress request is not authorized.` Gateway log: `authzPolicyInfo.result: DENIED`, `agentRegistryResource` = the pnt-hello endpoint |
| Bound engine, unregistered `https://example.com` | **403** `Egress request is not authorized. The endpoint is either incorrect or unregistered in the Agent Registry. Only registered endpoints are allowed.` |
| Bound engine, egressor granted to `principal://agents.global.org-000000000000.system.id.goog/resources/aiplatform/projects/123456789012/locations/us-west1/reasoningEngines/<ENGINE>` | **200** for both URL variants, **1m53s** after the grant |

### 2.3 Proof of the private path

- The gateway log entry for the allowed call (`networkservices.googleapis.com/gateway_requests`) has `httpRequest.serverIp: "10.70.250.10:443"`, which is the PSC endpoint for Google APIs inside `pnt-vpc`. It also has `requestWasTlsIntercepted: true`, SNI = the run.app host, and authz ALLOWED. Denied entries have no `serverIp`.
- The same gateway's calls to Google APIs (`us-west1-aiplatform.mtls`, `telemetry.mtls`) show **public** `serverIp`s (`74.125.x.95` and so on). With `PRIVATE_RANGES_ONLY`, only names that DNS peering resolves to private IPs go into the VPC.
- Cloud Run accepted the request with `ingress=internal` (200), while the unbound engine got 404. Cloud Run's request log shows `remoteIp 0.0.0.0` for both the gateway's and the VM's PSC-endpoint calls. So Cloud Run doesn't show the attachment IP (`10.70.0.2`), and its log can't tell these paths apart.
- Inside the runtime of a bound engine, every hostname resolves to **`240.0.0.2`** (plus public IPv6), and there are no proxy env vars. The gateway intercepts transparently.

**Conclusion:** the plan's chosen pattern works end to end with no ILB and no custom domain. Cloud Run `internal` admits traffic from the gateway's PSC interface when it arrives through a PSC endpoint for Google APIs in a VPC of the same project. F30's worry doesn't apply to this pattern.

### 2.4 Required env var (new gotcha)

The first engine, created with the gateway binding and **without** the env var, failed every request:
- session creation got `401 UNAUTHENTICATED Request had invalid authentication credentials`;
- the gateway authorized each call (ALLOWED), and upstream Google APIs (`iamcredentials.mtls`, `us-west1-aiplatform.mtls`) returned 401.

It was still failing 9 minutes later. An identical engine created with `GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES=false` worked on the first call. The demo's engines (bound later by PATCH, through gateways without a template, in another region) don't need it. **Cause (found later):** a known google-auth bug, which Google is fixing. The preferred fix is pinning `google-auth==2.60.0` in the agent's requirements, which keeps Context-Aware Access token binding; the env var also works but opts out of token binding, which Google strongly discourages.

---

## 3. T2: attaching a template to an existing gateway

Gateways used: `pnt-egress-bare` and `pnt-egress-bare2`, both `AGENT_TO_ANYWHERE` with the registry and no networking (create took about 2m15s). Templates `pnt-tmpl-b` and `pnt-tmpl-c` use the same attachment. T1's gateway was never touched.

| # | Call | Result | Time |
|---|---|---|---|
| 1 | `PATCH agentGateways/BARE?updateMask=agentConnectivityTemplate` `{"agentConnectivityTemplate": "projects/123456789012/.../pnt-tmpl-b"}` | HTTP 200, then LRO **`{code: 13, message: "an internal error has occurred"}`** | 8 s |
| 1b | Same on a second, fresh bare gateway; also with masks `agentConnectivityTemplate,networkConfig` and `agentConnectivityTemplate,labels` | Same **code 13** every time (4 attempts) | 11 s each |
| 2 | `PATCH ...?updateMask=networkConfig` `{"networkConfig": {"egress": {"networkAttachment": "projects/acme-prod/regions/us-west1/networkAttachments/pnt-att"}, "dnsPeeringConfig": {"domains": ["run.app."], "targetProject": "acme-prod", "targetNetwork": "projects/acme-prod/global/networks/pnt-vpc"}}}` | **Success** (inline model added to a bare gateway) | **3m33s** |
| 3 | On that inline gateway: `PATCH ?updateMask=agentConnectivityTemplate` | **400** `Config validation failed` field `resource.network_config`: `network_config cannot be set when agent_connectivity_template is set` | sync |
| 4 | `PATCH ?updateMask=agentConnectivityTemplate,networkConfig` `{"agentConnectivityTemplate": ".../pnt-tmpl-b"}` (networkConfig omitted, so cleared) | **Success**: template set, `networkConfig` null, labels kept | **2m49s** |
| 5 | Template swap on a gateway that already has one: `PATCH ?updateMask=agentConnectivityTemplate` (`pnt-tmpl-b` → `pnt-tmpl-c`) | **Success** | **11 s** |
| 6 | `PATCH agentConnectivityTemplates/pnt-tmpl-b?updateMask=egressNetworkConfig.vpcEgress` while a gateway references it | LRO **`{code: 9, "Precondition failed: cannot update agent connectivity template that is referenced by an agent gateway"}`**, `PreconditionFailure` violation `type: AgentGatewayReference`, `subject: //networkservices.googleapis.com/projects/123456789012/locations/us-west1/agentGateways/<gw>` | 1 s |
| 7 | `PATCH ...?updateMask=description` on the referenced template | **Success** | 1 s |
| 8 | `DELETE` of the referenced template | **400 FAILED_PRECONDITION** `Resource '...agentConnectivityTemplates/pnt-tmpl-b' is already being used by resource(s) '//networkservices.googleapis.com/projects/123456789012/.../agentGateways/<gw>'` | sync |

**Side effect bug:** after each failed bare → template PATCH (code 13), the gateway's **`labels` were gone** on GET. On the first gateway, they came back after the next successful PATCH; on `pnt-egress-bare2`, they stayed gone.

Template create **does** validate. Both of these failed and created nothing:
- `targetNetwork` with the project number: `code 3 Config validation failed .egress_network_config.network_attachment: subnet ... of network attachment ... is in network "projects/acme-prod/global/networks/pnt-vpc", not target network "projects/123456789012/global/networks/pnt-vpc"`;
- an attachment in **us-west2** for a us-west1 template: LRO `code 13 "an internal error has occurred"`. That's an opaque error, but the attachment region must match.

The "every agent in a project+region binds the same egress gateway" rule is enforced at bind time. Binding an engine to a second egress gateway while one is in use returned:

> `400 INVALID_ARGUMENT "Another Agent Gateway is already active or being created for this project and direction."`

**Conclusion:**
- An existing gateway **can** get private egress in place, without delete and recreate and without rebinding engines:
  - bare → `networkConfig` (inline) → template, 2 PATCHes, about 6.5 min in total;
  - or template → template, one PATCH, seconds.
- The direct bare → template PATCH fails today with INTERNAL. Treat it as a bug and use the two-step path.
- These PATCHes ran on gateways with **no bound engines**. Whether traffic through a bound gateway is disrupted during the PATCH wasn't measured.

---

## 4. T3: private ingress

Setup:
- ingress gateway `pnt-ingress` (`CLIENT_TO_AGENT`, LRO **3 s**);
- Model Armor template `pnt-shield` (prompt injection and jailbreak, `MEDIUM_AND_ABOVE`);
- authz extension `pnt-ma-authz` (service `modelarmor.us-west1.rep.googleapis.com`, `model_armor_settings` → template);
- `CONTENT_AUTHZ` policy `pnt-ingress-ma-policy` targeting `pnt-ingress`, about 20 s;
- the service agents already had the Model Armor roles project-wide from the demo;
- the bound engine got both directions in one PATCH (`clientToAgentConfig` + `agentToAnywhereConfig`): **158 s**;
- client: an e2-micro VM in `pnt-client` (Private Google Access on), with no external IP and no service account. Called with a user access token passed over IAP SSH.

Call: `POST https://us-west1-aiplatform.googleapis.com/v1/projects/acme-prod/locations/us-west1/reasoningEngines/<ENGINE>:streamQuery?alt=sse` with `{"class_method": "async_stream_query", "input": {"user_id": "...", "message": "<injection>"}}`.

| Route from the VM | DNS | Bound engine, before ingress bind | Bound engine, after bind |
|---|---|---|---|
| Private Google Access | public (`172.217.x.4`) | 200 ECHO | **403** `Model Armor: Prompt violates content security configurations` (PERMISSION_DENIED) |
| PSC endpoint, `curl --resolve host:443:10.70.250.10` | — | 200 ECHO | **403** (same) |
| PSC endpoint, full `googleapis.com.` zone (apex A + `*` CNAME) | resolves through the CNAME to 10.70.250.10 | — | **403**; benign prompt 200 |
| PSC endpoint, narrow `us-west1-aiplatform.googleapis.com.` zone (apex A) | 10.70.250.10 | — | **403**; benign prompt 200 |
| Laptop (internet) | public | 200 ECHO | **403** |

Hostnames:
- `aiplatform.us-west1.rep.googleapis.com` **doesn't exist** (NXDOMAIN). Through the PSC endpoint with `--resolve`, TLS fails (`all-apis` doesn't serve `.rep`).
- `aiplatform.us.rep.googleapis.com` and global `aiplatform.googleapis.com` return **404** for `streamQuery` on a us-west1 engine.
- Only `REGION-aiplatform.googleapis.com` works.

The 403 text is the gateway's own `Model Armor: Prompt violates content security configurations`, **not** the template's `customPromptSafetyErrorMessage`.

### 4.1 Enforcement is inconsistent (important)

Repeated identical injection calls, same prompt:

| When (min after the bind finished) | From | Bound engine blocked | **Unbound** engine (same project+region) blocked |
|---|---|---|---|
| +3 | laptop | 4/8 | 1/8 |
| +6 | laptop | 2/10 | 1/10 |
| +8 | laptop, interleaved | 6/12 | 6/12 |
| +17 | laptop | 8/16 | 2/16 |
| +17 | VM, PSC | 4/4 | — |
| +18 | VM, PSC | 11/16 | 5/16 |
| ingress **unbound** on every engine: +0 min after unbind | VM, PSC | 9/16 | 9/16 |
| +6.5 min after unbind | VM, PSC | 4/16 | 3/16 |
| +12 min after unbind | VM, PSC | 0/16 | 1/16 |

The Model Armor `sanitize_operations` log (`client_name: AGENT_GATEWAY`) showed every screened injection as `MATCH_FOUND`, confidence `HIGH`, so detection is deterministic. The calls that weren't blocked were **not sent to Model Armor at all**: a share of requests skips the ingress gateway, and a share of requests to an engine that **isn't bound** goes through it. The engine with PSC-I (unbound) was never blocked (0/8). After every engine was unbound, about half the requests were still screened, decaying to zero over about 12 minutes. **Ingress screening follows project+region state that propagates slowly and unevenly, not the per-engine binding.** The ingress gateway wrote no `gateway_requests` entries, as before.

**Conclusion T3:**
- Private client paths (PGA, or a PSC endpoint for Google APIs with a narrow or full DNS override) **do** reach the ingress gateway. There's nothing network-specific to configure on the gateway.
- Ingress governance can't be relied on per engine: it reached only ~50–70% of the bound engine's requests 20 minutes after binding, reached unbound engines in the same project+region, and lingered about 12 minutes after unbinding. Report it as a product issue, and don't demo ingress Model Armor as a guarantee.
- The narrow zone is enough. `*.googleapis.com` does cover `us-west1-aiplatform.googleapis.com`.

---

## 5. T4: Agent Runtime PSC-I together with an egress gateway binding

| Step | Result |
|---|---|
| Create with `psc_interface_config` (attachment `pnt-att-psci`, `dns_peering_configs: [{domain: run.app., target_project: acme-prod, target_network: pnt-vpc}]`) **and** `agent_gateway_config.agent_to_anywhere_config` | **400 INVALID_ARGUMENT** `` `spec.deployment_spec.psc_interface_config` and `spec.deployment_spec.agent_gateway_config` cannot be both set. `` |
| Create with PSC-I only | OK (about 5 min). The engine's run.app names resolve to 10.70.250.10 (DNS peering into the VPC's private zone). Both run.app URLs return **200** with **no registry entry or IAP grant involved** (ungoverned). `http://<vm-ip>:22` is reachable at TCP level. `https://example.com` gives `Network is unreachable` (no NAT) |
| Then `PATCH ...?updateMask=spec.deploymentSpec.agentGatewayConfig` (egress) on that PSC-I engine | **Accepted**, LRO **success in 248 s**. The engine now has **both** `pscInterfaceConfig` and `agentGatewayConfig` |
| Calls after that PATCH | Every query fails after 95–125 s: session create `498 Failed to send request to https://us-west1-aiplatform.mtls.googleapis.com/.../sessions` (runtime log: `SSL handshake is taking longer than 60.0 seconds`). **No gateway log entries** from that engine |

**Conclusion T4:**
- The supported answer is "not allowed": the create is rejected.
- The PATCH path skips that validation and produces an engine that can't make Google API calls. So no traffic path exists, governed or ungoverned, in the combined state.
- An engine with PSC-I and **no** gateway is a real ungoverned side door into the VPC (audit A8 high stays as written).
- A8 medium ("both set") should become "**broken configuration**: PSC-I plus a gateway binding (only reachable by PATCH); the agent can't reach Google APIs". Fix: redeploy without PSC-I.

---

## 6. T5: VPC-SC feasibility (read only)

- The project is directly under the organization (`getAncestry`).
- `organizations/000000000000:testIamPermissions` returned all of these as granted:
  - `accesscontextmanager.policies.list|get|create`
  - `servicePerimeters.list|get|create|update`
  - `accessLevels.list`
  - `resourcemanager.organizations.get`
- `GET accesscontextmanager.googleapis.com/v1/accessPolicies?parent=organizations/000000000000` returned **403 SERVICE_DISABLED** ("Access Context Manager API has not been used in project acme-prod"). `gcloud access-context-manager policies list` hangs non-interactively (it offers to enable the API). **The API was not enabled; nothing was created.**

What a VPC-SC demo would need:
1. Enable `accesscontextmanager.googleapis.com` on a quota project.
2. Read the org's access policy. If none exists, creating one is an **org-wide** action: use a scoped policy (`--scopes=projects/123456789012`) instead.
3. Create a perimeter around the gateway project (plus the Shared VPC host or DNS project, if separate). Restricted services: at least `aiplatform`, `networkservices`, `agentregistry`, `modelarmor`, `run`, `dns`. Start in **dry-run** mode.
4. Recreate the egress gateway, after 2026-09-08 and with a template using `ALL_TRAFFIC`:
   - `0.0.0.0/0` route plus Cloud Router and **Cloud NAT** on the attachment subnet;
   - private zone `googleapis.com.` → `restricted.googleapis.com` (199.36.153.4/30);
   - add `googleapis.com.` to the peered domains;
   - a PSC endpoint created after 2026-09-01 with the `vpc-sc` bundle, if used.
5. Rebind engines.

None of this was tested. Because creating a policy or perimeter has org-wide blast radius, **run the VPC-SC demo in a dedicated project with a scoped access policy.**

---

## 7. Timings (measured)

| Operation | Time |
|---|---|
| Connectivity template create | < 1 s |
| Egress gateway create, with template | 3m39s |
| Egress gateway create, bare | ~2m15s |
| Ingress gateway create | 3 s |
| PATCH bare → inline `networkConfig` | 3m33s |
| PATCH inline → template | 2m49s |
| PATCH template swap | 11 s |
| Engine create (AdkApp, Agent Identity, with or without binding) | 4.5–7 min |
| Engine PATCH both directions | 2m38s |
| Engine PATCH egress onto PSC-I engine | 4m08s |
| Engine PATCH removing ingress | 2m21s |
| IAP egressor grant → first 200 | 1m53s |
| IAP authz policy create | ~3 min |
| Model Armor CONTENT_AUTHZ policy create | ~20 s |
| Model Armor extension create | ~6 s |
| Gateway delete (with template) | 5m11s |
| Attachment deletable after gateway / PSC-I engine delete | first try, ~2.5 min after the gateway delete and ~20 min after the PSC-I engine delete (no 5–30 min wait observed) |

---

## 8. Updates to PRIVATE_NETWORKING_PLAN.md §2

| Fact | Was | Now | Change |
|---|---|---|---|
| F1 | Doc + API | **Live** | Both models work live. A gateway can be moved between them by PATCH (T2). |
| F2 | API | Live (partly) | `accessPath`, `deploymentModel: CENTRALIZED`, `egressNetworkConfig{networkAttachment, dnsPeeringConfig, vpcEgress}` verified. `agentCompute`, `accessTypes`, `AMBIENT` not exercised. |
| F4 | Doc | Partly live | Not tested directly. A template swap keeping the same attachment works. |
| F5 | Doc | **Verified** | Exact errors: PATCH of a referenced template → LRO code 9 `FAILED_PRECONDITION ... referenced by an agent gateway` (but `description` **is** patchable); DELETE → 400 `already being used by resource(s)`. |
| F6 | Doc ("must be deleted and recreated") | **Refuted** | A gateway without networking can get VPC connectivity in place: PATCH `networkConfig` (3.5 min), then PATCH `agentConnectivityTemplate,networkConfig` → template (2m49s). The direct bare → template PATCH fails with INTERNAL (bug). |
| F7 | **Unverified** | **Verified** | `updateMask=agentConnectivityTemplate` works for template → template (11 s) and fails (code 13) for bare → template. `networkConfig` PATCH works on a bare gateway. The mask must include `networkConfig` to clear inline config. **The template reference must use the project number.** A failed PATCH can drop `labels`. |
| F9 | **Unverified** | **Verified** | A template with an attachment in another region fails at create (LRO code 13 INTERNAL, opaque). |
| F11 | Doc | Live | `gcp-sa-agentgateway` with `compute.networkAdmin` + `dns.peer` on the (same) project was sufficient. Whether fewer roles suffice wasn't tested. |
| F12 | Unverified | Partly | The tenant project in `serviceExtensionsServiceAccount` (`service-<TENANT>@gcp-sa-dep`) is the same number as the attachment consumer `projectIdOrNum`. That ties the identities to a gateway. Which agent does what is still not fully mapped. |
| F13 | Doc | **Verified** (`targetNetwork` uses the project ID) | Exact error: `... is in network "projects/<ID>/...", not target network "projects/<NUMBER>/..."`. |
| F15 | Doc | **Live** | With `PRIVATE_RANGES_ONLY`, Google APIs left directly (public `serverIp`), and peered names resolving to the PSC endpoint went through the attachment. NAT not needed. |
| F16 | Doc; ports unverified | Live (partly) | Gateway PSC interface IP = first usable IP of the attachment subnet (`10.x.x.2`). Only HTTPS :443 tested. No firewall rule was needed toward a PSC endpoint for Google APIs. Cloud Run logs show `remoteIp 0.0.0.0` for PSC-endpoint callers, so source-IP evidence comes from the **gateway log `serverIp`**, not Cloud Run. |
| F21 | Doc/CL | Live | One registry service with **two `interfaces`** (both run.app variants, `HTTP_JSON`) works, and IAP decisions match either host. |
| F22 (pattern 2) | CL | **Live, works** | Template gateway + run.app private zone → PSC endpoint for Google APIs + Cloud Run `internal`. |
| F23 | Doc | Live | Both run.app variants were needed (one per URL form); unregistered hosts get a distinct 403 message. |
| F24 | Doc | **Live** | 403 `Egress request is not authorized.` without egressor; 200 about 2 min after the grant. |
| F28 | **Unverified** | **Verified (rejected), with a loophole** | Create rejects both (`cannot be both set`). PATCH accepts adding a gateway to a PSC-I engine, and the engine then can't reach Google APIs (TLS handshake timeouts, nothing in gateway logs). |
| F29 | Live | Live, mapping verified | Consumer `projectIdOrNum` = the gateway's `gcp-sa-dep` tenant number (for gateways). |
| F30 | Unverified for the gateway | **Refuted for pattern 2** | Cloud Run `internal` accepts the gateway's traffic when it goes through a PSC endpoint for Google APIs in a same-project VPC. A VM via the endpoint is also accepted. An unbound engine (public path) gets 404. Agent Runtime PSC-I via the same endpoint also gets 200. |
| F34 | **Unverified** | **Verified** | A private `googleapis.com.` zone with apex A + `*.googleapis.com.` CNAME resolves `us-west1-aiplatform.googleapis.com` to the endpoint, and `streamQuery` works. A narrow `REGION-aiplatform.googleapis.com.` zone with an apex A record also works. |
| F35 | Runtime on `.rep` unverified | **Verified: not usable** | `aiplatform.REGION.rep.googleapis.com` doesn't resolve; `aiplatform.us.rep.googleapis.com` and `aiplatform.googleapis.com` return 404 for a regional engine's `streamQuery`. Only `REGION-aiplatform.googleapis.com`. |
| F35b | aiplatform `p.googleapis.com` record unverified | Not checked | — |
| F36 | **Unverified** | **Verified, but unreliable** | Requests over PGA and over the PSC endpoint were blocked by the bound ingress gateway's Model Armor. Coverage was ~50–70% of requests to the bound engine, ~15–30% of requests to an **unbound** engine in the same project+region were also screened (20+ min after binding), and screening continued for ~12 min after every engine was unbound. Enforcement is project+region-level state that propagates slowly, not per engine. |
| F37 | Live | Live | Still Model Armor only; the ingress gateway writes no request logs. The block message is the gateway's generic one, not the template's custom message. |
| F40 | Doc | **Verified** | Second egress gateway in the same project+region → `400 "Another Agent Gateway is already active or being created for this project and direction."` An unbound engine can coexist with bound ones. |
| F41 | Unverified | Partly | 4 egress gateways + 1 ingress in one project+region were allowed. One `/28` attachment served 2 gateways. |
| **F44 (new)** | — | Live | Engines bound at create time to a template egress gateway needed `GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES=false`; without it, every Google API call through the gateway got 401. Cause: a known google-auth bug (Google is fixing it); pinning `google-auth==2.60.0` is the preferred fix (keeps token binding). |
| **F45 (new)** | — | Live | The PSC endpoint for Google APIs forwarding rule name can't contain `-` (1–20 lowercase letters/digits), so it can't carry a `<prefix>-` naming scheme. Use labels or the address name. |

### Plan changes recommended

1. **§6.2 strategy:** for an existing egress gateway, prefer an **in-place migration**:
   - PATCH `networkConfig`, then PATCH `agentConnectivityTemplate,networkConfig`;
   - no new gateway, no engine rebind, no archived revisions;
   - keep blue/green as the fallback.

   Verify on a gateway with bound engines (traffic during the PATCH) before Policy Studio applies it to live gateways. Add both masks to the writer allowlist (P0 verified), always send `labels` in the mask, and re-read labels afterwards.
2. **Template swap** (`updateMask=agentConnectivityTemplate`, 11 s) is verified: allow it for DNS, `vpcEgress` and TLS changes (new template, same attachment).
3. **Bodies:** the gateway's `agentConnectivityTemplate` must use the **project number**; the template's `networkAttachment` and `targetNetwork` use the **project ID**. Put both rules in `agentgw_core` and preflight.
4. **A8:** high when PSC-I with no egress binding (verified ungoverned). New wording when both are set: "broken: agent can't reach Google APIs" (only reachable by PATCH). Block the PATCH in Policy Studio's preflight when the engine has PSC-I.
5. **Ingress (§1.1, §7.1, demo scenario):**
   - say private clients **are** governed by the ingress gateway, but coverage was inconsistent (F36);
   - don't present ingress Model Armor as a guarantee;
   - file product feedback;
   - default to the narrow zone; `REGION-aiplatform.googleapis.com` is the only working host.
6. **Engine deploys bound to a gateway:**
   - pin `google-auth==2.60.0` in the agent's requirements (F44: a known google-auth bug) in the demo bootstrap and in the Policy Studio redeploy guidance; `GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES=false` only as a fallback (it opts out of token binding);
   - add a preflight or audit hint when an engine's sessions return 401 through the gateway.
7. **Evidence of the private path** for the demo UI: use `gateway_requests.httpRequest.serverIp` (private IP = VPC path). Cloud Run logs don't help.
8. **Discovery:** map attachment consumers to gateways through the `gcp-sa-dep` tenant number in `agentGatewayCard.serviceExtensionsServiceAccount`.
9. **VPC-SC:** needs the ACM API enabled on a quota project and org-level policy rights. Use a dedicated project with a scoped access policy, in dry-run first.
10. **Cost:** this pattern needs no ILB, so the demo's standing cost drops to the VM, the PSC endpoint for Google APIs and the DNS zones.

---

## Cleanup

**Complete.** `teardown.sh` ran 15:15–15:28 UTC with no retries needed, then `verify-clean.sh` listed every resource type with no `pnt-` matches. Order and contents:

1. engines (`force=true`)
2. authz policies, then extensions
3. 4 gateways
4. templates
5. Model Armor template
6. 26 registry services (their IAP policies go with them)
7. the 3 project IAM bindings the spike added. `gcp-sa-aiplatform`'s pre-existing `compute.networkAdmin` was deliberately kept, and the post-teardown IAM matches the pre-spike state for both service agents
8. 3 DNS zones (one had been deleted mid-spike)
9. PSC forwarding rule and address
10. VM and the OS Login key (verified absent from the profile)
11. Cloud Run service
12. 3 network attachments (us-west1 ×2, us-west2 ×1)
13. 2 firewall rules, 4 subnets, the VPC
14. the staging bucket

Two engines (A, E), two gateways and two templates were deleted earlier, during the run. Nothing outside `pnt-*` was modified, except the three IAM bindings (added and removed) and a temporary OS Login key on the user's profile (removed). Cloud Logging entries from the spike remain until log retention expires.

## Cost (rough)

Under **USD 5** in total (estimate; check billing in a day):
- 5 Agent Runtime engines, each alive 0.5–1 h at minimum scale: the largest share, roughly USD 1–3.
- 4 egress gateways and 1 ingress gateway for about 1 h: Agent Gateway pricing not checked.
- e2-micro VM about 1 h: < USD 0.02.
- PSC endpoint for Google APIs about 1.25 h: ~USD 0.01.
- 3 private DNS zones: prorated cents.
- Cloud Run with min-instances 0 and a handful of requests: ~0.
- About 200 Model Armor sanitize calls: likely within the free tier.

No Cloud NAT, ILB or Cloud Router was created: `ALL_TRAFFIC` was never needed.

## Artifacts

The scratchpad has `log.md` (every call and result), `recreate.sh`, `teardown.sh`, `verify-clean.sh` and the phase scripts. They aren't in this repo because they contain real project identifiers.
