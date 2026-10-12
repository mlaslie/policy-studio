// Client-side stand-in for POST /render and POST /diff, used only by the mock layer.
// It mirrors what the backend generates closely enough to exercise the UI end to end.
import type { Binding, Ctx, DiffItem, DiffResult, Intent, Outputs, RenderItem, RenderResult } from "./types";
import type { World } from "./mockData";
import { MOCK_NUMBER, templateFrom } from "./mockData";
import { ROLE, accessWords, conditionFor, intentEnglish, shortName } from "../lib/policy";
import { modifyWarning } from "../lib/apply";

const IAP = "https://iap.googleapis.com/v1";

const TF_TYPE = {
  agent: ["google_iap_agent_registry_agent_iam_member", "agent_id", "agent"],
  mcp_server: ["google_iap_agent_registry_mcp_server_iam_member", "mcp_server_id", "mcp-server"],
  endpoint: ["google_iap_agent_registry_endpoint_iam_member", "endpoint_id", "endpoint"],
  registry: ["google_iap_agent_registry_iam_member", "", ""],   // registry-wide: no id, no gcloud flag
} as const;
const REG_PATH = { agent: "agents", mcp_server: "mcpServers", endpoint: "endpoints", registry: "" } as const;

const ident = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "item";
const hcl = (s: string) => JSON.stringify(s).replace(/\$\{/g, "$${");
const sq = (s: string) => `'${s.replace(/'/g, `'"'"'`)}'`;

function iapResource(ctx: Ctx, i: Intent) {
  const d = i.destination!;
  const base = `projects/${MOCK_NUMBER}/locations/${ctx.region}/iap_web/agentRegistry`;
  return d.kind === "registry" ? base : `${base}/${REG_PATH[d.kind]}/${d.id}`;
}

function grantOutputs(ctx: Ctx, i: Intent, revoke: boolean): { outputs: Outputs; warnings: string[]; notes: string[] } {
  const d = i.destination!;
  const member = i.source!.principal;
  // A revoke repeats the condition: IAM matches the binding by member, role and condition expression.
  const cond = conditionFor(i.access);
  const [tfType, tfKey, gFlag] = TF_TYPE[d.kind];
  const name = ident(`${i.source!.label}_${d.label}`);
  const res = iapResource(ctx, i);
  const warnings: string[] = [];
  const notes: string[] = [];
  if (cond && i.access?.mode !== "custom") notes.push("The '' in the condition keeps MCP setup calls (initialize, tools/list) working: they carry no tool name.");
  if (i.access?.mode === "read_only_hint") notes.push("Tools whose server marks them readOnlyHint=true are allowed, including tools added later.");
  if (i.source?.type === "project_agents") notes.push("principalSet:// covers every Agent Runtime agent in the project, current and future.");

  // ---------- Terraform
  let terraform: string;
  if (revoke) {
    terraform = [
      `# Revoke: ${intentEnglish(i)}`,
      `# If Terraform manages this grant, delete its "${tfType}" block and run terraform apply.`,
      `# If it was created outside Terraform, there is nothing to declare: use the gcloud or REST tab.`,
      `# To stop Terraform from managing it without deleting it:`,
      `#   terraform state rm ${tfType}.${name}`,
    ].join("\n");
  } else {
    const body = [
      `resource "${tfType}" "${name}" {`,
      ...([["project", "var.project_id"], ["location", "var.region"], ...(tfKey ? [[tfKey, hcl(d.id)]] : []), ["role", `"${ROLE}"`], ["member", hcl(member)]] as const).map(
        ([k, v]) => `  ${k.padEnd(Math.max(tfKey.length, 8))} = ${v}`,
      ),
    ];
    if (cond) body.push(`  condition {`, `    title      = ${hcl(cond.title)}`, `    expression = ${hcl(cond.expression)}`, `  }`);
    body.push("}");
    terraform = `# ${intentEnglish(i)}\n` + body.join("\n");
  }

  // ---------- gcloud
  const flags = [
    `  --resource-type=agent-registry \\`,
    ...(gFlag ? [`  --${gFlag}=${d.id} \\`] : []),
    `  --region=${ctx.region} \\`,
    `  --project=${ctx.project} \\`,
    `  --member=${sq(member)} \\`,
    `  --role=${ROLE}`,
  ];
  let gcloud: string;
  const verb = revoke ? "remove" : "add";
  if (revoke && !cond) {
    gcloud = [`# ${intentEnglish(i)}`, `gcloud iap web remove-iam-policy-binding \\`, ...flags.slice(0, -1), `  --role=${ROLE} \\`, `  --condition=None`].join("\n");
  } else if (cond) {
    gcloud = [
      `# ${intentEnglish(i)}`,
      `# The expression contains commas, so it goes in a file (--condition= would split on them).`,
      `cat > condition.yaml <<'EOF'`,
      `title: ${JSON.stringify(cond.title)}`,
      `expression: ${JSON.stringify(cond.expression)}`,
      `EOF`,
      `gcloud iap web ${verb}-iam-policy-binding \\`,
      ...flags.slice(0, -1),
      `  --role=${ROLE} \\`,
      `  --condition-from-file=condition.yaml`,
    ].join("\n");
  } else {
    gcloud = [`# ${intentEnglish(i)}`, `gcloud iap web add-iam-policy-binding \\`, ...flags, ``].join("\n").trimEnd() + " \\\n  --condition=None";
  }

  // ---------- REST
  const bindingJson = JSON.stringify({ role: ROLE, members: [member], ...(cond ? { condition: cond } : {}) });
  const rest = [
    `# ${intentEnglish(i)}`,
    `# IAM is read-modify-write: read the policy (with its etag), change it, write it back.`,
    `RES="${res}"`,
    `TOKEN="$(gcloud auth print-access-token)"`,
    `curl -sS -X POST "${IAP}/$RES:getIamPolicy" \\`,
    `  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\`,
    `  -d '{"options":{"requestedPolicyVersion":3}}' > policy.json`,
    revoke
      ? `jq --arg m ${sq(member)} --arg e ${sq(cond?.expression ?? "")} '.bindings |= map(if .role=="${ROLE}" and ((.condition.expression // "") == $e) then .members -= [$m] else . end | select(.members|length>0)) | .version=3' policy.json > new.json`
      : `jq --argjson b ${sq(bindingJson)} '.bindings += [$b] | .version=3' policy.json > new.json`,
    `curl -sS -X POST "${IAP}/$RES:setIamPolicy" \\`,
    `  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\`,
    `  -d "{\\"policy\\": $(cat new.json)}"`,
  ].join("\n");

  // ---------- Python
  const python = [
    `# ${intentEnglish(i)}`,
    `# pip install google-cloud-iap`,
    `from google.cloud import iap_v1`,
    `from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2`,
    `from google.type import expr_pb2`,
    ``,
    `client = iap_v1.IdentityAwareProxyAdminServiceClient()`,
    `resource = ${JSON.stringify(res)}`,
    `policy = client.get_iam_policy(request=iam_policy_pb2.GetIamPolicyRequest(`,
    `    resource=resource, options=options_pb2.GetPolicyOptions(requested_policy_version=3)))`,
    `policy.version = 3`,
    ...(revoke
      ? [
          `for b in policy.bindings:`,
          `    if b.role == ${JSON.stringify(ROLE)} and ${JSON.stringify(member)} in b.members and b.condition.expression == ${JSON.stringify(cond?.expression ?? "")}:`,
          `        b.members.remove(${JSON.stringify(member)})`,
          `keep = [b for b in policy.bindings if b.members]`,
          `del policy.bindings[:]`,
          `policy.bindings.extend(keep)`,
        ]
      : [
          `policy.bindings.append(policy_pb2.Binding(`,
          `    role=${JSON.stringify(ROLE)},`,
          `    members=[${JSON.stringify(member)}],`,
          ...(cond ? [`    condition=expr_pb2.Expr(`, `        title=${JSON.stringify(cond.title)},`, `        expression=${JSON.stringify(cond.expression)}),`] : []),
          `))`,
        ]),
    `client.set_iam_policy(request=iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy))`,
  ].join("\n");

  return { outputs: { terraform, gcloud, rest, python }, warnings, notes };
}

/** modify: one read-modify-write that swaps the binding with the old condition for one with the new condition, like
 *  the backend's render (gcloud get-/set-iam-policy, REST and Python the same; Terraform is a destroy + create). */
function modifyOutputs(ctx: Ctx, i: Intent): { outputs: Outputs; warnings: string[]; notes: string[] } {
  const d = i.destination!;
  const member = i.source!.principal;
  const from = conditionFor(i.access_from);
  const cond = conditionFor(i.access);
  const [tfType, tfKey, gFlag] = TF_TYPE[d.kind];
  const name = ident(`${i.source!.label}_${d.label}`);
  const res = iapResource(ctx, i);
  const head = `# ${intentEnglish(i)}`;
  const where = [`  --resource-type=agent-registry \\`, ...(gFlag ? [`  --${gFlag}=${d.id} \\`] : []), `  --region=${ctx.region} \\`, `  --project=${ctx.project}`];
  const jq = [
    `jq --arg role ${ROLE} --arg member ${sq(member)} --arg from ${sq(from?.expression ?? "")} --arg expr ${sq(cond?.expression ?? "")} --arg title ${sq(cond?.title ?? "")} '`,
    `  .version = 3 | .bindings = ([(.bindings // [])[] | if .role == $role and ((.condition.expression // "") == $from) then .members -= [$member] else . end | select(.members | length > 0)]`,
    `    + [{role: $role, members: [$member]} + (if $expr == "" then {} else {condition: {title: $title, expression: $expr}} end)])' policy.json > new.json`,
  ];
  const pad = Math.max(tfKey.length, 8);
  const block = (c: typeof cond, lifecycle: boolean) =>
    [
      `resource "${tfType}" "${name}" {`,
      ...([["project", "var.project_id"], ["location", "var.region"], ...(tfKey ? [[tfKey, hcl(d.id)]] : []), ["role", `"${ROLE}"`], ["member", hcl(member)]] as const).map(([k, v]) => `  ${k.padEnd(pad)} = ${v}`),
      ...(c ? [`  condition {`, `    title      = ${hcl(c.title)}`, `    expression = ${hcl(c.expression)}`, `  }`] : []),
      ...(lifecycle ? [`  lifecycle {`, `    create_before_destroy = true`, `  }`] : []),
      `}`,
    ].join("\n");
  const terraform = [
    head,
    `# Change access: an _iam_member is keyed by its condition, so Terraform plans a replacement (destroy + create).`,
    `# Edit the condition of the block that manages this grant as below; create_before_destroy adds the new binding first.`,
    `#`,
    `# Today:`,
    block(from, false).split("\n").map((l) => `# ${l}`).join("\n"),
    ``,
    block(cond, true),
  ].join("\n");
  const gcloud = [head, `# One read-modify-write: not remove- + add-iam-policy-binding (that leaves a moment with no access).`, `gcloud iap web get-iam-policy \\`, ...where.slice(0, -1), `${where[where.length - 1]} \\`, `  --format=json > policy.json`, ...jq, `gcloud iap web set-iam-policy new.json \\`, ...where].join("\n");
  const rest = [
    head,
    `RES="${res}"`,
    `TOKEN="$(gcloud auth print-access-token)"`,
    `curl -sS -X POST "${IAP}/$RES:getIamPolicy" \\`,
    `  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\`,
    `  -d '{"options":{"requestedPolicyVersion":3}}' > policy.json`,
    ...jq,
    `curl -sS -X POST "${IAP}/$RES:setIamPolicy" \\`,
    `  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\`,
    `  -d "{\\"policy\\": $(cat new.json)}"`,
  ].join("\n");
  const python = [
    head,
    `# pip install google-cloud-iap  (see the bundle for the modify() helper)`,
    `modify(`,
    `    ${JSON.stringify(res)},`,
    `    ${JSON.stringify(member)},`,
    ...(from ? [`    old_expression=${JSON.stringify(from.expression)},`] : []),
    ...(cond ? [`    title=${JSON.stringify(cond.title)},`, `    expression=${JSON.stringify(cond.expression)},`] : []),
    `)`,
  ].join("\n");
  const notes = [`change: replaces the binding whose condition is ${from?.expression ?? "none (unconditional)"}, in the same setIamPolicy as the new one.`];
  const warn = modifyWarning(i);
  return { outputs: { terraform, gcloud, rest, python }, warnings: warn ? [warn] : [], notes };
}

/** A modify on one resource's bindings, like the backend's apply.modify_binding: the member's binding with exactly
 *  the old condition (by expression) is swapped for one with the new condition; the others are kept in order. */
export function modifyBindings(cur: Binding[], i: Intent): { bindings: Binding[]; outcome: "changed" | "same" | "already" | "not_found" } {
  const member = i.source?.principal ?? "";
  const from = conditionFor(i.access_from);
  const to = conditionFor(i.access);
  const mine = (b: Binding, c: Binding["condition"]) => b.member === member && b.role === ROLE && sameCond(b.condition, c);
  if (sameCond(from, to)) return { bindings: cur, outcome: "same" };
  if (!cur.some((b) => mine(b, from))) return { bindings: cur, outcome: cur.some((b) => mine(b, to)) ? "already" : "not_found" };
  const kept = cur.filter((b) => !mine(b, from));
  const next: Binding = { role: ROLE, member, member_label: i.source?.label ?? member, condition: to, english: intentEnglish({ ...i, kind: "grant" }) };
  return { bindings: kept.some((b) => mine(b, to)) ? kept : [...kept, next], outcome: "changed" };
}

function bindOutputs(ctx: Ctx, w: World, i: Intent, unbind: boolean): { outputs: Outputs; warnings: string[]; notes: string[] } {
  const engine = w.inventory.engines.find((e) => e.name === i.engine);
  const engName = i.engine ?? "projects/PROJECT_NUMBER/locations/REGION/reasoningEngines/ENGINE_ID";
  const dir = i.gateway!.direction;
  const current = { ...(engine?.gateways ?? {}) };
  if (unbind) delete current[dir];
  else current[dir] = i.gateway!.name;
  const cfg: Record<string, { agentGateway: string }> = {};
  if (current.egress) cfg.agentToAnywhereConfig = { agentGateway: current.egress };
  if (current.ingress) cfg.clientToAgentConfig = { agentGateway: current.ingress };
  const body = JSON.stringify({ spec: { deploymentSpec: { agentGatewayConfig: cfg } } });
  const url = `https://${ctx.region}-aiplatform.googleapis.com/v1/${engName}?updateMask=spec.deploymentSpec.agentGatewayConfig`;
  const label = engine?.display_name ?? i.engine_label ?? shortName(engName);
  const warnings: string[] = [];
  if (engine && !engine.bindable) warnings.push(`${label} was created before 2026-04-29 and can't be bound to a gateway. Redeploy it to get a bindable engine.`);
  if (dir === "ingress" && !ctx.ge_app) warnings.push("Gemini Enterprise app ID is not set; registering the agent with your app uses GE_APP_ID.");
  const notes = ["The PATCH replaces the whole agentGatewayConfig, so the other direction is re-sent unchanged.", "The engine redeploys: it takes a few minutes before traffic uses the new path."];
  const curl = [
    `curl -sS --fail-with-body -X PATCH \\`,
    `  "${url}" \\`,
    `  -H "Authorization: Bearer $(gcloud auth print-access-token)" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d ${sq(body)}`,
  ];
  const ge =
    dir === "ingress" && !unbind
      ? [
          ``,
          `# Then register the agent with your Gemini Enterprise app (${ctx.ge_location || "global"}):`,
          `agents-cli publish gemini-enterprise --app=${ctx.ge_app || "GE_APP_ID"} --location=${ctx.ge_location || "global"} \\`,
          `  --agent-engine=${engName}`,
        ]
      : [];
  const terraform = [
    `# ${intentEnglish(i)}`,
    `# No Terraform resource binds an existing Agent Runtime engine to a gateway, so this runs the PATCH.`,
    `resource "terraform_data" "${ident(`${unbind ? "unbind" : "bind"}_${label}_${dir}`)}" {`,
    `  input = {`,
    `    url  = "https://\${var.region}-aiplatform.googleapis.com/v1/${engName}?updateMask=spec.deploymentSpec.agentGatewayConfig"`,
    `    body = ${hcl(body)}`,
    `  }`,
    `  provisioner "local-exec" {`,
    `    command = <<-EOT`,
    `      curl -sS --fail-with-body -X PATCH "$URL" \\`,
    `        -H "Authorization: Bearer $(gcloud auth print-access-token)" \\`,
    `        -H "Content-Type: application/json" -d "$BODY"`,
    `    EOT`,
    `    environment = { URL = self.input.url, BODY = self.input.body }`,
    `  }`,
    `}`,
  ].join("\n");
  const gcloud = [`# ${intentEnglish(i)}`, `# There is no gcloud command for this yet; the REST PATCH below is the supported way.`, ...curl, ...ge].join("\n");
  const rest = [`# ${intentEnglish(i)}`, ...curl, ...ge].join("\n");
  const python = [
    `# ${intentEnglish(i)}`,
    `# The client library has no method for agentGatewayConfig yet, so this PATCHes with an AuthorizedSession.`,
    `import google.auth`,
    `from google.auth.transport.requests import AuthorizedSession`,
    ``,
    `creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])`,
    `session = AuthorizedSession(creds)`,
    `r = session.patch(`,
    `    ${JSON.stringify(url)},`,
    `    json=${body},`,
    `)`,
    `r.raise_for_status()`,
    `print("operation:", r.json()["name"])`,
  ].join("\n");
  return { outputs: { terraform, gcloud, rest, python }, warnings, notes };
}

function maOutputs(ctx: Ctx, w: World, i: Intent, off: boolean, all: Intent[]): { outputs: Outputs; warnings: string[]; notes: string[] } {
  const gw = i.gateway!;
  const gid = shortName(gw.name);
  const gp = gw.name.split("/")[1] ?? ctx.project;
  const pid = `${gid}-ma-policy`;
  const staged = all.filter((x) => x.kind === "model_armor_extension" && !x.params?.delete).map((x) => `projects/${x.params?.project || w.GP}/locations/${ctx.region}/authzExtensions/${x.params?.name}`);
  const known = gw.extension ?? staged[0] ?? w.maExtensions[0]?.name;
  const ext = known ?? `projects/${gp}/locations/${ctx.region}/authzExtensions/MODEL_ARMOR_EXTENSION`;
  const notes = ["Creating or deleting an authz policy is a long-running operation (about 4 minutes).", "Egress screening covers MCP traffic, not A2A."];
  const warnings: string[] = [];
  if (gw.direction === "ingress") notes.push("An ingress gateway allows at most one CONTENT_AUTHZ policy.");
  if (staged.includes(ext)) notes.push(`Uses ${shortName(ext)}, which an earlier item in this cart creates.`);
  if (!off && known && gw.extension && !staged.includes(known) && !w.maExtensions.some((x) => x.name === known))
    warnings.push(`Model Armor isn't set up in ${ctx.region} yet: the extension ${shortName(known)} doesn't exist and isn't staged in this cart. Stage the setup (template, extension, service agent roles) with this item.`);
  if (!off && !known)
    warnings.push(
      `Model Armor isn't set up in ${ctx.region} yet: there's no Model Armor authz extension for this gateway to use. Set it up first (a template, an extension and permissions for the gateway's service agent); this item then uses the new extension automatically. Until then the commands below use the placeholder MODEL_ARMOR_EXTENSION.`,
    );
  const yaml = [
    `name: ${pid}`,
    `target:`,
    `  resources:`,
    `  - ${gw.name}`,
    `policyProfile: CONTENT_AUTHZ`,
    `action: CUSTOM`,
    `customProvider:`,
    `  authzExtension:`,
    `    resources:`,
    `    - ${ext}`,
  ];
  const api = `https://networksecurity.googleapis.com/v1/projects/${gp}/locations/${ctx.region}/authzPolicies`;
  const body = JSON.stringify({ target: { resources: [gw.name] }, policyProfile: "CONTENT_AUTHZ", action: "CUSTOM", customProvider: { authzExtension: { resources: [ext] } } });
  if (off) {
    return {
      notes,
      warnings,
      outputs: {
        terraform: `# ${intentEnglish(i)}\n# Delete the google_network_security_authz_policy block for ${pid} and run terraform apply.\n# Not managed by Terraform? Use the gcloud tab.`,
        gcloud: `# ${intentEnglish(i)}\ngcloud network-security authz-policies delete ${pid} \\\n  --location=${ctx.region} --project=${gp} --quiet`,
        rest: `# ${intentEnglish(i)}\ncurl -sS -X DELETE "${api}/${pid}" \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)"`,
        python: `# ${intentEnglish(i)}\n# pip install google-cloud-network-security\nfrom google.cloud import network_security_v1\n\nclient = network_security_v1.NetworkSecurityClient()\nop = client.delete_authz_policy(name=${JSON.stringify(`projects/${gp}/locations/${ctx.region}/authzPolicies/${pid}`)})\nop.result(timeout=900)`,
      },
    };
  }
  return {
    notes,
    warnings,
    outputs: {
      terraform: [
        `# ${intentEnglish(i)}`,
        `resource "google_network_security_authz_policy" "${ident(pid)}" {`,
        `  project         = ${hcl(gp)}`,
        `  location        = var.region`,
        `  name            = ${hcl(pid)}`,
        `  policy_profile  = "CONTENT_AUTHZ"`,
        `  action          = "CUSTOM"`,
        `  target {`,
        `    resources = [${hcl(gw.name)}]`,
        `  }`,
        `  custom_provider {`,
        `    authz_extension {`,
        `      resources = [${hcl(ext)}]`,
        `    }`,
        `  }`,
        `}`,
      ].join("\n"),
      gcloud: [`# ${intentEnglish(i)}`, `# authz-policies has no flag-based create: import a YAML file.`, `cat > ma-policy.yaml <<'EOF'`, ...yaml, `EOF`, `gcloud network-security authz-policies import ${pid} \\`, `  --source=ma-policy.yaml --location=${ctx.region} --project=${gp}`].join("\n"),
      rest: [`# ${intentEnglish(i)}`, `curl -sS -X POST "${api}?authzPolicyId=${pid}" \\`, `  -H "Authorization: Bearer $(gcloud auth print-access-token)" \\`, `  -H "Content-Type: application/json" \\`, `  -d ${sq(body)}`].join("\n"),
      python: [
        `# ${intentEnglish(i)}`,
        `# pip install google-cloud-network-security`,
        `from google.cloud import network_security_v1 as ns`,
        ``,
        `client = ns.NetworkSecurityClient()`,
        `policy = ns.AuthzPolicy(`,
        `    target=ns.AuthzPolicy.Target(resources=[${JSON.stringify(gw.name)}]),`,
        `    policy_profile=ns.AuthzPolicy.PolicyProfile.CONTENT_AUTHZ,`,
        `    action=ns.AuthzPolicy.AuthzAction.CUSTOM,`,
        `    custom_provider=ns.AuthzPolicy.CustomProvider(`,
        `        authz_extension=ns.AuthzPolicy.CustomProvider.AuthzExtension(resources=[${JSON.stringify(ext)}])),`,
        `)`,
        `op = client.create_authz_policy(parent=${JSON.stringify(`projects/${gp}/locations/${ctx.region}`)},`,
        `                                authz_policy=policy, authz_policy_id=${JSON.stringify(pid)})`,
        `op.result(timeout=900)`,
      ].join("\n"),
    },
  };
}

function setupOutputs(ctx: Ctx, w: World, i: Intent): { outputs: Outputs; warnings: string[]; notes: string[]; resource: string } {
  const p = i.params ?? {};
  const proj = p.project || w.GP;
  const R = ctx.region;
  const del = !!p.delete;
  const head = `# ${intentEnglish(i)}\n`;
  const notes: string[] = [];
  const warnings: string[] = [];
  if (i.kind === "model_armor_template") {
    const id = p.template_id || "TEMPLATE_ID";
    const f = p.filters ?? { pi_jailbreak: "MEDIUM_AND_ABOVE", sdp: "basic", rai: {}, malicious_uri: true };
    const raw = templateFrom(`projects/${proj}/locations/${R}/templates/${id}`, f, p.block_message).raw as Record<string, unknown>;
    const body = JSON.stringify({ filterConfig: raw.filterConfig, templateMetadata: raw.templateMetadata });
    const url = `https://modelarmor.${R}.rep.googleapis.com/v1/projects/${proj}/locations/${R}/templates`;
    notes.push("A template is a named set of filters; an authz extension names it, and an authz policy attaches the extension to a gateway.");
    if (f.sdp === "advanced") warnings.push("Sensitive data “advanced” needs a Sensitive Data Protection inspect template; the commands use the placeholder INSPECT_TEMPLATE.");
    return {
      resource: `projects/${proj}/locations/${R}/templates/${id}`,
      notes,
      warnings,
      outputs: {
        terraform: head + (del ? `# Delete the google_model_armor_template block for ${id} and run terraform apply.` : `resource "google_model_armor_template" "${ident(id)}" {\n  project     = ${hcl(proj)}\n  location    = ${hcl(R)}\n  template_id = ${hcl(id)}\n  # filter_config { ... } (mock preview; the real backend renders every filter)\n}`),
        gcloud: head + (del ? `CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR=https://modelarmor.${R}.rep.googleapis.com/ gcloud model-armor templates delete ${id} --project=${proj} --location=${R} --quiet` : `CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR=https://modelarmor.${R}.rep.googleapis.com/ gcloud model-armor templates create ${id} \\\n  --project=${proj} --location=${R} \\\n  --malicious-uri-filter-settings-enforcement=${f.malicious_uri ? "enabled" : "disabled"}`),
        rest: head + (del ? `curl -sS -X DELETE "${url}/${id}" -H "Authorization: Bearer $(gcloud auth print-access-token)"` : `curl -sS -X POST "${url}?templateId=${id}" \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\\n  -d ${sq(body)}`),
        python: head + `# pip install google-cloud-modelarmor\n# ${del ? "delete_template" : "create_template"}(${JSON.stringify(proj)}, ${JSON.stringify(R)}, ${JSON.stringify(id)}${del ? "" : ", body"})`,
      },
    };
  }
  if (i.kind === "model_armor_extension") {
    const name = p.name || "EXTENSION_NAME";
    const tmpl = p.template?.startsWith("projects/") ? p.template : `projects/${proj}/locations/${R}/templates/${p.template ?? "TEMPLATE_ID"}`;
    const settings = JSON.stringify([{ request_template_id: tmpl, response_template_id: tmpl }]);
    const body = JSON.stringify({ service: `modelarmor.${R}.rep.googleapis.com`, failOpen: false, timeout: "5s", metadata: { model_armor_settings: settings } });
    const url = `https://networkservices.googleapis.com/v1/projects/${proj}/locations/${R}/authzExtensions`;
    notes.push("service modelarmor.<region>.rep.googleapis.com makes this a Model Armor extension; metadata.model_armor_settings names the template.", "A long-running operation.");
    return {
      resource: `projects/${proj}/locations/${R}/authzExtensions/${name}`,
      notes,
      warnings,
      outputs: {
        terraform: head + (del ? `# Delete the google_network_services_authz_extension block for ${name} and run terraform apply.` : `resource "google_network_services_authz_extension" "${ident(name)}" {\n  project   = ${hcl(proj)}\n  location  = ${hcl(R)}\n  name      = ${hcl(name)}\n  service   = "modelarmor.${R}.rep.googleapis.com"\n  timeout   = "5s"\n  fail_open = false\n  metadata = {\n    model_armor_settings = jsonencode([{ request_template_id = ${hcl(tmpl)}, response_template_id = ${hcl(tmpl)} }])\n  }\n}`),
        gcloud: head + (del ? `gcloud service-extensions authz-extensions delete ${name} --location=${R} --project=${proj} --quiet` : `cat > ${name}.yaml <<'EOF'\nname: ${name}\nservice: modelarmor.${R}.rep.googleapis.com\nfailOpen: false\ntimeout: 5s\nmetadata:\n  model_armor_settings: '${settings}'\nEOF\ngcloud service-extensions authz-extensions import ${name} \\\n  --source=${name}.yaml --location=${R} --project=${proj}`),
        rest: head + (del ? `curl -sS -X DELETE "${url}/${name}" -H "Authorization: Bearer $(gcloud auth print-access-token)"` : `curl -sS -X POST "${url}?authzExtensionId=${name}" \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\\n  -d ${sq(body)}`),
        python: head + `# pip install google-cloud-network-services\n# ${del ? "delete_authz_extension" : "create_authz_extension"}(${JSON.stringify(proj)}, ${JSON.stringify(R)}, ${JSON.stringify(name)}${del ? "" : ", body"})`,
      },
    };
  }
  const member = p.member?.includes(":") ? p.member : `serviceAccount:${p.member ?? "SERVICE_AGENT"}`;
  const roles = p.roles ?? [];
  notes.push("Project-level IAM on the template's project, so the gateway's service agent can call Model Armor.");
  return {
    resource: `projects/${proj}`,
    notes,
    warnings,
    outputs: {
      terraform: head + (del ? "# Delete the google_project_iam_member block and run terraform apply." : `resource "google_project_iam_member" "${ident(`ma_roles_${member}`)}" {\n  for_each = toset(${JSON.stringify(roles)})\n\n  project = ${hcl(proj)}\n  role    = each.value\n  member  = ${hcl(member)}\n}`),
      gcloud: head + roles.map((r) => `gcloud projects ${del ? "remove" : "add"}-iam-policy-binding ${proj} \\\n  --member=${member} --role=${r} --condition=None`).join("\n"),
      rest: head + `# getIamPolicy -> ${del ? "remove" : "add"} ${member} in ${roles.join(", ")} -> setIamPolicy (read-modify-write with the etag)`,
      python: head + `# pip install google-cloud-resource-manager\n# ${del ? "revoke" : "grant"}_project_roles(${JSON.stringify(proj)}, ${JSON.stringify(member)}, ${JSON.stringify(roles)})`,
    },
  };
}

function enforcementOutputs(ctx: Ctx, w: World, i: Intent, all: Intent[]): { outputs: Outputs; warnings: string[]; notes: string[]; resource: string } {
  const g = w.gateways.find((x) => x.name === i.gateway?.name);
  const enf = g?.enforcement;
  const head = `# ${intentEnglish(i)}\n`;
  const warnings: string[] = [];
  const notes = ["The enforcement mode lives on the IAP authz extension, not on the gateway.", "Takes effect in about 2–3 minutes (measured), sometimes before the operation reports done."];
  const api = "https://networkservices.googleapis.com/v1";
  if (i.kind === "set_enforcement") {
    const ext = i.extension ?? enf?.extension ?? "EXTENSION";
    const id = shortName(ext);
    const staged = all.some((x) => x.kind === "dedicate_extension" && !x.revert && x.new_name === id);
    const shared = staged ? [] : (enf?.shared_with ?? []).map(shortName);
    const dry = i.mode === "DRY_RUN";
    const md = dry ? { iapPolicyVersion: "V1", iamEnforcementMode: "DRY_RUN" } : { iapPolicyVersion: "V1" };
    const body = JSON.stringify({ metadata: md, failOpen: dry });
    if (shared.length && i.scope === "shared") warnings.push(`This extension also controls ${shared.join(", ")}: they switch to ${dry ? "dry run" : "enforce"} too.`);
    if (shared.length && i.scope !== "shared") warnings.push(`${id} also controls ${shared.join(", ")}, so they change too. Give ${g?.id} its own extension first.`);
    if (dry) warnings.push(`Dry run: once applied, nothing is blocked on ${[g?.id, ...(i.scope === "shared" ? shared : [])].join(", ")} (calls IAP would deny pass and are logged as allowed).`);
    const proj = ext.split("/")[1] ?? w.GP;
    const yaml = [`name: ${id}`, `service: iap.googleapis.com`, `timeout: 1s`, `failOpen: ${dry}`, `metadata:`, `  iapPolicyVersion: V1`, ...(dry ? [`  iamEnforcementMode: DRY_RUN`] : [])].join("\n");
    return {
      resource: ext,
      notes,
      warnings,
      outputs: {
        terraform: head + (staged ? `# ${id} is created by the dedicate item in this cart; its block already has the ${dry ? "dry-run" : "enforce"} settings.` : `import {\n  to = google_network_services_authz_extension.iap_${ident(id)}\n  id = ${hcl(ext)}\n}\n\nresource "google_network_services_authz_extension" "iap_${ident(id)}" {\n  project   = ${hcl(proj)}\n  location  = ${hcl(ctx.region)}\n  name      = ${hcl(id)}\n  service   = "iap.googleapis.com"\n  timeout   = "1s"\n  fail_open = ${dry}\n  metadata = {\n    iapPolicyVersion = "V1"${dry ? '\n    iamEnforcementMode = "DRY_RUN"' : ""}\n  }\n}`),
        gcloud: head + `cat > ${id}.yaml <<'EOF'\n${yaml}\nEOF\ngcloud service-extensions authz-extensions import ${id} \\\n  --source=${id}.yaml --location=${ctx.region} --project=${proj}`,
        rest: head + `curl -sS --fail-with-body -X PATCH '${api}/${ext}?updateMask=metadata,failOpen' \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\\n  -d ${sq(body)}`,
        python: head + `# pip install google-cloud-network-services\nset_iap_enforcement(${JSON.stringify(ext)}, ${JSON.stringify(md)}, ${dry ? "True" : "False"})`,
      },
    };
  }
  const src = i.source_extension ?? enf?.extension ?? "EXTENSION";
  const name = i.new_name ?? "NEW_EXTENSION";
  const copy = src.replace(/\/authzExtensions\/[^/]+$/, `/authzExtensions/${name}`);
  const policy = enf?.policy ?? "POLICY";
  const proj = src.split("/")[1] ?? w.GP;
  const patch = `curl -sS --fail-with-body -X PATCH 'https://networksecurity.googleapis.com/v1/${policy}?updateMask=customProvider.authzExtension.resources,labels' \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \\\n  -d '{"customProvider":{"authzExtension":{"resources":["${i.revert ? src : copy}"]}},"labels":{"team":"platform"}}'`;
  if (i.revert)
    return {
      resource: policy,
      notes,
      warnings,
      outputs: {
        terraform: head + `# Point ${shortName(policy)} back at ${shortName(src)}, then remove the ${name} block and run terraform apply.`,
        gcloud: head + `# (authz-policies import with ${shortName(src)})\ngcloud service-extensions authz-extensions delete ${name} --location=${ctx.region} --project=${proj} --quiet`,
        rest: head + patch + `\ncurl -sS --fail-with-body -X DELETE '${api}/${copy}' -H "Authorization: Bearer $(gcloud auth print-access-token)"`,
        python: head + `point_policy_at(${JSON.stringify(policy)}, ${JSON.stringify(src)})\ndelete_iap_extension(${JSON.stringify(proj)}, ${JSON.stringify(ctx.region)}, ${JSON.stringify(name)})`,
      },
    };
  notes.push(`1. create ${name}, a copy of ${shortName(src)}; 2. PATCH ${shortName(policy)} so ${g?.id} uses it. Other gateways keep ${shortName(src)}.`);
  return {
    resource: policy,
    notes,
    warnings,
    outputs: {
      terraform: head + `resource "google_network_services_authz_extension" "${ident(name)}" {\n  project   = ${hcl(proj)}\n  location  = ${hcl(ctx.region)}\n  name      = ${hcl(name)}\n  service   = "iap.googleapis.com"\n  timeout   = "1s"\n}\n\n# + import and update google_network_security_authz_policy ${shortName(policy)} (custom_provider -> ${name})`,
      gcloud: head + `gcloud service-extensions authz-extensions import ${name} --source=${name}.yaml --location=${ctx.region} --project=${proj}\ngcloud network-security authz-policies import ${shortName(policy)} --source=${shortName(policy)}.yaml --location=${ctx.region} --project=${proj}`,
      rest: head + `curl -sS --fail-with-body -X POST '${api}/projects/${proj}/locations/${ctx.region}/authzExtensions?authzExtensionId=${name}' \\\n  -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" -d '{"service":"iap.googleapis.com", ...}'\n` + patch,
      python: head + `copy_authz_extension(${JSON.stringify(proj)}, ${JSON.stringify(ctx.region)}, ${JSON.stringify(name)}, body)\npoint_policy_at(${JSON.stringify(policy)}, ${JSON.stringify(copy)})`,
    },
  };
}

export function mockRender(ctx: Ctx, w: World, intents: Intent[]): RenderResult {
  const items: RenderItem[] = intents.map((i) => {
    let r: { outputs: Outputs; warnings: string[]; notes: string[] };
    let anatomy: RenderItem["anatomy"];
    if (i.kind === "grant" || i.kind === "revoke" || i.kind === "modify") {
      if (!i.source || !i.destination) {
        return { intent_id: i.id, english: intentEnglish(i), anatomy: { resource: "", role: ROLE, member: "", notes: [] }, outputs: { terraform: "", gcloud: "", rest: "", python: "" }, warnings: ["Pick a source and a destination first."] };
      }
      r = i.kind === "modify" ? modifyOutputs(ctx, i) : grantOutputs(ctx, i, i.kind === "revoke");
      const cond = i.kind !== "revoke" ? conditionFor(i.access) : null;
      anatomy = { resource: iapResource(ctx, i), role: ROLE, member: i.source.principal, condition: cond?.expression ?? null, notes: r.notes };
      const src = w.inventory.engines.find((e) => e.name === i.source?.engine);
      if (i.kind === "grant" && src && !src.gateways.egress) r.warnings.push(`${src.display_name} is not bound to an egress gateway, so this grant is never checked: its calls go out directly.`);
      if (i.kind === "grant" && i.access?.mode === "all" && i.destination.kind === "mcp_server") {
        const s = w.inventory.mcp_servers.find((m) => m.id === i.destination!.id);
        const destructive = s?.tools.filter((t) => t.destructive).map((t) => t.name) ?? [];
        if (destructive.length) r.warnings.push(`Full access includes destructive tools: ${destructive.join(", ")}.`);
      }
    } else if (i.kind === "bind_gateway" || i.kind === "unbind_gateway") {
      r = bindOutputs(ctx, w, i, i.kind === "unbind_gateway");
      anatomy = { resource: i.engine ?? "", role: "", member: "", condition: null, notes: r.notes };
    } else if (i.kind === "set_enforcement" || i.kind === "dedicate_extension") {
      const s = enforcementOutputs(ctx, w, i, intents);
      r = s;
      anatomy = { resource: s.resource, role: i.kind === "set_enforcement" ? `enforcement → ${i.mode === "DRY_RUN" ? "Dry run" : "Enforce"}` : "customProvider.authzExtension", member: i.gateway?.name ?? "", condition: null, notes: s.notes };
    } else if (i.kind === "model_armor_template" || i.kind === "model_armor_extension" || i.kind === "iam_project_grant") {
      const s = setupOutputs(ctx, w, i);
      r = s;
      anatomy = { resource: s.resource, role: i.kind === "iam_project_grant" ? (i.params?.roles ?? []).join(", ") : "", member: i.params?.member ?? "", condition: null, notes: s.notes };
    } else {
      r = maOutputs(ctx, w, i, i.kind === "model_armor_off", intents);
      anatomy = { resource: i.gateway?.name ?? "", role: "", member: "", condition: null, notes: r.notes };
    }
    return { intent_id: i.id, english: intentEnglish(i), anatomy, outputs: r.outputs, warnings: r.warnings };
  });

  const tf = items.map((x) => x.outputs.terraform).filter(Boolean).join("\n\n");
  const header = (title: string) => `#!/usr/bin/env bash\n# ${title}\n# Generated by Policy Studio for project ${ctx.project}, region ${ctx.region}.\nset -euo pipefail\n`;
  return {
    items,
    bundle: {
      terraform: {
        "main.tf": `terraform {\n  required_providers {\n    google = { source = "hashicorp/google", version = ">= 7.40.0" }\n  }\n}\n\nprovider "google" {\n  project = var.project_id\n  region  = var.region\n}\n\n${tf}\n`,
        "variables.tf": `variable "project_id" {\n  type    = string\n  default = ${hcl(ctx.project)}\n}\n\nvariable "region" {\n  type    = string\n  default = ${hcl(ctx.region)}\n}\n`,
      },
      gcloud: header("Apply with gcloud") + "\n" + items.map((x) => x.outputs.gcloud).join("\n\n") + "\n",
      rest: header("Apply with the REST API (curl + jq)") + "\n" + items.map((x) => x.outputs.rest).join("\n\n") + "\n",
      python:
        "# Apply with the Google Cloud client libraries.\n# Generated by Policy Studio for project " + ctx.project + ", region " + ctx.region + ".\n\n" +
        items.map((x, n) => `def step_${n + 1}():\n` + x.outputs.python.split("\n").map((l) => (l ? "    " + l : "")).join("\n")).join("\n\n\n") +
        `\n\n\nif __name__ == "__main__":\n` + (items.length ? items.map((_, n) => `    step_${n + 1}()`).join("\n") : "    pass") + "\n",
    },
  };
}

// Like the backend's same_condition: by expression, whitespace-insensitive (the title doesn't count).
const normExpr = (c: Binding["condition"]) => (c?.expression ?? "").replace(/\s+/g, " ").trim();
const sameCond = (a: Binding["condition"], b: Binding["condition"]) => normExpr(a) === normExpr(b);

export function mockDiff(w: World, intents: Intent[]): DiffResult {
  const items: DiffItem[] = intents.map((i) => {
    if (i.kind === "grant" || i.kind === "revoke" || i.kind === "modify") {
      const res = i.destination?.name ?? "";
      const current = w.inventory.access[res] ?? [];
      const mine = current.filter((b) => b.member === i.source?.principal && b.role === ROLE);
      if (i.kind === "modify") {
        // Like the backend's diff: replace / present (same, or already changed) / absent (the grant changed).
        const r = modifyBindings(mine, i);
        const change = `${accessWords(i.access_from)} → ${accessWords(i.access)}`;
        if (r.outcome === "changed") return { intent_id: i.id, status: "replace", current: mine, after: r.bindings, detail: change };
        if (r.outcome === "not_found") return { intent_id: i.id, status: "absent", current: mine, after: mine, detail: "The grant to change wasn't found: it changed since you looked; Sync and try again." };
        return { intent_id: i.id, status: "present", current: mine, after: mine, detail: r.outcome === "same" ? "The new access is the same as the current one." : `Already changed (${change}).` };
      }
      if (i.kind === "revoke") {
        // Like the backend: only the binding with exactly this condition expression (no access = unconditional).
        const want = conditionFor(i.access);
        const t = want ? `“${want.title}”` : "unconditional";
        const hit = mine.filter((b) => sameCond(b.condition, want));
        return hit.length
          ? { intent_id: i.id, status: "remove", current, after: mine.filter((b) => !hit.includes(b)), detail: `Removes ${i.source?.label}'s ${t} binding; other bindings are kept.` }
          : { intent_id: i.id, status: "absent", current, detail: `${i.source?.label} has no ${t} grant on ${i.destination?.label}; nothing to remove.` };
      }
      const cond = conditionFor(i.access);
      if (mine.some((b) => sameCond(b.condition, cond))) return { intent_id: i.id, status: "present", current, detail: "An identical grant already exists." };
      if (mine.length) return { intent_id: i.id, status: "replace", current, detail: `Replaces ${i.source?.label}'s existing grant (${mine[0].condition ? "a different condition" : "unconditional"}).` };
      const broader = current.find((b) => !b.condition && (b.member.startsWith("principalSet://") || b.member.startsWith("all")));
      return { intent_id: i.id, status: "add", current, detail: broader ? `Adds a new binding. Note: ${broader.member_label} already has unconditional access.` : "Adds a new binding." };
    }
    if (i.kind === "bind_gateway" || i.kind === "unbind_gateway") {
      const e = w.inventory.engines.find((x) => x.name === i.engine);
      const cur = e?.gateways[i.gateway!.direction];
      const has = cur === i.gateway?.name;
      if (i.kind === "bind_gateway") return { intent_id: i.id, status: has ? "present" : cur ? "replace" : "add", current: null, detail: has ? "Already bound to this gateway." : cur ? `Moves from ${shortName(cur)} to ${shortName(i.gateway!.name)}.` : `Binds ${i.gateway!.direction}; other directions are kept.` };
      return { intent_id: i.id, status: has ? "remove" : "absent", current: null, detail: has ? "Unbinds this direction; the other is kept." : "Not bound to this gateway." };
    }
    if (i.kind === "model_armor_template" || i.kind === "model_armor_extension" || i.kind === "iam_project_grant") {
      const p = i.params ?? {};
      const del = !!p.delete;
      let have = false;
      let what = "";
      if (i.kind === "model_armor_template") {
        have = w.modelArmor.templates.some((t) => t.id === p.template_id);
        what = `template ${p.template_id}`;
      } else if (i.kind === "model_armor_extension") {
        have = w.maExtensions.some((x) => shortName(x.name) === p.name);
        what = `extension ${p.name}`;
      } else {
        const a = w.serviceAgents.find((x) => x.member === p.member);
        const held = (p.roles ?? []).filter((r) => a?.roles[r]);
        const todo = (p.roles ?? []).filter((r) => !a?.roles[r]);
        if (del) return { intent_id: i.id, status: held.length ? "remove" : "absent", current: null, detail: held.length ? `Removes ${held.join(", ")}.` : "Holds none of these roles." };
        return { intent_id: i.id, status: todo.length ? "add" : "present", current: null, detail: todo.length ? `Grants ${todo.join(", ")}.` : "Already holds every role." };
      }
      if (del) return { intent_id: i.id, status: have ? "remove" : "absent", current: null, detail: have ? `Deletes ${what}.` : `${what} doesn't exist.` };
      return { intent_id: i.id, status: have ? "present" : "add", current: null, detail: have ? `${what} already exists.` : `Creates ${what}.` };
    }
    if (i.kind === "set_enforcement" || i.kind === "dedicate_extension") {
      const gw = w.gateways.find((x) => x.name === i.gateway?.name);
      const enf = gw?.enforcement;
      const label = (m?: string | null) => (m === "DRY_RUN" ? "Dry run" : m === "ENFORCE" ? "Enforce" : "unknown");
      if (!enf?.mode) return { intent_id: i.id, status: "absent", current: null, detail: enf?.reason ?? "No IAP enforcement mode on this gateway." };
      if (i.kind === "set_enforcement") {
        const staged = intents.some((x) => x.kind === "dedicate_extension" && !x.revert && x.new_name === shortName(i.extension ?? ""));
        if (staged) return { intent_id: i.id, status: "replace", current: null, current_mode: enf.mode, target_mode: i.mode, detail: `${gw!.id}: ${label(enf.mode)} → ${label(i.mode)} (on its own extension ${shortName(i.extension ?? "")}); other gateways keep their mode` };
        if (enf.mode === i.mode) return { intent_id: i.id, status: "present", current: null, current_mode: enf.mode, target_mode: i.mode, detail: `already ${label(i.mode).toLowerCase()}` };
        const also = enf.shared_with.length && shortName(i.extension ?? "") === shortName(enf.extension) ? `; also ${enf.shared_with.map(shortName).join(", ")} (shared extension)` : "";
        return { intent_id: i.id, status: "replace", current: null, current_mode: enf.mode, target_mode: i.mode, detail: `${gw!.id}: ${label(enf.mode)} → ${label(i.mode)}${also}` };
      }
      if (i.revert) return { intent_id: i.id, status: shortName(enf.extension) === i.new_name ? "remove" : "absent", current: null, detail: shortName(enf.extension) === i.new_name ? `${gw!.id} goes back to ${shortName(i.source_extension ?? "")}; ${i.new_name} is deleted` : `${gw!.id} doesn't use ${i.new_name}` };
      if (shortName(enf.extension) === i.new_name) return { intent_id: i.id, status: "present", current: null, detail: `${gw!.id} already uses ${i.new_name}` };
      return { intent_id: i.id, status: "add", current: null, detail: `creates ${i.new_name} (copy of ${shortName(enf.extension)}, ${label(enf.mode).toLowerCase()}) and points ${gw!.id}'s IAP policy at it${enf.shared_with.length ? `; ${enf.shared_with.map(shortName).join(", ")} keep ${shortName(enf.extension)}` : ""}` };
    }
    const g = w.modelArmor.gateways.find((x) => x.gateway === i.gateway?.name);
    if (i.kind === "model_armor_on") return { intent_id: i.id, status: g?.enabled ? "present" : "add", current: null, detail: g?.enabled ? "Model Armor is already on." : "Creates a CONTENT_AUTHZ policy on the gateway." };
    return { intent_id: i.id, status: g?.enabled ? "remove" : "absent", current: null, detail: g?.enabled ? "Deletes the CONTENT_AUTHZ policy." : "Model Armor is already off." };
  });
  return { items };
}
