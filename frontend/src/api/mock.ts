// Mock handlers (VITE_MOCK=1). Lazily imported by client.ts so the mock never ships in a real build path.
//
// P3 query flags (add to the page URL, e.g. http://localhost:5174/?mode=apply&adc=mismatch):
//   ?mode=generate|apply        run mode (default apply, like a local run)
//   ?adc=ok|missing|mismatch    ADC state (default ok); mismatch = signed in to another project
//   ?fail=1                     the second item of every apply fails
//   ?fast=1                     long-running operations finish in about a second
//   ?writable=partial           you can apply grants/revokes but not gateway or Model Armor changes
// Applied changes are kept in memory (until reload), so Sync shows them.
import type { ApplyConfirm, ApplyEvent, AuthInfo, Binding, Ctx, GatewayLogEntry, GatewayLogsResp, GatewaysResp, Intent, PreflightItem, PreflightResult } from "./types";
import { buildWorld, MOCK_NUMBER, refreshEnforcement, templateFrom, type World } from "./mockData";
import { mockDiff, mockRender } from "./mockRender";
import { ROLE, conditionFor, intentEnglish, intentKey, newId, projectPrincipalSet } from "../lib/policy";
import { NO_IDENTITY_REASON } from "../components/Redeploy";
import { accessFromCondition } from "../lib/grants";

const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

function flags() {
  const q = new URLSearchParams(window.location.search);
  return {
    mode: q.get("mode") === "generate" ? "generate" : "apply",
    adc: (["missing", "mismatch"].includes(q.get("adc") ?? "") ? q.get("adc") : "ok") as "ok" | "missing" | "mismatch",
    fail: q.get("fail") === "1",
    fast: q.get("fast") === "1",
    partial: q.get("writable") === "partial",
  } as const;
}

// ---- in-memory "project": intents applied in this page session, replayed onto a fresh world ----
const applied: Intent[] = [];

// Like the backend's same_condition: IAM tells bindings apart by expression (whitespace-insensitive), not title.
const normExpr = (c: Binding["condition"]) => (c?.expression ?? "").replace(/\s+/g, " ").trim();
const sameCond = (a: Binding["condition"], b: Binding["condition"]) => normExpr(a) === normExpr(b);

const short = (n: string | undefined) => (n ?? "").split("/").pop() ?? "";
const extFull = (source: string, name: string) => source.replace(/\/authzExtensions\/[^/]+$/, `/authzExtensions/${name}`);

function mutate(w: World, i: Intent) {
  if (i.kind === "set_enforcement") {
    const x = w.iapExts.find((e) => short(e.name) === short(i.extension) || (!i.extension && e.gateways.includes(i.gateway?.name ?? "")));
    if (x && i.mode) x.mode = i.mode;
    refreshEnforcement(w.gateways, w.iapExts);
    return;
  }
  if (i.kind === "dedicate_extension") {
    const gw = i.gateway?.name ?? "";
    const src = w.iapExts.find((e) => short(e.name) === short(i.source_extension)) ?? w.iapExts.find((e) => e.gateways.includes(gw));
    const copy = w.iapExts.find((e) => short(e.name) === short(i.new_name));
    if (!i.revert && src && !copy) {
      w.iapExts.push({ name: extFull(src.name, i.new_name ?? "copy"), mode: src.mode, gateways: [gw], policies: { [gw]: src.policies[gw] } });
      src.gateways = src.gateways.filter((g) => g !== gw);
    } else if (i.revert && src && copy) {
      src.gateways.push(gw);
      src.policies[gw] = copy.policies[gw];
      w.iapExts.splice(w.iapExts.indexOf(copy), 1);
    }
    refreshEnforcement(w.gateways, w.iapExts);
    return;
  }
  if (i.kind === "grant" || i.kind === "revoke") {
    const res = i.destination?.name ?? "";
    const cur = (w.inventory.access[res] ??= []);
    const member = i.source?.principal ?? "";
    const cond = conditionFor(i.access);
    if (i.kind === "grant") {
      if (!cur.some((b) => b.member === member && sameCond(b.condition, cond)))
        cur.push({ role: ROLE, member, member_label: i.source?.label ?? member, condition: cond, english: intentEnglish(i) });
    } else {
      // Like the backend: remove only the binding with exactly this condition (no access = the unconditional one).
      w.inventory.access[res] = cur.filter((b) => !(b.member === member && sameCond(b.condition, cond)));
    }
    return;
  }
  const p = i.params ?? {};
  const loc = (proj?: string) => `projects/${proj || w.GP}/locations/${w.R}`;
  if (i.kind === "model_armor_template") {
    const name = `${loc(p.project)}/templates/${p.template_id}`;
    w.modelArmor.templates = w.modelArmor.templates.filter((t) => t.name !== name);
    if (!p.delete) w.modelArmor.templates.push(templateFrom(name, p.filters ?? { pi_jailbreak: "MEDIUM_AND_ABOVE", sdp: "basic", rai: {}, malicious_uri: true }, p.block_message));
    return;
  }
  if (i.kind === "model_armor_extension") {
    const name = `${loc(p.project)}/authzExtensions/${p.name}`;
    const keep = w.maExtensions.filter((x) => x.name !== name);
    w.maExtensions.splice(0, w.maExtensions.length, ...keep);
    if (!p.delete) w.maExtensions.push({ name, templates: [p.template?.startsWith("projects/") ? p.template : `${loc(p.project)}/templates/${p.template}`] });
    return;
  }
  if (i.kind === "iam_project_grant") {
    const a = w.serviceAgents.find((x) => x.member === p.member || x.email === p.member);
    if (a) for (const r of p.roles ?? []) a.roles[r] = !p.delete;
    return;
  }
  const gwName = i.gateway?.name ?? "";
  if (i.kind === "bind_gateway" || i.kind === "unbind_gateway") {
    const dir = i.gateway!.direction;
    const e = w.inventory.engines.find((x) => x.name === i.engine);
    if (!e) return;
    for (const g of w.gateways) g.bound_engines = g.bound_engines.filter((b) => !(b.engine === e.name && b.direction === dir));
    if (i.kind === "bind_gateway") {
      e.gateways[dir] = gwName;
      w.gateways.find((g) => g.name === gwName)?.bound_engines.push({ engine: e.name, display_name: e.display_name, direction: dir });
    } else delete e.gateways[dir];
    return;
  }
  const ma = w.modelArmor.gateways.find((x) => x.gateway === gwName);
  const gw = w.gateways.find((g) => g.name === gwName);
  if (!ma || !gw) return;
  const base = gwName.replace(/\/agentGateways\/.*/, "");
  if (i.kind === "model_armor_on") {
    const ext = w.maExtensions.find((x) => x.name === i.gateway?.extension) ?? w.maExtensions[0];
    ma.enabled = true;
    ma.template = w.modelArmor.templates.find((t) => t.name === ext?.templates[0]) ?? w.modelArmor.templates[0] ?? null;
    ma.policy = `${base}/authzPolicies/${gw.id}-ma-policy`;
    ma.extension = ext?.name ?? `${base}/authzExtensions/corp-ma-authz`;
    if (!gw.authz_policies.some((p) => p.profile === "CONTENT_AUTHZ"))
      gw.authz_policies.push({ name: ma.policy, profile: "CONTENT_AUTHZ", provider: "model_armor", extension: ma.extension, enforcement: "ENFORCE" });
  } else {
    ma.enabled = false;
    ma.template = null;
    ma.policy = null;
    ma.extension = null;
    gw.authz_policies = gw.authz_policies.filter((p) => p.profile !== "CONTENT_AUTHZ");
  }
}

function world(ctx: Ctx): World {
  const w = buildWorld(ctx);
  for (const i of applied) mutate(w, i);
  return w;
}

export const context = (ctx: Ctx) => {
  const c = world(ctx).context();
  const f = flags();
  const canWrite = f.mode === "apply" && f.adc !== "missing";
  const P = c.project;
  // Write permissions share role grants, so the UI can show one command for several permissions.
  c.permissions = [
    ...c.permissions.filter((p) => !p.permission.endsWith("setIamPolicy") && !p.permission.endsWith("reasoningEngines.update")),
    { permission: "iap.webServices.setIamPolicy", granted: canWrite, write: true, role: "roles/iap.admin", needed_for: "Apply grants and revokes", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/iap.admin` },
    { permission: "iap.webServices.getIamPolicy", granted: true, write: false, role: "roles/iap.admin", needed_for: "Read back grants after Apply" },
    { permission: "aiplatform.reasoningEngines.update", granted: canWrite, write: true, role: "roles/aiplatform.admin", needed_for: "Bind and unbind agents to gateways", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/aiplatform.admin` },
    { permission: "aiplatform.reasoningEngines.get", granted: canWrite, write: true, role: "roles/aiplatform.admin", needed_for: "Read back gateway bindings after Apply", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/aiplatform.admin` },
    { permission: "networksecurity.authzPolicies.create", granted: canWrite, write: true, role: "roles/networksecurity.admin", needed_for: "Turn Model Armor on", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/networksecurity.admin` },
    { permission: "networksecurity.authzPolicies.delete", granted: canWrite, write: true, role: "roles/networksecurity.admin", needed_for: "Turn Model Armor off", fix: `gcloud projects add-iam-policy-binding ${P} --member=user:alex.admin@example.com --role=roles/networksecurity.admin` },
  ];
  const a = auth(ctx);
  c.can_apply = a.can_apply;
  c.can_apply_reason = a.can_apply_reason;
  return c;
};
export const gateways = (ctx: Ctx): GatewaysResp => ({
  gateways: clone(world(ctx).gateways),
  notes: [
    "Agent Runtime allows one egress and one ingress gateway per project and region.",
    "Agent Runtime agents created before 2026-04-29 can't be bound to a gateway.",
  ],
});
/** Like logs.is_platform in the backend: the agent runtime's own traffic, by host. */
function isPlatformHost(host: string, registered: boolean): boolean {
  const h = host.toLowerCase().replace(/:\d+$/, "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.startsWith("[") || h.endsWith(".google.internal") || /^[a-z0-9-]*aiplatform[a-z0-9.-]*\.googleapis\.com$/.test(h)) return true;
  return !registered && h.endsWith(".googleapis.com");
}

/** Like dryrun.check in the backend: would the caller's current roles/iap.egressor grants on the destination allow
 *  this call? [decision, reason]. Conditions other than tools-by-name and read-only-by-hint give "unknown". */
function mockCheck(w: World, caller: { display_name: string; principal: string } | null, destName: string, tool: string | null): ["allowed" | "would_deny" | "unknown", string] {
  const inv = w.inventory;
  const item = [...inv.agents, ...inv.mcp_servers, ...inv.endpoints].find((x) => x.name === destName);
  const dest = item?.display_name ?? short(destName);
  if (!caller) return ["unknown", "The log entry doesn't name the caller, and its client certificate didn't match an agent bound to this gateway."];
  const projectSet = projectPrincipalSet(caller.principal, undefined);
  const mcp = inv.mcp_servers.find((m) => m.name === destName);
  const limited: string[] = [];
  for (const b of inv.access[destName] ?? []) {
    if (b.role !== ROLE) continue;
    const through = b.member === caller.principal ? "" : b.member === projectSet || b.member === "allUsers" || b.member === "allAuthenticatedUsers" ? ` through ${b.member_label}` : null;
    if (through === null) continue;
    const acc = accessFromCondition(b.condition?.expression);
    const ok =
      acc?.mode === "all" ? true
      : acc?.mode === "tools" ? !tool || (acc.tools ?? []).includes(tool)
      : acc?.mode === "read_only_hint" ? (!tool ? true : (mcp?.tools.find((t) => t.name === tool)?.read_only ?? null))
      : null;
    const cond = b.condition ? ` (condition: ${b.condition.title || b.condition.expression})` : "";
    if (ok) return ["allowed", `${caller.display_name} holds roles/iap.egressor on ${dest}${through}${cond}.`];
    if (ok === null) return ["unknown", `The condition on ${caller.display_name}'s grant on ${dest} can't be evaluated here${cond}.`];
    limited.push(b.condition?.title ?? "");
  }
  if (limited.length) return ["would_deny", `${caller.display_name}'s roles/iap.egressor grant on ${dest} is limited (${limited.join("; ")}) and doesn't cover ${tool ?? "this call"}.`];
  return ["would_deny", `${caller.display_name} holds no roles/iap.egressor grant on ${dest} (or on the whole Agent Registry).`];
}

/** Mirrors GET /gateway-logs. Every call is logged as allowed on a dry-run gateway (as Google does); would-deny is
 *  computed from the current grants. On an enforcing gateway the same calls are logged allowed / denied (403). */
export function gatewayLogs(ctx: Ctx, gateway: string, since: string): GatewayLogsResp {
  const w = world(ctx);
  const g = w.gateways.find((x) => x.name === gateway || x.id === short(gateway));
  const dry = g?.type === "egress" && g?.enforcement?.mode === "DRY_RUN";
  const bound = (g?.bound_engines ?? []).filter((b) => b.direction === g?.type);
  const engines = bound.map((b) => w.inventory.engines.find((e) => e.name === b.engine)).filter((e): e is NonNullable<typeof e> => !!e);
  const now = Date.now();
  const byId = (coll: { name: string; id: string }[], id: string) => coll.find((x) => x.id === id)?.name ?? "";
  // [minutes ago, caller engine (index into the bound agents; -1 = certificate not recognized), destination, tool, host]
  // Destination "" = no agentRegistryResource (the platform's internal address 240.0.0.2, seen live).
  const aip = `${w.R}-aiplatform.mtls.googleapis.com`;
  const calls: [number, number, string, string | null, string][] = [
    [1, 0, "", null, "240.0.0.2:443"],
    [2, 0, byId(w.inventory.endpoints, "aiplatform-googleapis"), null, aip],
    [3, 0, byId(w.inventory.endpoints, "aiplatform-googleapis"), null, aip],
    [7, 1, "", null, "240.0.0.2:443"],
    [12, 1, byId(w.inventory.endpoints, "aiplatform-googleapis"), null, aip],
    [33, 0, "", null, "240.0.0.2:443"],
    [4, 0, byId(w.inventory.mcp_servers, "tickets-mcp-6a21"), "close_ticket", "tickets-mcp-a1b2c3-uk.a.run.app"],
    [9, 1, byId(w.inventory.mcp_servers, "tickets-mcp-6a21"), "get_ticket", "tickets-mcp-a1b2c3-uk.a.run.app"],
    [17, 1, byId(w.inventory.mcp_servers, "tickets-mcp-6a21"), "update_ticket", "tickets-mcp-a1b2c3-uk.a.run.app"],
    [26, 0, byId(w.inventory.endpoints, "aiplatform-googleapis"), null, `${w.R}-aiplatform.googleapis.com`],
    [48, 0, byId(w.inventory.agents, "billing-agent-91d0"), null, "billing-agent-d4e5f6-uk.a.run.app"],
    [95, 1, byId(w.inventory.mcp_servers, "hr-directory-mcp-0f3c"), "delete_employee_record", "hr-directory-mcp-a1b2c3-uk.a.run.app"],
    [130, -1, byId(w.inventory.mcp_servers, "tickets-mcp-6a21"), "list_tickets", "tickets-mcp-a1b2c3-uk.a.run.app"],
    [240, 0, byId(w.inventory.agents, "kb-agent-4c1e"), null, "kb-agent-a1b2c3-uk.a.run.app"],
  ];
  const regRes = (name: string) => name.replace(/^projects\/[^/]+\//, `projects/${MOCK_NUMBER}/`);
  const entries: GatewayLogEntry[] = !g
    ? []
    : calls
        .filter(([, who]) => who < engines.length)
        .map(([min, who, destName, tool, host]) => {
          const eng = who >= 0 ? engines[who] : engines.length === 1 ? engines[0] : null;
          const how = who >= 0 && engines.length > 1 ? ("mtls" as const) : ("only_bound_agent" as const);
          const platform = isPlatformHost(host, !!destName);
          const [verdict, reason]: [GatewayLogEntry["decision"], string] =
            !destName && platform ? ["platform", `Platform traffic (${host}): the agent runtime's own call, with no Agent Registry resource, so no roles/iap.egressor grant applies. Not checked.`] : mockCheck(w, eng ?? null, destName, tool);
          const decision: GatewayLogEntry["decision"] = dry ? verdict : verdict === "would_deny" ? "denied" : "allowed";
          const ts = new Date(now - min * 60_000).toISOString();
          const insert = `mock${min}${decision}`;
          const logged = decision === "denied" ? "DENIED" : "ALLOWED";
          return {
            decision,
            status: decision === "denied" ? 403 : 200,
            host,
            mcp_tool: tool,
            mcp_method: tool ? "tools/call" : null,
            registry_resource: destName ? regRes(destName) : null,
            destination: destName ? short(destName) : host,
            policies: [{ name: g.enforcement?.policy ?? "", result: logged }],
            authz_result: logged,
            timestamp: ts,
            method: "POST",
            url: `https://${host}/mcp`,
            insert_id: insert,
            console_url: `https://console.cloud.google.com/logs/query;query=insertId%3D%22${insert}%22?project=${encodeURIComponent(w.GP)}`,
            agent: eng?.display_name ?? null,
            agent_inferred: !!eng,
            caller: eng ? { engine: eng.name, display_name: eng.display_name, how } : null,
            client_cert: who >= 0 ? `mock-cert-${who}` : "mock-cert-unknown",
            computed: dry,
            reason: dry ? reason : null,
            platform,
          };
        });
  const counts = { allowed: 0, denied: 0, would_deny: 0, unknown: 0, platform: 0 };
  for (const e of entries) counts[e.decision]++;
  const filter = `logName="projects/${w.GP}/logs/networkservices.googleapis.com%2Fgateway_requests" AND resource.labels.gateway_name="${short(gateway)}"`;
  return {
    gateway: short(gateway),
    since: new Date(now - 24 * 3600_000).toISOString(),
    filter,
    entries,
    counts,
    // Like a live dry-run gateway: the newest entries were mostly platform calls, and the platform-free second query
    // covered the rest of the window.
    truncated: dry,
    checked_truncated: false,
    console_url: `https://console.cloud.google.com/logs/query;query=${encodeURIComponent(filter)}?project=${encodeURIComponent(w.GP)}`,
    notes: [`Mock log entries (since ${since}).`, ...(dry ? ["Older platform calls (aiplatform*.googleapis.com, IPv4 hosts) were left out; every non-platform entry of the window was checked."] : [])],
    errors: [],
    dry_run: dry,
  };
}

export const modelArmor = (ctx: Ctx) => {
  const w = world(ctx);
  return clone({ ...w.modelArmor, extensions: w.maExtensions, setup: w.setup() });
};
export const inventory = (ctx: Ctx) => clone(world(ctx).inventory);
export const audit = (ctx: Ctx) => {
  const w = world(ctx);
  const a = w.audit();
  // A finding whose fix is already in place disappears, like the real audit after Sync.
  a.findings = a.findings.filter((f) => !f.fix || !["present", "absent"].includes(mockDiff(w, [f.fix]).items[0].status));
  return a;
};
export const render = (ctx: Ctx, intents: Intent[]) => {
  const r = mockRender(ctx, world(ctx), intents);
  const first = new Map<string, string>();
  for (const i of intents) {
    const k = intentKey(i);
    const item = r.items.find((x) => x.intent_id === i.id);
    if (first.has(k) && item) item.warnings.push(`Same change as item ${first.get(k)} earlier in the cart: left out of the bundle (it's applied once).`);
    else first.set(k, i.id);
    const e = world(ctx).inventory.engines.find((x) => x.name === i.engine);
    if (i.kind === "bind_gateway" && e && !e.bindable && item) {
      item.error = `${e.display_name} can't be bound to Agent Gateway. ${e.bindable_reason ?? ""}`;
    }
  }
  return r;
};

/** Mirrors POST /preflight: duplicates, and items that would certainly fail. */
export function preflight(ctx: Ctx, intents: Intent[]): PreflightResult {
  const w = world(ctx);
  const a = auth(ctx);
  const seen = new Map<string, string>();
  const extStaged = intents.some((i) => i.kind === "model_armor_extension" && !i.params?.delete);
  const staged = intents.filter((i) => i.kind === "model_armor_extension" && !i.params?.delete).map((i) => `projects/${i.params?.project || w.GP}/locations/${ctx.region}/authzExtensions/${i.params?.name}`);
  const items: PreflightItem[] = intents.map((i) => {
    const k = intentKey(i);
    if (seen.has(k)) return { intent_id: i.id, status: "duplicate", duplicate_of: seen.get(k), reason: `Same change as ${seen.get(k)}; applied once.` };
    seen.set(k, i.id);
    if (a.writable?.[i.kind] === false) return { intent_id: i.id, status: "blocked", fix: "permission", reason: `You don't have permission for this kind of change in ${ctx.project} (see the “can write” check on Context for the role to ask for).` };
    const e = w.inventory.engines.find((x) => x.name === i.engine);
    if (i.kind === "bind_gateway" && e && !e.bindable) return { intent_id: i.id, status: "blocked", fix: "redeploy", reason: `${e.display_name} can't be bound to Agent Gateway. ${e.bindable_reason ?? ""}` };
    if (i.kind === "set_enforcement" || i.kind === "dedicate_extension") {
      const g = w.gateways.find((x) => x.name === i.gateway?.name);
      const enf = g?.enforcement;
      const stagedCopy = intents.some((x) => x.kind === "dedicate_extension" && !x.revert && x.new_name && short(i.extension) === x.new_name);
      if (i.kind === "set_enforcement" && stagedCopy) return { intent_id: i.id, status: "ok" };
      if (!enf?.editable) return { intent_id: i.id, status: "blocked", fix: "", reason: `${g?.id ?? short(i.gateway?.name)} has no IAP REQUEST_AUTHZ policy, so it has no enforcement mode to change.` };
      if (i.kind === "set_enforcement" && enf.mode === i.mode)
        return { intent_id: i.id, status: "blocked", fix: "already", reason: `Already ${i.mode === "ENFORCE" ? "enforcing" : "in dry run"}: ${short(enf.extension)} on ${g!.id} is in that mode, so there is nothing to change.` };
      if (i.kind === "dedicate_extension" && !i.revert && w.iapExts.some((x) => short(x.name) === i.new_name))
        return { intent_id: i.id, status: "blocked", fix: "", reason: `An authz extension named ${i.new_name} already exists in ${ctx.region}; pick another name.` };
      if (i.kind === "set_enforcement" && i.scope === "shared" && enf.shared_with.length)
        return { intent_id: i.id, status: "ok", warning: `${short(enf.extension)} also controls ${enf.shared_with.map(short).join(", ")}: they switch to ${i.mode === "ENFORCE" ? "enforce" : "dry run"} too.` };
      return { intent_id: i.id, status: "ok" };
    }
    const ext = i.gateway?.extension;
    const extOk = ext ? w.maExtensions.some((x) => x.name === ext) || staged.includes(ext) : extStaged || w.maExtensions.length > 0;
    if (i.kind === "model_armor_on" && !extOk)
      return {
        intent_id: i.id,
        status: "blocked",
        fix: "ma_setup",
        reason: `Model Armor isn't set up in ${ctx.region} yet: ${ext ? `the extension ${ext.split("/").pop()} doesn't exist` : "there's no Model Armor authz extension for this gateway to use"}, and none is staged in this cart. Set it up first (template, extension, service agent roles).`,
      };
    return { intent_id: i.id, status: "ok" };
  });
  return { items };
}
export const diff = (ctx: Ctx, intents: Intent[]) => mockDiff(world(ctx), intents);

// ---- /auth ----
export function auth(ctx: Ctx): AuthInfo {
  const f = flags();
  const P = ctx.project || "my-demo-project";
  const acct = "alex.admin@example.com";
  const GP = ctx.gateway_project || P;
  const all = (v: boolean) => ({ grant: v, revoke: v, bind_gateway: v, unbind_gateway: v, model_armor_on: v, model_armor_off: v });
  if (f.mode === "generate")
    return {
      mode: "generate",
      runtime: "cloud_run",
      adc: { ok: true, type: "compute_engine", account: "policy-studio@" + P + ".iam.gserviceaccount.com", quota_project: null, adc_project: P, source: "metadata server", error: null },
      gcloud: { available: false, account: null, project: null },
      target_project: P,
      gateway_project: GP,
      writable: all(false),
      checks: [
        { id: "adc_present", status: "ok", title: "Credentials found", detail: "Using the Cloud Run service account from the metadata server." },
        { id: "adc_valid", status: "ok", title: "Credentials work", detail: "The access token refreshed." },
      ],
      can_apply: false,
      can_apply_reason: "Generate-only mode (Cloud Run service account)",
    };
  if (f.adc === "missing")
    return {
      mode: "apply",
      runtime: "local",
      adc: { ok: false, type: "unknown", account: null, quota_project: null, adc_project: null, source: null, error: "Your default credentials were not found." },
      gcloud: { available: true, account: acct, project: P },
      target_project: P,
      gateway_project: GP,
      writable: all(false),
      // The backend omits the checks that depend on ADC when it's missing.
      checks: [
        { id: "adc_present", status: "error", title: "No Application Default Credentials", detail: "Policy Studio applies changes with ADC, which is separate from your gcloud login. Sign in once to create it.", fix: "gcloud auth application-default login" },
      ],
      can_apply: false,
      can_apply_reason: "No Application Default Credentials. Run: gcloud auth application-default login",
    };
  const other = f.adc === "mismatch" ? "alex-sandbox" : P;
  const checks: AuthInfo["checks"] = [
    { id: "adc_present", status: "ok", title: "Credentials found", detail: "~/.config/gcloud/application_default_credentials.json" },
    { id: "adc_valid", status: "ok", title: "Credentials work", detail: "The access token refreshed." },
    { id: "account_matches_gcloud", status: "ok", title: "Same account as gcloud", detail: `ADC and gcloud both use ${acct}.` },
    other === P
      ? { id: "quota_project", status: "ok", title: "Quota project", detail: `API quota is billed to ${P}.` }
      : { id: "quota_project", status: "warn", title: "Quota project is a different project", detail: `API quota is billed to ${other}, not ${P}. That usually works, but set it to the target to avoid surprises.`, fix: `gcloud auth application-default set-quota-project ${P}` },
    other === P
      ? { id: "project_matches", status: "ok", title: "Working on your current project", detail: `gcloud and ADC point at ${P}.` }
      : { id: "project_matches", status: "warn", title: "Signed in to a different project", detail: `gcloud and ADC point at ${other}, but you're working on ${P}. Apply always targets ${P} explicitly.`, fix: `gcloud config set project ${P}` },
    f.partial
      ? {
          id: "can_write",
          status: "warn",
          title: "You can apply some kinds of change",
          detail: `You can apply grants and revokes, but not gateway bindings or Model Armor changes in ${P}.`,
          fix: `gcloud projects add-iam-policy-binding ${P} --member=user:${acct} --role=roles/aiplatform.admin\ngcloud projects add-iam-policy-binding ${GP} --member=user:${acct} --role=roles/networksecurity.admin`,
        }
      : { id: "can_write", status: "ok", title: "You can make these changes", detail: `testIamPermissions on ${P} returned every write permission Apply needs.` },
  ];
  return {
    mode: "apply",
    runtime: "local",
    adc: { ok: true, type: "user", account: acct, quota_project: other, adc_project: other, source: "~/.config/gcloud/application_default_credentials.json", error: null },
    gcloud: { available: true, account: acct, project: other },
    target_project: P,
    gateway_project: GP,
    writable: f.partial ? { ...all(true), bind_gateway: false, unbind_gateway: false, model_armor_on: false, model_armor_off: false } : all(true),
    checks,
    can_apply: true,
    can_apply_reason: null,
  };
}

// ---- /apply (streamed) ----
class HttpErr extends Error {
  status: number;
  constructor(status: number, m: string) {
    super(m);
    this.status = status;
  }
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((res, rej) => {
    const t = setTimeout(res, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      rej(new DOMException("Aborted", "AbortError"));
    });
  });

const DESTRUCTIVE = new Set<Intent["kind"]>(["revoke", "unbind_gateway", "model_armor_off"]);
const SETUP = new Set<Intent["kind"]>(["model_armor_template", "model_armor_extension", "iam_project_grant"]);
const destructive = (i: Intent) =>
  DESTRUCTIVE.has(i.kind) || (SETUP.has(i.kind) && !!i.params?.delete) || (i.kind === "set_enforcement" && i.mode === "DRY_RUN") || (i.kind === "dedicate_extension" && !!i.revert);
// Like the backend: setup creates first, then dedicated IAP extensions, then the cart order, then reverts, then setup deletes in reverse.
const runOrder = (i: Intent) =>
  i.params?.delete
    ? ({ iam_project_grant: 6, model_armor_extension: 7, model_armor_template: 8 } as Record<string, number>)[i.kind] ?? 4
    : i.kind === "dedicate_extension" && i.revert
      ? 5
      : ({ model_armor_template: 0, model_armor_extension: 1, iam_project_grant: 2, dedicate_extension: 3 } as Record<string, number>)[i.kind] ?? 4;

/** The inverse of an intent, given the world before it was applied. */
function inverse(w: World, i: Intent): Intent | Intent[] | null {
  const id = () => newId("u");
  switch (i.kind) {
    case "grant": {
      const cond = conditionFor(i.access);
      return { id: id(), kind: "revoke", source: i.source, destination: i.destination, access: cond ? { mode: "custom", expression: cond.expression, title: cond.title } : { mode: "all" } };
    }
    case "revoke": {
      const cur = w.inventory.access[i.destination?.name ?? ""] ?? [];
      const want = conditionFor(i.access);
      const removed = cur.filter((b) => b.member === i.source?.principal && sameCond(b.condition, want));
      return removed.map((b) => ({
        id: id(),
        kind: "grant" as const,
        source: i.source,
        destination: i.destination,
        access: b.condition ? { mode: "custom" as const, expression: b.condition.expression, title: b.condition.title } : { mode: "all" as const },
      }));
    }
    case "bind_gateway": {
      const e = w.inventory.engines.find((x) => x.name === i.engine);
      const prev = e?.gateways[i.gateway!.direction];
      return prev
        ? { id: id(), kind: "bind_gateway", engine: i.engine, engine_label: i.engine_label, gateway: { name: prev, direction: i.gateway!.direction } }
        : { id: id(), kind: "unbind_gateway", engine: i.engine, engine_label: i.engine_label, gateway: i.gateway };
    }
    case "unbind_gateway":
      return { id: id(), kind: "bind_gateway", engine: i.engine, engine_label: i.engine_label, gateway: i.gateway };
    case "model_armor_on":
      return { id: id(), kind: "model_armor_off", gateway: i.gateway };
    case "model_armor_off":
      return { id: id(), kind: "model_armor_on", gateway: i.gateway };
    case "model_armor_template":
    case "model_armor_extension":
      return { ...i, id: id(), params: { ...i.params, delete: !i.params?.delete } };
    case "iam_project_grant": {
      const a = w.serviceAgents.find((x) => x.member === i.params?.member);
      const changed = (i.params?.roles ?? []).filter((r) => (a?.roles[r] ?? false) === !!i.params?.delete);
      return { ...i, id: id(), params: { ...i.params, roles: changed, delete: !i.params?.delete } };
    }
    case "set_enforcement": {
      const x = w.iapExts.find((e) => short(e.name) === short(i.extension));
      return { ...i, id: id(), mode: x?.mode ?? (i.mode === "ENFORCE" ? "DRY_RUN" : "ENFORCE") };
    }
    case "dedicate_extension":
      return { ...i, id: id(), revert: !i.revert };
  }
}

export async function* applyStream(ctx: Ctx, intents: Intent[], confirm: ApplyConfirm, signal?: AbortSignal): AsyncGenerator<ApplyEvent> {
  const a = auth(ctx);
  await sleep(300, signal);
  if (!a.can_apply) throw new HttpErr(403, a.can_apply_reason ?? "Apply is not available.");
  if (confirm.project !== ctx.project) throw new HttpErr(400, `confirm.project must equal ${ctx.project}.`);
  if (intents.some(destructive) && !confirm.acknowledge_destructive) throw new HttpErr(400, "Destructive changes need acknowledge_destructive: true.");
  const f = flags();
  const counts = { verified: 0, failed: 0, skipped: 0, blocked: 0 };
  // Like the backend: duplicates are skipped and certain failures are refused before any change.
  const pre = new Map(preflight(ctx, intents).items.map((p) => [p.intent_id, p]));
  for (const i of intents) {
    const p = pre.get(i.id);
    if (p?.status === "duplicate") {
      counts.skipped++;
      yield { intent_id: i.id, state: "skipped", detail: p.reason };
    } else if (p?.status === "blocked") {
      counts.failed++;
      counts.blocked++;
      yield { intent_id: i.id, state: "failed", detail: `Blocked before any change: ${p.reason}`, blocked: true, fix: p.fix };
    }
  }
  intents = intents.filter((i) => pre.get(i.id)?.status === "ok" || !pre.get(i.id));
  // Like the backend: a flip of a copy that a revert in this request deletes is skipped, and a flip of a copy that a
  // dedicate in this request created gets no undo (the dedicate's revert undoes both).
  const reverted = new Set(intents.filter((i) => i.kind === "dedicate_extension" && i.revert).map((i) => i.new_name));
  const created = new Set<string>();
  for (const [n, i] of [...intents].sort((a, b) => runOrder(a) - runOrder(b)).entries()) {
    const w = world(ctx);
    const d = mockDiff(w, [i]).items[0];
    yield { intent_id: i.id, state: "running", detail: "Applying…" };
    if (i.kind === "set_enforcement" && reverted.has(short(i.extension))) {
      await sleep(300, signal);
      counts.skipped++;
      yield { intent_id: i.id, state: "skipped", detail: `Not needed: ${short(i.extension)} is deleted by the revert in this request.` };
      continue;
    }
    if (d.status === "present" || d.status === "absent") {
      await sleep(400, signal);
      counts.skipped++;
      yield { intent_id: i.id, state: "skipped", detail: d.status === "present" ? "Already in place; nothing changed." : "Nothing to remove; nothing changed." };
      continue;
    }
    if (i.kind === "model_armor_on" && !w.maExtensions.length) {
      await sleep(400, signal);
      counts.failed++;
      yield { intent_id: i.id, state: "failed", detail: `Model Armor isn't set up in ${ctx.region} yet (no Model Armor authz extension). Stage the setup (template, extension, service agent roles) with this item, then apply again.` };
      continue;
    }
    const lro = !["grant", "revoke", "model_armor_template", "iam_project_grant"].includes(i.kind);
    const op = lro ? `projects/${ctx.project}/locations/${ctx.region}/operations/operation-${Date.now()}-${Math.random().toString(16).slice(2, 10)}` : undefined;
    if (lro)
      yield {
        intent_id: i.id,
        state: "running",
        detail: i.kind === "set_enforcement" || i.kind === "dedicate_extension" ? "Waiting for the authz extension / policy operation…" : i.kind === "model_armor_extension" ? "Waiting for the authz extension operation…" : i.kind.startsWith("model_armor") ? "Waiting for the authz policy operation…" : "Waiting for the agent update operation…",
        operation: op,
      };
    if (lro) {
      // Like the backend: repeated "done" + progress events while the operation is polled.
      const total = f.fast ? 1200 : i.kind.startsWith("model_armor") ? 6000 : 7000;
      const t0 = Date.now();
      while (Date.now() - t0 < total) {
        await sleep(Math.min(1500, total - (Date.now() - t0)), signal);
        const s = Math.round((Date.now() - t0) / 1000);
        yield { intent_id: i.id, state: "done", progress: true, detail: `Operation running (${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")})…`, operation: op };
      }
    } else await sleep(1100, signal);
    if (f.fail && n === 1) {
      counts.failed++;
      // Friendly text with the raw Google Cloud error kept, like the backend.
      yield i.kind === "bind_gateway"
        ? { intent_id: i.id, state: "failed", detail: NO_IDENTITY_REASON, raw_error: "HTTP 400: Reasoning Engine with agent_gateway_config must use AGENT_IDENTITY identity type.", operation: op }
        : {
            intent_id: i.id,
            state: "failed",
            detail: lro ? "Another change to this resource is still running. Wait a few minutes and try again." : "The policy changed while it was being updated (someone else edited it). Try again.",
            raw_error: lro ? "Operation failed: FAILED_PRECONDITION: the agent is being updated by another operation." : "HTTP 409: ABORTED: There were concurrent policy changes.",
            operation: op,
          };
      continue;
    }
    const fresh = i.kind === "set_enforcement" && created.has(short(i.extension));
    const undo = fresh ? null : inverse(w, i);
    if (i.kind === "dedicate_extension" && !i.revert && i.new_name) created.add(i.new_name);
    applied.push(structuredClone(i));
    yield { intent_id: i.id, state: "done", detail: lro ? "Operation finished. Reading back…" : "setIamPolicy succeeded. Reading back…", operation: op };
    await sleep(lro ? 1300 : 600, signal);
    counts.verified++;
    yield {
      intent_id: i.id,
      state: "verified",
      detail:
        i.kind === "grant"
          ? "Read back: the binding is there."
          : i.kind === "revoke"
            ? "Read back: the binding is gone."
            : i.kind.endsWith("gateway")
              ? "Read back: agentGatewayConfig matches."
              : i.kind === "set_enforcement"
                ? `Read back: ${short(i.extension)} is in ${i.mode === "DRY_RUN" ? "dry run (failOpen true)" : "enforce (failOpen false)"}. Takes effect in about 2–3 minutes (measured), sometimes before the operation reports done.${fresh ? ` Undo: revert giving the gateway its own extension (deletes ${short(i.extension)}).` : ""}`
                : i.kind === "dedicate_extension"
                  ? i.revert
                    ? `Read back: ${short(i.gateway?.name)} uses ${short(i.source_extension)} again and ${i.new_name} is gone.`
                    : `Read back: ${short(i.gateway?.name)}'s IAP policy uses ${i.new_name}.`
              : i.kind === "model_armor_template"
                ? `Read back: template ${i.params?.template_id} ${i.params?.delete ? "is gone" : "exists"}.`
                : i.kind === "model_armor_extension"
                  ? `Read back: extension ${i.params?.name} ${i.params?.delete ? "is gone" : "screens with " + (i.params?.template ?? "").split("/").pop()}.`
                  : i.kind === "iam_project_grant"
                    ? `Read back: the service agent ${i.params?.delete ? "no longer holds" : "holds"} ${(i.params?.roles ?? []).join(", ")}.`
                    : "Read back: the CONTENT_AUTHZ policy matches.",
      operation: op,
      undo,
    };
  }
  yield { type: "done", summary: counts };
}
