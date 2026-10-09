// Mock handlers (VITE_MOCK=1). Lazily imported by client.ts so the mock never ships in a real build path.
//
// P3 query flags (add to the page URL, e.g. http://localhost:5174/?mode=apply&adc=mismatch):
//   ?mode=generate|apply        run mode (default apply, like a local run)
//   ?adc=ok|missing|mismatch    ADC state (default ok); mismatch = signed in to another project
//   ?fail=1                     the second item of every apply fails
//   ?fast=1                     long-running operations finish in about a second
//   ?writable=partial           you can apply grants/revokes but not gateway or Model Armor changes
// Applied changes are kept in memory (until reload), so Sync shows them.
import type { ApplyConfirm, ApplyEvent, AuthInfo, Binding, Ctx, GatewaysResp, Intent, PreflightItem, PreflightResult } from "./types";
import { buildWorld, templateFrom, type World } from "./mockData";
import { mockDiff, mockRender } from "./mockRender";
import { ROLE, conditionFor, intentEnglish, intentKey, newId } from "../lib/policy";
import { NO_IDENTITY_REASON } from "../components/Redeploy";

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

const sameCond = (a: Binding["condition"], b: Binding["condition"]) => (a?.expression ?? "") === (b?.expression ?? "");

function mutate(w: World, i: Intent) {
  if (i.kind === "grant" || i.kind === "revoke") {
    const res = i.destination?.name ?? "";
    const cur = (w.inventory.access[res] ??= []);
    const member = i.source?.principal ?? "";
    if (i.kind === "grant") {
      const cond = i.access?.mode === "custom" && i.access.title ? { title: i.access.title, expression: i.access.expression ?? "" } : conditionFor(i.access);
      if (!cur.some((b) => b.member === member && sameCond(b.condition, cond)))
        cur.push({ role: ROLE, member, member_label: i.source?.label ?? member, condition: cond, english: intentEnglish(i) });
    } else {
      w.inventory.access[res] = cur.filter((b) => !(b.member === member && (i.access?.title === undefined || (b.condition?.title ?? "") === i.access.title)));
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
const destructive = (i: Intent) => DESTRUCTIVE.has(i.kind) || (SETUP.has(i.kind) && !!i.params?.delete);
// Like the backend: setup creates first, then the cart order, then setup deletes in reverse.
const runOrder = (i: Intent) =>
  i.params?.delete ? ({ iam_project_grant: 4, model_armor_extension: 5, model_armor_template: 6 } as Record<string, number>)[i.kind] ?? 3 : ({ model_armor_template: 0, model_armor_extension: 1, iam_project_grant: 2 } as Record<string, number>)[i.kind] ?? 3;

/** The inverse of an intent, given the world before it was applied. */
function inverse(w: World, i: Intent): Intent | Intent[] | null {
  const id = () => newId("u");
  switch (i.kind) {
    case "grant": {
      const cond = conditionFor(i.access);
      return { id: id(), kind: "revoke", source: i.source, destination: i.destination, access: { mode: i.access?.mode ?? "all", title: cond?.title ?? "" } };
    }
    case "revoke": {
      const cur = w.inventory.access[i.destination?.name ?? ""] ?? [];
      const removed = cur.filter((b) => b.member === i.source?.principal && (i.access?.title === undefined || (b.condition?.title ?? "") === i.access.title));
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
  for (const [n, i] of [...intents].sort((a, b) => runOrder(a) - runOrder(b)).entries()) {
    const w = world(ctx);
    const d = mockDiff(w, [i]).items[0];
    yield { intent_id: i.id, state: "running", detail: "Applying…" };
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
        detail: i.kind === "model_armor_extension" ? "Waiting for the authz extension operation…" : i.kind.startsWith("model_armor") ? "Waiting for the authz policy operation…" : "Waiting for the agent update operation…",
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
    const undo = inverse(w, i);
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
