// Agent Registry entries (registry_service): the "Register a new destination" form, its checks, the intents it
// stages (the create, and a grant on the new entry that depends on it), the inventory's "Delete entry", and the
// private-domain hint. Pure. The checks mirror the backend's preflight (backend/policy_studio/preflight.py
// _registry_blocker / registry_warnings and gcp/registry.py), so the mock and the form say what Apply would.
import type { Gateway, Intent, Inventory, ProtocolBinding, RegistryInterface, RegistryService } from "../api/types";
import { newId } from "./policy";

export type RegKind = "endpoint" | "mcp_server";
export const BINDINGS: ProtocolBinding[] = ["HTTP_JSON", "JSONRPC", "GRPC"];
export const BINDING_LABEL: Record<ProtocolBinding, string> = { HTTP_JSON: "HTTP + JSON", JSONRPC: "JSON-RPC", GRPC: "gRPC" };
/** API endpoints default to HTTP + JSON, MCP servers to JSON-RPC (MCP's transport). */
export const DEFAULT_BINDING: Record<RegKind, ProtocolBinding> = { endpoint: "HTTP_JSON", mcp_server: "JSONRPC" };
export const REG_KIND_LABEL: Record<RegKind, string> = { endpoint: "API endpoint", mcp_server: "MCP server" };
/** 4–63 lowercase letters, digits and hyphens, starting with a letter (the API's serviceId rule; digits are seen on
 *  live ids). */
export const SERVICE_ID_RE = /^[a-z][a-z0-9-]{2,61}[a-z0-9]$/;
/** A single region (us-east4), not a multi-region (us, eu, global): the gateway uses the registry of its own region. */
export const SINGLE_REGION_RE = /^[a-z]+-[a-z]+\d+$/;
export const GRANTS_LOST = "IAP grants live on the entry: deleting it deletes them, and re-creating it (undo) gives a new, empty entry, so they don't come back";
const A2A_OUT_OF_SCOPE =
  "A2A agents can't be registered here: Agent Registry registers them from their agent card (agentSpec A2A_AGENT_CARD, with no interfaces), not from URLs. Publish the agent with its card (agents-cli publish, or gcloud agent-registry services create --agent-spec-type=a2a-agent-card).";

// ------------------------------------------------------------------ URLs
/** For duplicate checks: scheme and host lowercased, a trailing slash dropped (as the backend's norm_url). */
export function normUrl(url: string): string {
  const u = (url ?? "").trim();
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?/.exec(u);
  if (!m || !m[2]) return u.replace(/\/+$/, "");
  return `${m[1].toLowerCase()}://${m[2].toLowerCase()}${m[3].replace(/\/+$/, "")}${m[4] ?? ""}`;
}

export function hostOf(url: string): string {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/.exec((url ?? "").trim());
  return (m?.[1] ?? "").toLowerCase();
}

/** Why a URL can't be registered (null = fine): https only, no wildcard, a host. */
export function urlProblem(url: string): string | null {
  const u = (url ?? "").trim();
  if (!u) return "the URL is empty";
  if (u.includes("*")) return `${u} has a wildcard: the gateway matches registered hostnames exactly, so register each URL`;
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(u)?.[1];
  if (!scheme) return `${u} isn't a valid URL`;
  if (scheme.toLowerCase() !== "https") return `${u} isn't https (the gateway only calls registered https URLs)`;
  if (!hostOf(u)) return `${u} has no host name`;
  if (/\s/.test(u)) return `${u} contains spaces`;
  return null;
}

const RUN_APP_NUMBER = /^[a-z0-9-]+-\d+\.[a-z0-9-]+\.run\.app$/;
const RUN_APP_HASH = /^[a-z0-9-]+-[a-z0-9]+-[a-z]{2}\.a\.run\.app$/;
/** "number" (SERVICE-PROJECT_NUMBER.REGION.run.app), "hash" (SERVICE-HASH-XX.a.run.app), "other" run.app, or null. */
export function runAppForm(url: string): "number" | "hash" | "other" | null {
  const h = hostOf(url);
  if (!h.endsWith(".run.app")) return null;
  return RUN_APP_NUMBER.test(h) ? "number" : RUN_APP_HASH.test(h) ? "hash" : "other";
}

/** A warning when the URLs use only one of Cloud Run's two URL forms (the gateway matches hostnames exactly). */
export function runAppHint(urls: string[]): string | null {
  const forms = new Set(urls.map(runAppForm).filter((f) => f === "number" || f === "hash"));
  if (forms.size !== 1) return null;
  const have = forms.has("number") ? "SERVICE-PROJECT_NUMBER.REGION.run.app" : "SERVICE-HASH-XX.a.run.app";
  return `Only one of Cloud Run's two URL forms is registered (${have}). A Cloud Run service answers on both, and the gateway matches hostnames exactly: also register the other run.app URL shown on the Cloud Run page.`;
}

/** The private DNS domain of the gateway (trailing dot, e.g. "run.app.") that a URL's host falls under, or null.
 *  x.run.app matches run.app.; run.app.evil.com doesn't. Display only: whether the name really resolves to a private
 *  address depends on the zones behind it. */
export function privateDomainMatch(url: string, domains: string[]): string | null {
  const host = hostOf(url).replace(/\.$/, "");
  if (!host) return null;
  let best: string | null = null;
  for (const d of domains) {
    const dom = d.toLowerCase().replace(/\.$/, "");
    if (!dom) continue;
    if ((host === dom || host.endsWith(`.${dom}`)) && (!best || dom.length > best.replace(/\.$/, "").length)) best = d;
  }
  return best;
}

/** The egress gateways in the region with private egress, and their domains (for the form's hint). */
export function privateGateways(gateways: Gateway[]): { id: string; vpc: string; domains: string[] }[] {
  return gateways
    .filter((g) => g.type === "egress" && g.private_egress && !g.private_egress.error && g.private_egress.dns_domains.length)
    .map((g) => ({ id: g.id, vpc: g.private_egress!.vpc || "a VPC", domains: g.private_egress!.dns_domains }));
}

// ------------------------------------------------------------------ what's registered today
/** Every registered URL (normalized) and the entry that has it: "Tickets MCP (tickets-mcp)". */
export function registeredUrls(inv: Inventory | null | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!inv) return out;
  for (const x of [...inv.agents, ...inv.mcp_servers, ...inv.endpoints]) for (const u of x.urls ?? (x.url ? [x.url] : [])) if (!out.has(normUrl(u))) out.set(normUrl(u), `${x.display_name} (${x.id})`);
  for (const s of inv.services ?? []) for (const i of s.interfaces) out.set(normUrl(i.url), `${s.display_name} (${s.id})`);
  return out;
}

export const serviceOf = (inv: Inventory | null | undefined, id: string): RegistryService | undefined => inv?.services?.find((s) => s.id === id);

/** The entry (projection) a Service is behind, if listed. */
export function entryOfService(inv: Inventory | null | undefined, svc: RegistryService | undefined): { name: string; display_name: string } | undefined {
  if (!inv || !svc) return undefined;
  return [...inv.mcp_servers, ...inv.endpoints, ...inv.agents].find((x) => x.service === svc.name);
}

/** Bindings on a Service's entry today (removed with it). */
export const grantsOnService = (inv: Inventory | null | undefined, svc: RegistryService | undefined): number => {
  const e = entryOfService(inv, svc);
  return e && inv ? (inv.access[e.name] ?? []).length : 0;
};

// ------------------------------------------------------------------ the form
export type RegRow = { url: string; protocol_binding: ProtocolBinding };
export type RegForm = {
  kind: RegKind;
  display_name: string;
  service_id: string;
  description: string;
  rows: RegRow[];
  /** Optional: the server's tools/list response (JSON), so tool conditions can match. */
  tools_json: string;
};
export const emptyForm = (kind: RegKind = "mcp_server"): RegForm => ({ kind, display_name: "", service_id: "", description: "", rows: [{ url: "", protocol_binding: DEFAULT_BINDING[kind] }], tools_json: "" });

/** "Notes MCP (prod)" → "notes-mcp-prod": a valid service id, or "" when nothing usable is left. */
export function suggestServiceId(name: string): string {
  let s = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  s = s.replace(/^[^a-z]+/, "").slice(0, 63).replace(/-+$/, "");
  if (s.length && s.length < 4) s = `${s}-svc`.slice(0, 63);
  return SERVICE_ID_RE.test(s) ? s : "";
}

/** The tools/list JSON as a tool spec ({tools: [...]}), or an error. "" = none. */
export function parseTools(text: string): { spec: { tools: unknown[] } | null; error: string | null } {
  const t = text.trim();
  if (!t) return { spec: null, error: null };
  try {
    const v = JSON.parse(t) as unknown;
    const tools = Array.isArray(v) ? v : (v as { tools?: unknown })?.tools ?? (v as { result?: { tools?: unknown } })?.result?.tools;
    if (!Array.isArray(tools) || !tools.every((x) => x && typeof x === "object" && typeof (x as { name?: unknown }).name === "string"))
      return { spec: null, error: "Paste the tools/list response: {\"tools\": [{\"name\": …, \"annotations\": {…}}]}." };
    if (JSON.stringify({ tools }).length > 10 * 1024) return { spec: null, error: "The tool list is over the registry's 10 KB limit." };
    return { spec: { tools }, error: null };
  } catch {
    return { spec: null, error: "Not valid JSON." };
  }
}

export interface FormCheck {
  /** field → message (blocking) */
  errors: Partial<Record<"kind" | "display_name" | "service_id" | "rows" | "tools_json" | "region", string>>;
  /** per row: a blocking message, or null */
  rowErrors: (string | null)[];
  warnings: string[];
  ok: boolean;
}

/** The form's checks: the same ones preflight blocks on (https, no wildcard, not registered, a valid and free id,
 *  a single region), plus the run.app hint. `staged`: URLs and ids of creates already in the cart. */
export function checkForm(f: RegForm, opts: { inv: Inventory | null | undefined; region: string; cart?: Intent[] }): FormCheck {
  const errors: FormCheck["errors"] = {};
  const taken = registeredUrls(opts.inv);
  const stagedUrls = new Map<string, string>();
  const stagedIds = new Set<string>();
  for (const i of opts.cart ?? [])
    if (i.kind === "registry_service" && !i.params?.delete) {
      stagedIds.add(i.params?.service_id ?? "");
      for (const r of i.params?.interfaces ?? []) stagedUrls.set(normUrl(r.url), i.params?.service_id ?? "");
    }
  if (!SINGLE_REGION_RE.test(opts.region)) errors.region = `${opts.region || "No region"} isn't a single region: pick the gateway's region on Context.`;
  if (!f.display_name.trim()) errors.display_name = "Enter a display name.";
  else if (f.display_name.trim().length > 63) errors.display_name = "At most 63 characters.";
  const sid = f.service_id.trim();
  if (!sid) errors.service_id = "Enter an id.";
  else if (!SERVICE_ID_RE.test(sid)) errors.service_id = "4–63 lowercase letters, digits and hyphens, starting with a letter (not ending with a hyphen).";
  else if (serviceOf(opts.inv, sid)) errors.service_id = `${sid} already exists in this region.`;
  else if (stagedIds.has(sid)) errors.service_id = `${sid} is already staged in the cart.`;
  const seen = new Set<string>();
  const filled = f.rows.filter((r) => r.url.trim());
  const rowErrors = f.rows.map((r) => {
    const u = r.url.trim();
    if (!u) return null;
    const p = urlProblem(u);
    if (p) return p[0].toUpperCase() + p.slice(1) + ".";
    const k = normUrl(u);
    if (seen.has(k)) return "Listed twice.";
    seen.add(k);
    const owner = taken.get(k);
    if (owner) return `Duplicate: already registered as ${owner}. Grant on that entry instead.`;
    if (stagedUrls.has(k)) return `Duplicate: also registered by ${stagedUrls.get(k)} in the cart.`;
    return null;
  });
  if (!filled.length) errors.rows = "Add at least one URL the agents call.";
  const tools = f.kind === "mcp_server" ? parseTools(f.tools_json) : { spec: null, error: null };
  if (tools.error) errors.tools_json = tools.error;
  const warnings: string[] = [];
  const hint = runAppHint(filled.map((r) => r.url.trim()));
  if (hint) warnings.push(hint);
  if (f.kind === "mcp_server" && !tools.spec) warnings.push("No tool list: the entry is registered without tools (NO_SPEC), so a read-only or specific-tools grant only lets MCP setup calls through. Grant full access, or paste the tools/list response.");
  return { errors, rowErrors, warnings, ok: !Object.keys(errors).length && rowErrors.every((e) => !e) };
}

/** The pending entry's map / simulate name until the registry projects it (and assigns its id). */
export const pendingEntryName = (sid: string) => `pending-registry/${sid}`;
export const isPendingEntry = (name: string | undefined) => !!name && name.startsWith("pending-registry/");

export function createIntent(f: RegForm, id = newId("reg")): Intent {
  const tools = f.kind === "mcp_server" ? parseTools(f.tools_json).spec : null;
  const interfaces: RegistryInterface[] = f.rows.filter((r) => r.url.trim()).map((r) => ({ url: r.url.trim(), protocol_binding: r.protocol_binding }));
  return {
    id,
    kind: "registry_service",
    params: {
      kind: f.kind,
      service_id: f.service_id.trim(),
      display_name: f.display_name.trim(),
      ...(f.description.trim() ? { description: f.description.trim() } : {}),
      interfaces,
      ...(tools ? { tool_spec: tools } : {}),
    },
  };
}

/** The destination of a grant on an entry a create in the same cart registers. */
export function pendingDestination(create: Intent): NonNullable<Intent["destination"]> {
  const p = create.params ?? {};
  return { kind: p.kind ?? "endpoint", id: "", name: pendingEntryName(p.service_id ?? ""), label: p.display_name || p.service_id || "", pending_service: p.service_id };
}

/** The Inventory's "Delete entry…": a delete of the Service behind an entry. */
export function deleteIntent(svc: RegistryService, id = newId("reg")): Intent {
  return {
    id,
    kind: "registry_service",
    params: { kind: svc.kind === "mcp_server" ? "mcp_server" : "endpoint", service_id: svc.id, display_name: svc.display_name, interfaces: svc.interfaces, delete: true },
  };
}

/** Plain English, as the backend's english.registry_english. */
export function registryEnglish(i: Intent): string {
  const p = i.params ?? {};
  const kind = p.kind ? REG_KIND_LABEL[p.kind] : "entry";
  const sid = p.service_id || "SERVICE_ID";
  const name = p.display_name || sid;
  const urls = (p.interfaces ?? []).map((x) => x.url).filter(Boolean);
  if (p.delete) return `Delete the Agent Registry ${kind} ${name} (${sid}): agents can no longer reach ${urls.length === 1 ? "its URL" : "its URLs"} through the gateway, and the IAP grants on it are removed with it.`;
  const where = urls.length ? (urls.length === 1 ? urls[0] : `${urls.length} URLs: ${urls.join(", ")}`) : "no URL yet";
  return `Register ${kind} ${name} (${sid}) in Agent Registry, at ${where}.`;
}

// ------------------------------------------------------------------ preflight (the mock's, and instant UI checks)
export type RegPreflight = { status: "ok" | "blocked"; reason?: string; fix?: "already" | "duplicate" | ""; warning?: string };

/** registry_service and grants on pending entries, as the backend's preflight: {intent id: result} for those only. */
export function registryPreflight(intents: Intent[], inv: Inventory | null | undefined, region: string): Map<string, RegPreflight> {
  const out = new Map<string, RegPreflight>();
  const taken = registeredUrls(inv);
  const stagedUrls = new Map<string, string>();
  const creates = new Map<string, string>();
  for (const i of intents) {
    if (i.kind !== "registry_service") continue;
    const p = i.params ?? {};
    const sid = (p.service_id ?? "").trim();
    const block = (reason: string, fix: RegPreflight["fix"] = "") => out.set(i.id, { status: "blocked", reason, fix });
    if (!p.delete) creates.set(sid, i.id);
    if (!SINGLE_REGION_RE.test(region)) {
      block(`Agent Registry entries for the gateway live in its region; ${region || "no region"} isn't a single region (us / eu / global multi-regions aren't used by Agent Gateway). Pick the gateway's region on Context.`);
      continue;
    }
    if ((p.kind as string) === "agent") {
      block(A2A_OUT_OF_SCOPE);
      continue;
    }
    if (p.kind !== "endpoint" && p.kind !== "mcp_server") {
      block("Pick what to register: an API endpoint or an MCP server.");
      continue;
    }
    if (!SERVICE_ID_RE.test(sid)) {
      block(sid ? `The service id '${sid}' isn't valid: 4–63 lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen.` : "No service id.");
      continue;
    }
    const existing = serviceOf(inv, sid);
    if (p.delete) {
      if (inv?.services && !existing) block(`There is no registry entry ${sid} in ${region} (deleted already?). Sync and check.`, "already");
      else {
        const n = existing ? grantsOnService(inv, existing) : null;
        const google = (existing?.interfaces ?? p.interfaces ?? []).map((x) => x.url).filter((u) => /(^|\.)googleapis\.com$/.test(hostOf(u)));
        const warn = [
          n ? `${n} grant${n === 1 ? "" : "s"} on this entry will be removed with it (${GRANTS_LOST}).` : n === null ? `Any grants on this entry are removed with it (${GRANTS_LOST}).` : "",
          google.length ? `${google.join(", ")} ${google.length === 1 ? "is a Google API" : "are Google APIs"}: agents bound to the egress gateway call it through the gateway, so they lose access when this entry goes.` : "",
        ].filter(Boolean);
        out.set(i.id, { status: "ok", ...(warn.length ? { warning: warn.join(" ") } : {}) });
      }
      continue;
    }
    if (existing) {
      block(`A registry entry with the id ${sid} already exists in ${region} (${existing.display_name}); pick another id.`);
      continue;
    }
    const ifs = (p.interfaces ?? []).filter((x) => x.url.trim());
    if (!ifs.length) {
      block("Add at least one URL the agents call.");
      continue;
    }
    const seen = new Set<string>();
    let bad: RegPreflight | null = null;
    for (const x of ifs) {
      const url = x.url.trim();
      const prob = urlProblem(url);
      if (prob) bad = { status: "blocked", reason: prob[0].toUpperCase() + prob.slice(1) + ".", fix: "" };
      else if (!BINDINGS.includes(x.protocol_binding)) bad = { status: "blocked", reason: `The protocol for ${url} must be one of JSONRPC, GRPC, HTTP_JSON.`, fix: "" };
      else if (seen.has(normUrl(url))) bad = { status: "blocked", reason: `${url} is listed twice.`, fix: "" };
      else if (taken.has(normUrl(url))) bad = { status: "blocked", reason: `Duplicate: ${url} is already registered in ${region} as ${taken.get(normUrl(url))}. Grant on that entry instead, or delete it first.`, fix: "duplicate" };
      else if (stagedUrls.has(normUrl(url)) && stagedUrls.get(normUrl(url)) !== sid) bad = { status: "blocked", reason: `Duplicate: ${url} is also registered by ${stagedUrls.get(normUrl(url))} earlier in this request.`, fix: "duplicate" };
      if (bad) break;
      seen.add(normUrl(url));
    }
    if (bad) {
      out.set(i.id, bad);
      continue;
    }
    for (const k of seen) if (!stagedUrls.has(k)) stagedUrls.set(k, sid);
    const hint = runAppHint(ifs.map((x) => x.url));
    out.set(i.id, { status: "ok", ...(hint ? { warning: hint } : {}) });
  }
  for (const i of intents) {
    const pending = i.destination?.pending_service;
    if (!pending || !["grant", "revoke", "modify"].includes(i.kind)) continue;
    const c = creates.get(pending);
    if (c === undefined) out.set(i.id, { status: "blocked", reason: `The entry ${pending} isn't registered by an item in this request, so there's nothing to grant on yet. Stage “Register a new destination” with it.`, fix: "" });
    else if (out.get(c)?.status === "blocked") out.set(i.id, { status: "blocked", reason: `Not attempted: registering ${pending} is blocked (${out.get(c)!.reason})`, fix: "" });
  }
  return out;
}
