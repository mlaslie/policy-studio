// Shared, client-side knowledge about egress grants: the condition expressions (API.md "Conditions"),
// plain-English sentences for intents, and principal helpers. The backend's /render is the source of
// truth for generated commands; this module only powers instant previews and labels.
import type { Access, AccessMode, Ctx, Intent, McpServer } from "../api/types";
import { registryEnglish } from "./registry";

export const ROLE = "roles/iap.egressor";
export const TOOL_ATTR = "iap.googleapis.com/mcp.toolName";
export const RO_ATTR = "iap.googleapis.com/mcp.tool.isReadOnly";

export const READ_ONLY_EXPR = `api.getAttribute('${RO_ATTR}', false) == true || api.getAttribute('${TOOL_ATTR}', '') == ''`;

/** A CEL single-quoted string literal (the backend's conditions.cel_string). The backend rejects tool names outside
 *  letters, digits and _ . - : / (model.py TOOL_NAME_RE), so for names it accepts this is just the name in quotes. */
export const celString = (s: string) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;

export function toolsExpr(tools: string[]): string {
  const list = [...tools.map(celString), "''"].join(", ");
  return `api.getAttribute('${TOOL_ATTR}', '') in [${list}]`;
}

/** The IAM condition for an access choice (null = unconditional). access.title overrides the generated title, like
 *  the backend's condition_for. */
export function conditionFor(access: Intent["access"]): { title: string; expression: string } | null {
  if (!access || access.mode === "all") return null;
  const title = access.title || undefined;
  if (access.mode === "read_only_hint") return { title: title ?? "MCP read-only tools (by hint)", expression: READ_ONLY_EXPR };
  if (access.mode === "tools") return { title: title ?? `MCP tools: ${(access.tools ?? []).join(", ") || "none"}`, expression: toolsExpr(access.tools ?? []) };
  return { title: title ?? "Custom condition", expression: access.expression ?? "" };
}

/** An existing condition expression as an access choice (none = full access); anything else is "custom". */
export function accessFromCondition(expr: string | undefined): Access {
  if (!expr) return { mode: "all" };
  const e = expr.replace(/\s+/g, " ").trim();
  if (e === READ_ONLY_EXPR) return { mode: "read_only_hint" };
  const m = new RegExp(`^api\\.getAttribute\\('${TOOL_ATTR.replace(/\./g, "\\.")}', ''\\) in \\[(.*)\\]$`).exec(e);
  if (m) {
    const tools = [...m[1].matchAll(/'((?:[^'\\]|\\.)*)'/g)].map((x) => x[1]).filter(Boolean);
    return { mode: "tools", tools };
  }
  return { mode: "custom", expression: expr };
}

/** A custom condition that holds for every request (true, (true), true == true, 1 == 1, !false), as the backend's
 *  conditions.always_true: full access that reads like a restriction. */
export function alwaysTrue(expr: string | undefined): boolean {
  let e = (expr ?? "").replace(/\s+/g, "");
  while (e.startsWith("(") && e.endsWith(")") && (e.match(/\(/g) ?? []).length === 1) e = e.slice(1, -1);
  return ["true", "true==true", "1==1", "!false"].includes(e);
}

/** Short phrase for an access, as the backend's english.access_words: an exact (custom) expression is described as
 *  what it is. For modify sentences ("full access → only read-only tools"). */
export function accessWords(a: Access | undefined): string {
  const acc = a?.mode === "custom" ? accessFromCondition(a.expression?.trim() ? a.expression : undefined) : a;
  if (!acc || acc.mode === "all") return "full access";
  if (acc.mode === "read_only_hint") return "only read-only tools";
  if (acc.mode === "tools") {
    const t = (acc.tools ?? []).filter(Boolean);
    return t.length ? `only tools ${t.join(", ")}` : "MCP setup calls only (no tools)";
  }
  if (alwaysTrue(acc.expression)) return "full access (always-true condition)";
  return "a custom condition";
}

/** modify: the bindings removed (access_from_list, else [access_from]). */
export const accessFroms = (i: Pick<Intent, "access_from" | "access_from_list">): Access[] => i.access_from_list ?? (i.access_from ? [i.access_from] : []);
/** modify: the bindings added (access_list, else [access]); [] = the remove-all form. */
export const accessTos = (i: Pick<Intent, "access" | "access_list">): Access[] => i.access_list ?? (i.access ? [i.access] : []);
/** A modify that isn't one binding → one binding (several removed, none or several added). */
export const isMultiModify = (i: Intent) => i.kind === "modify" && !(accessFroms(i).length === 1 && accessTos(i).length === 1);
/** The remove-all form of modify: bindings removed, none added (destructive). */
export const removesAll = (i: Intent) => i.kind === "modify" && accessFroms(i).length > 0 && accessTos(i).length === 0;

/** Shortest phrase for an access, as the backend's english.access_short ("read-only", "close_ticket"). */
export function accessShort(a: Access | undefined): string {
  const acc = a?.mode === "custom" ? accessFromCondition(a.expression?.trim() ? a.expression : undefined) : a;
  if (!acc || acc.mode === "all") return "full access";
  if (acc.mode === "read_only_hint") return "read-only";
  if (acc.mode === "tools") return (acc.tools ?? []).filter(Boolean).join(", ") || "no tools";
  if (alwaysTrue(acc.expression)) return "full access";
  return "a custom condition";
}

/** "before → after" of a modify, as the backend's english.modify_change: accessWords for one binding each way, else
 *  the short form of each ("read-only + close_ticket → list_tickets, get_ticket, update_ticket"; "→ no access"). */
export function modifyChange(i: Intent): string {
  if (!isMultiModify(i)) return `${accessWords(i.access_from)} → ${accessWords(i.access)}`;
  const side = (xs: Access[]) => xs.map(accessShort).join(" + ") || "no access";
  return `${side(accessFroms(i))} → ${side(accessTos(i))}`;
}

export const ACCESS_LABEL: Record<AccessMode, string> = {
  all: "Full access",
  read_only_hint: "Read-only tools (by MCP hint)",
  tools: "Specific tools",
  custom: "Custom condition",
};

const KIND_NOUN = { agent: "A2A agent", mcp_server: "MCP server", endpoint: "API endpoint" } as const;
export const kindNoun = (k: keyof typeof KIND_NOUN) => KIND_NOUN[k];

/** One plain-English sentence for an intent (used in the cart and as a fallback preview). */
export function intentEnglish(i: Intent): string {
  const who = i.source?.label ?? "Someone";
  const dest = i.destination?.label ?? "a destination";
  const gw = i.gateway?.name ? shortName(i.gateway.name) : "a gateway";
  const eng = i.engine_label ?? (i.engine ? shortName(i.engine) : "an agent");
  switch (i.kind) {
    case "grant": {
      const a = i.access;
      if (!a || a.mode === "all") return `${who} can call ${dest} (full access).`;
      if (a.mode === "read_only_hint") return `${who} can call only the read-only tools of ${dest}.`;
      if (a.mode === "tools") {
        const t = a.tools ?? [];
        if (!t.length) return `${who} can connect to ${dest} but call no tools.`;
        if (t.length === 1) return `${who} can call only ${t[0]} on ${dest}.`;
        return `${who} can call only these ${t.length} tools on ${dest}: ${t.join(", ")}.`;
      }
      if (alwaysTrue(a.expression)) return `${who} can call ${dest} (full access: its custom condition is always true).`;
      return a.title ? `${who} can call ${dest} under the condition “${a.title}”.` : `${who} can call ${dest} when a custom condition is true.`;
    }
    case "revoke": {
      // Like the backend: no access = the unconditional binding; otherwise the binding with exactly this condition.
      const c = conditionFor(i.access);
      return c ? `Remove ${who}'s “${c.title}” grant on ${dest}.` : `Remove ${who}'s unconditional grant on ${dest}.`;
    }
    case "modify": {
      if (removesAll(i)) {
        const n = accessFroms(i).length;
        return `Remove all of ${who}'s access to ${dest} (${n} ${n === 1 ? "grant" : "grants"}): ${modifyChange(i)}.`;
      }
      return `Change ${who}'s access to ${dest}: ${modifyChange(i)}.`;
    }
    case "bind_gateway":
      return i.gateway?.direction === "ingress"
        ? `Route traffic into ${eng} through ingress gateway ${gw}.`
        : `Send ${eng}'s outbound traffic through egress gateway ${gw}.`;
    case "unbind_gateway":
      return `Stop routing ${eng}'s ${i.gateway?.direction ?? ""} traffic through ${gw}.`;
    case "model_armor_on":
      return `Turn on Model Armor screening on ${gw}.`;
    case "model_armor_off":
      return `Turn off Model Armor screening on ${gw}.`;
    case "model_armor_template": {
      const t = shortName(i.params?.template_id ?? "") || "a template";
      return i.params?.delete ? `Delete Model Armor template ${t}.` : `Create Model Armor template ${t} (the filters Model Armor applies).`;
    }
    case "model_armor_extension": {
      const n = shortName(i.params?.name ?? "") || "an extension";
      return i.params?.delete ? `Delete Model Armor extension ${n}.` : `Create Model Armor extension ${n}, screening with template ${shortName(i.params?.template ?? "") || "?"}.`;
    }
    case "iam_project_grant": {
      const who = (i.params?.member ?? "the service agent").replace(/^serviceAccount:/, "");
      const roles = (i.params?.roles ?? []).map(shortName).join(", ") || "no roles";
      return i.params?.delete ? `Remove ${roles} from ${who}.` : `Let ${who} call Model Armor (${roles}).`;
    }
    case "set_enforcement":
      return i.mode === "DRY_RUN"
        ? `Put ${gw} in dry run: nothing is blocked (calls IAP would deny pass and are logged as allowed)${i.scope === "shared" ? " (shared extension: other gateways too)" : ""}.`
        : `Enforce IAP on ${gw}: calls without a grant are blocked${i.scope === "shared" ? " (shared extension: other gateways too)" : ""}.`;
    case "dedicate_extension":
      return i.revert
        ? `Point ${gw} back at ${shortName(i.source_extension ?? "") || "its original extension"} and delete ${i.new_name ?? "its own extension"}.`
        : `Give ${gw} its own IAP extension ${i.new_name ?? ""} (a copy of ${shortName(i.source_extension ?? "") || "the shared one"}).`;
    case "registry_service":
      return registryEnglish(i);
  }
}

export const KIND_LABEL: Record<Intent["kind"], string> = {
  grant: "Grant",
  revoke: "Revoke",
  modify: "Change access",
  bind_gateway: "Bind",
  unbind_gateway: "Unbind",
  model_armor_on: "Model Armor on",
  model_armor_off: "Model Armor off",
  model_armor_template: "Model Armor template",
  model_armor_extension: "Model Armor extension",
  iam_project_grant: "Service agent roles",
  set_enforcement: "Enforcement mode",
  dedicate_extension: "Own IAP extension",
  registry_service: "Registry entry",
};

/** Order used for the review list: infrastructure first, then grants (plan §5). */
export const KIND_ORDER: Record<Intent["kind"], number> = {
  registry_service: -1,
  bind_gateway: 0,
  unbind_gateway: 1,
  model_armor_template: 2,
  model_armor_extension: 3,
  iam_project_grant: 4,
  dedicate_extension: 5,
  set_enforcement: 6,
  model_armor_on: 7,
  model_armor_off: 8,
  grant: 9,
  modify: 10,
  revoke: 11,
};

function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v as object)
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined && (v as Record<string, unknown>)[k] !== null)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  return JSON.stringify(v);
}

/** Two intents with the same key do the same thing (ids, labels and discovered fields don't count). Mirrors the
 *  backend's preflight.intent_key. */
export function intentKey(i: Intent): string {
  const g = i.gateway;
  const a = i.access;
  const f = i.access_from;
  const list = (xs: Access[] | undefined) => (xs ? xs.map((x) => stable([x.mode, [...(x.tools ?? [])].filter(Boolean).sort(), x.expression ?? "", x.title ?? null])).sort() : null);
  return stable({
    kind: i.kind,
    gateway: g ? [shortName(g.name), g.direction] : null,
    engine: i.engine ? shortName(i.engine) : null,
    source: i.source?.principal ?? null,
    destination: i.destination ? [i.destination.kind, i.destination.id || shortName(i.destination.name), ...(i.destination.pending_service ? [i.destination.pending_service] : [])] : null,
    access: a ? [a.mode, [...(a.tools ?? [])].filter(Boolean).sort(), a.expression ?? "", a.title ?? null] : null,
    access_from: f ? [f.mode, [...(f.tools ?? [])].filter(Boolean).sort(), f.expression ?? "", f.title ?? null] : null,
    access_from_list: list(i.access_from_list),
    access_list: list(i.access_list),
    params: i.params ?? null,
    extension: i.extension ? shortName(i.extension) : null,
    mode: i.mode ?? null,
    scope: i.scope ?? null,
    source_extension: i.source_extension ? shortName(i.source_extension) : null,
    new_name: i.new_name ? shortName(i.new_name) : null,
    revert: i.revert ? true : null,
  });
}

export function shortName(resource: string): string {
  const p = resource.split("/");
  return p[p.length - 1] || resource;
}

/** principal://agents.global.org-<ORG>.system.id.goog/resources/aiplatform/projects/<N>/... → principalSet for the project. */
export function projectPrincipalSet(samplePrincipal: string | undefined, projectNumber: string | undefined): string {
  const m = /^principal:\/\/([^/]+)\/resources\/aiplatform\/projects\/(\d+)\//.exec(samplePrincipal ?? "");
  const domain = m?.[1] ?? "agents.global.org-ORG_ID.system.id.goog";
  return `principalSet://${domain}/attribute.platformContainer/aiplatform/projects/${m?.[2] ?? projectNumber ?? "PROJECT_NUMBER"}`;
}

const MEMBER_RE = /^(principal:\/\/|principalSet:\/\/|serviceAccount:|user:|group:|domain:)\S+$/;
export function validateMember(m: string): string | null {
  const v = m.trim();
  if (!v) return "Enter a principal.";
  if (v === "allUsers" || v === "allAuthenticatedUsers") return "Public members can't be granted egress (and shouldn't be).";
  if (!MEMBER_RE.test(v)) return "Must start with principal://, principalSet://, serviceAccount:, user:, group: or domain:.";
  if (v.startsWith("serviceAccount:") && !/@.+\.iam\.gserviceaccount\.com$/.test(v)) return "Service accounts look like serviceAccount:name@project.iam.gserviceaccount.com.";
  return null;
}

/** Light checks for a custom CEL condition. Returns hints (not hard errors). */
export function lintExpression(expr: string): string[] {
  const out: string[] = [];
  const e = expr.trim();
  if (!e) return ["The condition is empty."];
  if (alwaysTrue(e)) return ["Always true: every call is allowed, so this is full access. Choose Full access if that's meant, or write the condition that limits it."];
  let depth = 0;
  for (const ch of e) {
    if (ch === "(" || ch === "[") depth++;
    if (ch === ")" || ch === "]") depth--;
    if (depth < 0) break;
  }
  if (depth !== 0) out.push("Brackets or parentheses are unbalanced.");
  if ((e.match(/'/g) ?? []).length % 2) out.push("A single quote is not closed.");
  if (/[^=!<>]=[^=]/.test(e.replace(/==|!=|<=|>=/g, ""))) out.push("Use == for comparison, not =.");
  if (!e.includes("api.getAttribute")) out.push("Egress conditions usually test api.getAttribute('iap.googleapis.com/mcp.toolName', '').");
  else if (e.includes(TOOL_ATTR) && !/''\s*[\]\)]|== ''/.test(e))
    out.push("Allow the empty tool name ('') too, or MCP setup calls (initialize, tools/list) will be denied.");
  if (e.length > 12 * 1024) out.push("IAM conditions are limited to 12 KB.");
  return out;
}

export function readOnlyTools(s: McpServer | undefined): string[] {
  return (s?.tools ?? []).filter((t) => t.read_only).map((t) => t.name);
}

export function newId(prefix = "i"): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-3)}`;
}

/** Fields of the context that some outputs need, mapped to a short reason. */
export function missingContext(ctx: Ctx, intents: Intent[]): string[] {
  const out: string[] = [];
  if (!ctx.project) out.push("Project ID is empty: commands use a placeholder.");
  if (!ctx.region) out.push("Region is empty: commands use a placeholder.");
  if (intents.some((i) => i.kind === "bind_gateway" && i.gateway?.direction === "ingress") && !ctx.ge_app)
    out.push("Gemini Enterprise app ID is not set: the ingress steps that register the agent with your Gemini Enterprise app use a GE_APP_ID placeholder.");
  return out;
}
