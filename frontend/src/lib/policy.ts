// Shared, client-side knowledge about egress grants: the condition expressions (API.md "Conditions"),
// plain-English sentences for intents, and principal helpers. The backend's /render is the source of
// truth for generated commands; this module only powers instant previews and labels.
import type { AccessMode, Ctx, Intent, McpServer } from "../api/types";

export const ROLE = "roles/iap.egressor";
export const TOOL_ATTR = "iap.googleapis.com/mcp.toolName";
export const RO_ATTR = "iap.googleapis.com/mcp.tool.isReadOnly";

export const READ_ONLY_EXPR = `api.getAttribute('${RO_ATTR}', false) == true || api.getAttribute('${TOOL_ATTR}', '') == ''`;

export function toolsExpr(tools: string[]): string {
  const list = [...tools.map((t) => `'${t.replace(/'/g, "\\'")}'`), "''"].join(", ");
  return `api.getAttribute('${TOOL_ATTR}', '') in [${list}]`;
}

/** The IAM condition for an access choice (null = unconditional). */
export function conditionFor(access: Intent["access"]): { title: string; expression: string } | null {
  if (!access || access.mode === "all") return null;
  if (access.mode === "read_only_hint") return { title: "MCP read-only tools (by hint)", expression: READ_ONLY_EXPR };
  if (access.mode === "tools") return { title: `MCP tools: ${(access.tools ?? []).join(", ") || "none"}`, expression: toolsExpr(access.tools ?? []) };
  return { title: "Custom condition", expression: access.expression ?? "" };
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
      return a.title ? `${who} can call ${dest} under the condition “${a.title}”.` : `${who} can call ${dest} when a custom condition is true.`;
    }
    case "revoke":
      if (i.access?.title !== undefined)
        return i.access.title ? `Remove ${who}'s “${i.access.title}” grant on ${dest}.` : `Remove ${who}'s unconditional grant on ${dest}.`;
      return `Remove ${who}'s access to ${dest}.`;
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
  }
}

export const KIND_LABEL: Record<Intent["kind"], string> = {
  grant: "Grant",
  revoke: "Revoke",
  bind_gateway: "Bind",
  unbind_gateway: "Unbind",
  model_armor_on: "Model Armor on",
  model_armor_off: "Model Armor off",
};

/** Order used for the review list: infrastructure first, then grants (plan §5). */
export const KIND_ORDER: Record<Intent["kind"], number> = {
  bind_gateway: 0,
  unbind_gateway: 1,
  model_armor_on: 2,
  model_armor_off: 3,
  grant: 4,
  revoke: 5,
};

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
