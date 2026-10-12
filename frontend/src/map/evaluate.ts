// Does a grant let a caller through? A port of backend/policy_studio/dryrun.py (member_matches, condition_allows)
// and the parts of conditions.py they use, for the policy map. Both sides are tested against the same fixture
// (backend/tests/fixtures/egress_cases.json). null = can't be told here (a group or domain member, a custom
// condition, a tool missing from the inventory): never a deny.
import type { Binding } from "../api/types";

export const EVERYONE = ["allUsers", "allAuthenticatedUsers"];
export const PROJECT_AGENTS_RE = /^principalSet:\/\/[^/]+\/attribute\.platformContainer\/aiplatform\/projects\/(\d+)$/;
export const ENGINE_PRINCIPAL_RE = /^principal:\/\/[^/]+\/resources\/aiplatform\/projects\/(\d+)\/locations\/([^/]+)\/reasoningEngines\/([^/]+)$/;
const TD_RE = /^principal(?:Set)?:\/\/([^/]+)\//;

export const READ_ONLY_EXPRESSION =
  "api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''";
const TOOLS_RE = /^\s*api\.getAttribute\(\s*'iap\.googleapis\.com\/mcp\.toolName'\s*,\s*''\s*\)\s+in\s+\[(.*)\]\s*$/s;

const norm = (e: string) => e.trim().replace(/\s+/g, " ");

/** Does `member` include `principal`? null when it can't be told here (groups, domains). */
export function memberMatches(member: string, principal: string): boolean | null {
  if (member === principal || EVERYONE.includes(member)) return true;
  const ps = PROJECT_AGENTS_RE.exec(member ?? "");
  const eng = ENGINE_PRINCIPAL_RE.exec(principal ?? "");
  if (ps && eng) {
    const tdM = TD_RE.exec(member);
    const tdP = TD_RE.exec(principal);
    return ps[1] === eng[1] && !!(tdM && tdP && tdM[1] === tdP[1]);
  }
  if ((member ?? "").startsWith("group:") || (member ?? "").startsWith("domain:")) return null;
  return false;
}

/** Tool names of a `toolName in [...]` expression ('' removed unless keepEmpty), or null if it isn't one. */
export function parseTools(expression: string, keepEmpty = false): string[] | null {
  const m = TOOLS_RE.exec(expression ?? "");
  if (!m) return null;
  const inner = m[1];
  const items = [...inner.matchAll(/'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1] ?? x[2] ?? "");
  const rest = inner.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|,|\s/g, "");
  if (rest) return null;
  return items.filter((t) => t || keepEmpty);
}

export const isReadOnlyHint = (expression: string) => norm(expression ?? "") === norm(READ_ONLY_EXPRESSION);

/** One call through the gateway: an MCP method and tool (tools/call), or neither (A2A, API, MCP setup calls). */
export type Call = { mcp_method?: string | null; mcp_tool?: string | null };

/** Evaluate a binding condition for one call. `tools`: {tool name: read-only hint} of the destination MCP server
 *  (null = not an MCP server / unknown). */
export function conditionAllows(cond: Binding["condition"] | undefined, call: Call, tools: Record<string, boolean> | null): boolean | null {
  if (!cond) return true;
  const expr = cond.expression ?? "";
  const isCall = call.mcp_method === "tools/call";
  const tool = isCall ? (call.mcp_tool ?? null) : null;
  if (tool === null && isCall) return null; // a tool call without the tool name: can't tell
  if (isReadOnlyHint(expr)) {
    if (!tool) return true; // toolName '' (setup traffic, non-MCP calls)
    if (tools === null || !Object.prototype.hasOwnProperty.call(tools, tool)) return null;
    return tools[tool];
  }
  const names = parseTools(expr, true);
  if (names !== null) return names.includes(tool ?? "");
  return null;
}

/** Each tool of an MCP server under one condition: allowed, denied, or unknown (a condition that can't be evaluated
 *  here). */
export function evaluateTools(cond: Binding["condition"] | undefined, tools: Record<string, boolean>): { allowed: string[]; denied: string[]; unknown: string[] } {
  const out = { allowed: [] as string[], denied: [] as string[], unknown: [] as string[] };
  for (const name of Object.keys(tools)) {
    const ok = conditionAllows(cond, { mcp_method: "tools/call", mcp_tool: name }, tools);
    (ok === true ? out.allowed : ok === false ? out.denied : out.unknown).push(name);
  }
  return out;
}
