import { describe, expect, it } from "vitest";
import type { Engine, Grant } from "../api/types";
import { grantToIntent, grantToModify } from "./grants";
import { intentEnglish, intentKey } from "./policy";

const P = "principal://agents.global.org-777.system.id.goog/resources/aiplatform/projects/4242/locations/us-east4/reasoningEngines/111";
// A hand-written tools condition (no '' branch, double spaces): regenerating it would not match the binding.
const EXPR = "api.getAttribute('iap.googleapis.com/mcp.toolName', '')  in ['get_ticket']";
const grant: Grant = {
  role: "roles/iap.egressor",
  member: P,
  member_label: "Helpdesk Agent (Agent Identity)",
  condition: { title: "hand", expression: EXPR },
  english: "",
  resource: "projects/my-demo-project/locations/us-east4/mcpServers/tickets",
  resource_kind: "mcp_server",
  resource_label: "Tickets MCP",
};
const engines = new Map<string, Engine>([[P, { name: "projects/4242/locations/us-east4/reasoningEngines/111", id: "111", display_name: "Helpdesk Agent", principal: P, identity_type: "AGENT_IDENTITY", gateways: {}, create_time: "", bindable: true }]]);

describe("grantToModify", () => {
  it("is one modify intent whose access_from is the grant's exact condition", () => {
    const m = grantToModify(grant, engines, { mode: "read_only_hint" });
    expect(m.kind).toBe("modify");
    expect(m.access_from).toEqual({ mode: "custom", expression: EXPR, title: "hand" });
    expect(m.access).toEqual({ mode: "read_only_hint" });
    expect(m.source).toMatchObject({ type: "engine", principal: P, label: "Helpdesk Agent" });
    expect(m.destination).toEqual({ kind: "mcp_server", id: "tickets", name: grant.resource, label: "Tickets MCP" });
    expect(intentEnglish(m)).toBe("Change Helpdesk Agent's access to Tickets MCP: only tools get_ticket → only read-only tools.");
  });

  it("uses mode all for an unconditional grant, and kind registry for a registry-wide one", () => {
    const reg: Grant = { ...grant, condition: null, resource: "projects/my-demo-project/locations/us-east4", resource_kind: "registry", resource_label: "Agent Registry" };
    const m = grantToModify(reg, engines, { mode: "tools", tools: ["get_ticket"] });
    expect(m.access_from).toEqual({ mode: "all" });
    expect(m.destination).toMatchObject({ kind: "registry", id: "" });
    expect(intentEnglish(m)).toBe("Change Helpdesk Agent's access to Agent Registry: full access → only tools get_ticket.");
  });

  it("is a different change from a revoke or a grant of the same binding (cart dedup)", () => {
    const keys = [grantToModify(grant, engines, { mode: "all" }), grantToIntent(grant, engines, "revoke"), grantToIntent(grant, engines, "grant")].map(intentKey);
    expect(new Set(keys).size).toBe(3);
    expect(intentKey(grantToModify(grant, engines, { mode: "all" }))).toBe(intentKey(grantToModify(grant, engines, { mode: "all" })));
    expect(intentKey(grantToModify(grant, engines, { mode: "all" }))).not.toBe(intentKey(grantToModify({ ...grant, condition: null }, engines, { mode: "all" })));
  });
});
