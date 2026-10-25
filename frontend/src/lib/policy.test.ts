import { describe, expect, it } from "vitest";
import { accessFromCondition, toolsExpr } from "./policy";

describe("toolsExpr", () => {
  it("matches the backend's tools_expression for valid tool names", () => {
    expect(toolsExpr(["get_ticket", "github:create-issue", "ns/tool.v2"])).toBe(
      "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['get_ticket', 'github:create-issue', 'ns/tool.v2', '']",
    );
  });

  it("escapes quotes and backslashes so a name can't end the CEL string literal", () => {
    // the backend refuses these names; the preview still never shows a broader condition than it says
    expect(toolsExpr(["x'] || true || ['"])).toBe("api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['x\\'] || true || [\\'', '']");
    expect(toolsExpr(["a\\"])).toBe("api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['a\\\\', '']");
    expect(accessFromCondition(toolsExpr(["x'] || true || ['"]))).toEqual({ mode: "tools", tools: ["x\\'] || true || [\\'"] });
  });
});

describe("default context", () => {
  it("uses the backend's Gemini Enterprise location default (us)", async () => {
    const { DEFAULT_CTX } = await import("../store");
    expect(DEFAULT_CTX.ge_location).toBe("us");
  });
});

describe("an always-true custom condition", () => {
  it("reads as full access, like the backend's english, and the lint says so (without blocking staging)", async () => {
    const { accessShort, accessWords, alwaysTrue, intentEnglish, lintExpression } = await import("./policy");
    const { blocking } = await import("../components/AccessChooser");
    for (const e of ["true", " (true) ", "true == true", "1==1", "!false"]) expect(alwaysTrue(e)).toBe(true);
    for (const e of ["false", "true && x", "(a) || (true)", "", "request.time < timestamp('2030-01-01T00:00:00Z')"]) expect(alwaysTrue(e)).toBe(false);
    expect(accessWords({ mode: "custom", expression: "true" })).toBe("full access (always-true condition)");
    expect(accessShort({ mode: "custom", expression: "true" })).toBe("full access");
    const g = { id: "g", kind: "grant" as const, source: { type: "custom" as const, principal: "user:a@example.com", label: "Alice" }, destination: { kind: "mcp_server" as const, id: "t", name: "t", label: "Tickets MCP" }, access: { mode: "custom" as const, expression: "true" } };
    expect(intentEnglish(g)).toBe("Alice can call Tickets MCP (full access: its custom condition is always true).");
    const lint = lintExpression("true");
    expect(lint[0]).toMatch(/^Always true/);
    expect(blocking(lint)).toBe(false);
  });
});

describe("missingContext", () => {
  it("doesn't ask for the Gemini Enterprise app: no generated code uses it", async () => {
    const { missingContext } = await import("./policy");
    const bind = { id: "b", kind: "bind_gateway" as const, engine: "e", gateway: { name: "g", direction: "ingress" as const } };
    expect(missingContext({ project: "p", region: "r" }, [bind])).toEqual([]);
    expect(missingContext({ project: "", region: "r" }, [bind])).toEqual(["Project ID is empty: commands use a placeholder."]);
  });
});
