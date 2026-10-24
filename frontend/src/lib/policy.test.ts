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
