// The same cases as backend/tests/test_dryrun_parity.py: a change to matching on either side fails the other's test.
import { describe, expect, it } from "vitest";
import cases from "../../../backend/tests/fixtures/egress_cases.json";
import { conditionAllows, evaluateTools, memberMatches } from "./evaluate";

describe("memberMatches (dryrun.member_matches)", () => {
  it.each(cases.member_matches.map((c) => [c.name, c] as const))("%s", (_, c) => {
    expect(memberMatches(c.member, c.principal)).toBe(c.expected);
  });
});

describe("conditionAllows (dryrun.condition_allows)", () => {
  it.each(cases.condition_allows.map((c) => [c.name, c] as const))("%s", (_, c) => {
    expect(conditionAllows(c.condition, { mcp_method: c.mcp_method, mcp_tool: c.mcp_tool }, c.tools)).toBe(c.expected);
  });
});

describe("evaluateTools", () => {
  const tools = { list_tickets: true, delete_ticket: false, add_note: false, constructor: false };
  it("splits an MCP server's tools by condition", () => {
    const ro = { title: "t", expression: "api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''" };
    expect(evaluateTools(ro, tools)).toEqual({ allowed: ["list_tickets"], denied: ["delete_ticket", "add_note", "constructor"], unknown: [] });
    expect(evaluateTools({ title: "c", expression: "request.time < timestamp('2030-01-01T00:00:00Z')" }, tools).unknown).toHaveLength(4);
    expect(evaluateTools(null, tools).allowed).toHaveLength(4);
  });
});
