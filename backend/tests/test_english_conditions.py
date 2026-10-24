import pytest

import fakegcp as F
from policy_studio.conditions import (READ_ONLY_EXPRESSION, classify, condition_for, parse_tools, same_condition,
                                      tools_expression)
from policy_studio.english import condition_english, intent_english, make_binding, member_label
from policy_studio.model import Access, Destination, GatewayRef, Intent, Source


# ------------------------------------------------------------------ conditions
def test_read_only_expression_is_the_verified_one():
    assert READ_ONLY_EXPRESSION == ("api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || "
                                    "api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''")


def test_tools_expression_keeps_setup_traffic():
    assert tools_expression(["get_ticket", "list_tickets", "get_ticket"]) == \
        "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['get_ticket', 'list_tickets', '']"
    assert tools_expression([]) == "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['']"


@pytest.mark.parametrize("name", [
    "x', 'anything",                          # ends the literal: the list would gain a second name
    "x'] || true || ['",                      # makes the condition always true
    "a\\", "a b", "", "x" * 129, "tool\n", "\u00e9",
])
def test_hostile_tool_names_are_rejected(name):
    if not name:
        assert Access(mode="tools", tools=[name]).tools == [""]     # '' is ignored (setup traffic), not refused
        return
    with pytest.raises(ValueError, match="not allowed in a condition"):
        Access(mode="tools", tools=["get_ticket", name])


@pytest.mark.parametrize("name", ["get_ticket", "tickets.get", "github:create-issue", "ns/tool", "a" * 128])
def test_valid_tool_names(name):
    acc = Access(mode="tools", tools=[name])
    assert condition_for(acc).expression == f"api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['{name}', '']"


def test_tools_expression_escapes_as_defense_in_depth():
    # Access refuses these; tools_expression still never lets a name end the CEL string literal
    assert tools_expression(["x'] || true || ['"]) == \
        "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['x\\'] || true || [\\'', '']"
    assert tools_expression(["a\\"]) == "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['a\\\\', '']"
    assert parse_tools(tools_expression(["x'] || true || ['"])) == ["x\\'] || true || [\\'"]     # one name


def test_existing_condition_with_odd_tool_name_is_custom():
    expr = "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['a b', '']"
    assert classify({"expression": expr, "title": "t"}).mode == "custom"


@pytest.mark.parametrize("access,expr", [
    (Access(mode="all"), None),
    (None, None),
    (Access(mode="read_only_hint"), READ_ONLY_EXPRESSION),
    (Access(mode="tools", tools=["a"]), "api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['a', '']"),
    (Access(mode="custom", expression="  request.time < timestamp('2027-01-01T00:00:00Z') "),
     "request.time < timestamp('2027-01-01T00:00:00Z')"),
])
def test_condition_for(access, expr):
    c = condition_for(access)
    assert (c.expression if c else None) == expr
    if c:
        assert c.title and len(c.title) <= 100


def test_condition_title_override_and_truncation():
    assert condition_for(Access(mode="read_only_hint", title="ro")).title == "ro"
    long = condition_for(Access(mode="tools", tools=[f"tool_number_{i}" for i in range(20)]))
    assert len(long.title) == 100 and long.title.endswith("...")


@pytest.mark.parametrize("access", [
    Access(mode="all"), Access(mode="read_only_hint"), Access(mode="tools", tools=["x", "y_z"]),
    Access(mode="custom", expression="request.time < timestamp('2027-01-01T00:00:00Z')")])
def test_classify_round_trip(access):
    back = classify(condition_for(access))
    assert back.mode == access.mode
    if access.mode == "tools":
        assert back.tools == access.tools
    if access.mode == "custom":
        assert back.expression == access.expression


def test_parse_tools_and_same_condition():
    assert parse_tools("api.getAttribute('iap.googleapis.com/mcp.toolName', '') in [\"a\", 'b', '']") == ["a", "b"]
    assert parse_tools("api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['a'] || true") is None
    assert same_condition({"expression": READ_ONLY_EXPRESSION}, {"expression": READ_ONLY_EXPRESSION.replace(" ", "  ")})
    assert same_condition(None, None) and not same_condition(None, {"expression": "x"})


# ------------------------------------------------------------------ english
def test_member_labels():
    engines = {F.principal("111"): "HR Assistant"}
    assert member_label(F.principal("111"), engines) == "HR Assistant (Agent Identity)"
    assert member_label(F.principal("999")) == "Agent Runtime engine 999 (Agent Identity)"
    assert member_label(F.PROJECT_SET) == "All agents in project"
    for m in ("user:a@b.com", "group:g@b.com", "serviceAccount:x@p.iam.gserviceaccount.com"):
        assert member_label(m) == m
    assert "allUsers" in member_label("allUsers")


def test_condition_english():
    assert condition_english(None) == "all tools"
    assert condition_english({"expression": READ_ONLY_EXPRESSION}) == "only read-only tools (by MCP hint)"
    assert condition_english({"expression": tools_expression(["a", "b"])}) == "only tools: a, b"
    assert condition_english({"expression": "request.time < timestamp('2027-01-01T00:00:00Z')"}) == "custom condition"


def test_binding_english_by_kind():
    b = make_binding("roles/iap.egressor", F.PROJECT_SET, None, "Weather API", "endpoint")
    assert b.english == "All agents in project → Weather API: full access"
    b = make_binding("roles/iap.egressor", "user:a@b.com", {"title": "t", "expression": READ_ONLY_EXPRESSION},
                     "Tickets MCP", "mcp_server")
    assert b.english == "user:a@b.com → Tickets MCP: only read-only tools (by MCP hint)"
    assert b.condition.title == "t"


def test_intent_english():
    src = Source(type="engine", principal=F.principal("111"), label="HR Assistant")
    dst = Destination(kind="mcp_server", id="x", label="Tickets MCP")
    g = Intent(id="1", kind="grant", source=src, destination=dst, access=Access(mode="read_only_hint"))
    assert intent_english(g).startswith("HR Assistant can call only the read-only tools of Tickets MCP")
    r = Intent(id="2", kind="revoke", source=src, destination=dst, access=Access(mode="tools", tools=["a"]))
    assert intent_english(r) == "Revoke: HR Assistant can no longer call only these tools of Tickets MCP: a."
    a2a = Intent(id="3", kind="grant", source=src, destination=Destination(kind="agent", id="k", label="KB"))
    assert intent_english(a2a) == "HR Assistant can call KB (full access)."
    ma = Intent(id="4", kind="model_armor_on", gateway=GatewayRef(name=F.EG))
    assert intent_english(ma) == "Screen traffic on Agent Gateway corp-out with Model Armor."
