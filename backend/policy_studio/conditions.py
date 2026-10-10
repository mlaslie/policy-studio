"""IAM condition expressions for MCP tool-level egress (IAP V1 on Agent Registry resources).

Verified live against Agent Gateway (Oct 2026):
  read-only by hint: api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true
                     || api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''
  tools by name:     api.getAttribute('iap.googleapis.com/mcp.toolName', '') in ['t1', 't2', '']
The `''` keeps MCP setup traffic (initialize, tools/list, notifications) allowed: it carries no tool name.
"""
from __future__ import annotations

import re
from typing import Optional

from .model import Access, Condition

EGRESSOR = "roles/iap.egressor"

READ_ONLY_EXPRESSION = ("api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || "
                        "api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''")
READ_ONLY_TITLE = "Read-only MCP tools (by hint)"

_TOOLS_RE = re.compile(
    r"^\s*api\.getAttribute\(\s*'iap\.googleapis\.com/mcp\.toolName'\s*,\s*''\s*\)\s+in\s+\[(.*)\]\s*$", re.S)


def _norm(expr: str) -> str:
    return re.sub(r"\s+", " ", (expr or "").strip())


def tools_expression(tools: list[str]) -> str:
    names = [t for t in dict.fromkeys(tools) if t]
    items = ", ".join(f"'{t}'" for t in [*names, ""])
    return f"api.getAttribute('iap.googleapis.com/mcp.toolName', '') in [{items}]"


def tools_title(tools: list[str]) -> str:
    title = "Only MCP tools: " + ", ".join(t for t in dict.fromkeys(tools) if t)
    return title if len(title) <= 100 else title[:97] + "..."


def condition_for(access: Optional[Access]) -> Optional[Condition]:
    """Access mode -> IAM condition (None = unconditional). `access.title` overrides the generated title."""
    if access is None or access.mode == "all":
        return None
    if access.mode == "read_only_hint":
        cond = Condition(title=READ_ONLY_TITLE, expression=READ_ONLY_EXPRESSION)
    elif access.mode == "tools":
        tools = access.tools or []
        cond = Condition(title=tools_title(tools), expression=tools_expression(tools))
    else:
        cond = Condition(title="Custom condition", expression=(access.expression or "").strip())
    if access.title:
        cond.title = access.title[:100]
    return cond


def parse_tools(expression: str, keep_empty: bool = False) -> Optional[list[str]]:
    """Tool names of a `toolName in [...]` expression ('' removed unless keep_empty), or None if it isn't one."""
    m = _TOOLS_RE.match(expression or "")
    if not m:
        return None
    inner = m.group(1)
    items = re.findall(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", inner)
    rest = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|,|\s", "", inner)
    if rest:
        return None
    return [a or b for a, b in items if (a or b) or keep_empty]


def classify(cond: Optional[Condition | dict]) -> Access:
    """Existing binding condition -> Access (the inverse of condition_for)."""
    if not cond:
        return Access(mode="all")
    expr = cond.get("expression", "") if isinstance(cond, dict) else cond.expression
    title = cond.get("title", "") if isinstance(cond, dict) else cond.title
    if _norm(expr) == _norm(READ_ONLY_EXPRESSION):
        return Access(mode="read_only_hint", title=title or None)
    tools = parse_tools(expr)
    if tools is not None:
        return Access(mode="tools", tools=tools, title=title or None)
    return Access(mode="custom", expression=expr, title=title or None)


def same_condition(a: Optional[Condition | dict], b: Optional[Condition | dict]) -> bool:
    """IAM treats bindings as distinct by expression; compare expressions (whitespace-insensitive)."""
    ea = (a.get("expression") if isinstance(a, dict) else a.expression) if a else ""
    eb = (b.get("expression") if isinstance(b, dict) else b.expression) if b else ""
    return _norm(ea or "") == _norm(eb or "")
