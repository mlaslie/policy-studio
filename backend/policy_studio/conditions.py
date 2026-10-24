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

from .model import Access, Condition, valid_tool_name

EGRESSOR = "roles/iap.egressor"

READ_ONLY_EXPRESSION = ("api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || "
                        "api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''")
READ_ONLY_TITLE = "Read-only MCP tools (by hint)"

_TOOLS_RE = re.compile(
    r"^\s*api\.getAttribute\(\s*'iap\.googleapis\.com/mcp\.toolName'\s*,\s*''\s*\)\s+in\s+\[(.*)\]\s*$", re.S)


def _norm(expr: str) -> str:
    return re.sub(r"\s+", " ", (expr or "").strip())


def cel_string(s: str) -> str:
    """A CEL single-quoted string literal. Access rejects tool names that would need escaping; this is defense in
    depth (frontend lib/policy.ts toolsExpr escapes the same way)."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def tools_expression(tools: list[str]) -> str:
    names = [t for t in dict.fromkeys(tools) if t]
    items = ", ".join(cel_string(t) for t in [*names, ""])
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
    if tools is not None and all(valid_tool_name(t) for t in tools):
        return Access(mode="tools", tools=tools, title=title or None)
    return Access(mode="custom", expression=expr, title=title or None)


def exact_access(cond: Optional[Condition | dict]) -> Access:
    """An existing binding's condition, verbatim, as Access: mode "custom" with its exact expression and title (None
    = unconditional, mode "all"). For revokes (and the undo of a revoke) built from a binding that exists: classify()
    would regenerate the expression (a tools list gains '', quotes and order are normalized), and IAM matches a
    binding by its exact expression, so the revoke would find nothing."""
    if not cond:
        return Access(mode="all")
    expr = cond.get("expression", "") if isinstance(cond, dict) else cond.expression
    title = cond.get("title", "") if isinstance(cond, dict) else cond.title
    if not (expr or "").strip():
        return Access(mode="all")
    return Access(mode="custom", expression=expr, title=title or None)


def same_condition(a: Optional[Condition | dict], b: Optional[Condition | dict]) -> bool:
    """IAM treats bindings as distinct by expression; compare expressions (whitespace-insensitive)."""
    ea = (a.get("expression") if isinstance(a, dict) else a.expression) if a else ""
    eb = (b.get("expression") if isinstance(b, dict) else b.expression) if b else ""
    return _norm(ea or "") == _norm(eb or "")


def _effective(acc: Optional[Access]) -> Access:
    """An Access as what it does: an exact (custom) expression that is one of the known forms is classified."""
    if acc is None:
        return Access(mode="all")
    if acc.mode == "custom":
        return classify({"expression": acc.expression or ""}) if (acc.expression or "").strip() else Access(mode="all")
    return acc


def compare_access(old: Optional[Access], new: Optional[Access], read_only: Optional[set[str]] = None) -> str:
    """How a modify changes access: "same" | "narrower" | "broader" | "unknown". `read_only`: names of the MCP
    server's read-only tools (None = not known), used to compare a tools list with the read-only hint."""
    a, b = _effective(old), _effective(new)
    if same_condition(condition_for(a), condition_for(b)):
        return "same"
    if b.mode == "all":
        return "broader"
    if a.mode == "all":
        return "narrower"
    if a.mode == "tools" and b.mode == "tools":
        ta, tb = {t for t in a.tools or [] if t}, {t for t in b.tools or [] if t}
        if ta == tb:                               # the same tools in another order (or repeated)
            return "same"
        return "broader" if tb - ta else "narrower"
    if a.mode == "read_only_hint" and b.mode == "tools" and read_only is not None:
        return "broader" if set(b.tools or []) - read_only else "narrower"
    if a.mode == "tools" and b.mode == "read_only_hint" and read_only is not None:
        # the hint also covers read-only tools added later
        return "broader" if read_only - set(a.tools or []) else "unknown"
    return "unknown"


def _tool_set(acc: Access, read_only: Optional[set[str]]) -> Optional[set[str]]:
    """The tools an access allows, as a set (None = every tool). Raises LookupError when it can't be told here (a
    custom condition, or the read-only hint without the server's tool list)."""
    if acc.mode == "all":
        return None
    if acc.mode == "tools":
        return {t for t in acc.tools or [] if t}
    if acc.mode == "read_only_hint" and read_only is not None:
        return set(read_only)
    raise LookupError(acc.mode)


def compare_access_many(old: list[Access], new: list[Access], read_only: Optional[set[str]] = None) -> str:
    """compare_access for a modify with several bindings: IAM ORs a member's bindings, so what is allowed today is the
    union of `old` and after it the union of `new`. [] after = "narrower" (the remove-all form). One binding each way
    is compare_access."""
    if len(old) == 1 and len(new) == 1:
        return compare_access(old[0], new[0], read_only)
    if not new:
        return "narrower"
    a, b = [_effective(x) for x in old], [_effective(x) for x in new]
    norm = lambda xs: sorted({_norm((condition_for(x) or Condition()).expression) for x in xs})  # noqa: E731
    if norm(a) == norm(b):
        return "same"
    try:
        sets_a = [_tool_set(x, read_only) for x in a]
        sets_b = [_tool_set(x, read_only) for x in b]
    except LookupError:
        # can't be told per tool: broader only when every old binding alone is narrower than the new access
        verdicts = {compare_access(x, y, read_only) for x in old for y in new}
        return "broader" if verdicts == {"broader"} else "unknown"
    union_a = None if any(s is None for s in sets_a) else set().union(*sets_a)
    union_b = None if any(s is None for s in sets_b) else set().union(*sets_b)
    if union_b is None:
        return "same" if union_a is None else "broader"
    if union_a is None:
        return "narrower"
    if union_b - union_a:
        return "broader"
    # the read-only hint also covers read-only tools added later: only "narrower" when one was there before
    hint_b = any(x.mode == "read_only_hint" for x in b)
    hint_a = any(x.mode == "read_only_hint" for x in a)
    return "unknown" if hint_b and not hint_a else "narrower"
