"""A tiny HCL writer that produces `terraform fmt`-clean output."""
from __future__ import annotations

import json
import re
from typing import Any


def q(s: str) -> str:
    """HCL quoted string literal (escapes quotes, backslashes, newlines and template sequences)."""
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + s.replace("${", "$${").replace("%{", "%%{") + '"'


def ident(s: str, max_len: int = 60) -> str:
    out = re.sub(r"[^a-z0-9_]+", "_", (s or "").lower()).strip("_")
    out = re.sub(r"_+", "_", out)[:max_len].strip("_") or "r"
    return out if not out[0].isdigit() else f"r_{out}"


def obj(value: Any, ind: int) -> str:
    """Python value -> HCL expression at nesting depth `ind` (multi-line objects, one key per line)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return q(value)
    if isinstance(value, list):
        if all(not isinstance(x, (dict, list)) for x in value):
            return "[" + ", ".join(obj(x, ind) for x in value) + "]"
        pad = "  " * (ind + 1)
        return "[\n" + "".join(f"{pad}{obj(x, ind + 1)},\n" for x in value) + "  " * ind + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        pad = "  " * (ind + 1)
        items = [(k if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) else json.dumps(k), obj(v, ind + 1))
                 for k, v in value.items()]
        return "{\n" + "".join(align(items, pad)) + "  " * ind + "}"
    raise TypeError(f"unsupported value {value!r}")


def align(items: list[tuple[str, str]], pad: str) -> list[str]:
    """`key = value` lines; consecutive single-line items share one `=` column, as terraform fmt does.
    A multi-line value ({...}, [...], fn(...)) ends the run and is not padded; a heredoc is padded, then ends it."""
    out: list[str] = []
    group: list[tuple[str, str]] = []

    def flush() -> None:
        w = max((len(k) for k, _ in group), default=0)
        out.extend(f"{pad}{k.ljust(w)} = {v}\n" for k, v in group)
        group.clear()

    for k, v in items:
        if v.startswith("<<"):           # a heredoc joins the current run, then ends it
            group.append((k, v))
            flush()
        elif "\n" in v:
            flush()
            out.append(f"{pad}{k} = {v}\n")
        else:
            group.append((k, v))
    flush()
    return out


def heredoc(text: str, ind: int, marker: str = "EOT") -> str:
    """Indented heredoc for an attribute at depth `ind`. `${` in the text is escaped. The marker gets a _<n> suffix
    when a line of the text is the marker (with <<- an indented one ends the heredoc too)."""
    pad = "  " * (ind + 1)
    body = text.replace("${", "$${").replace("%{", "%%{")
    taken, base, n = {ln.strip() for ln in body.split("\n")}, marker, 0
    while marker in taken:
        n += 1
        marker = f"{base}_{n}"
    lines = "".join(f"{pad}{ln}\n" if ln else "\n" for ln in body.rstrip("\n").split("\n"))
    return f"<<-{marker}\n{lines}{'  ' * ind}{marker}"




class Block:
    """HCL block: header + items (attributes, nested blocks, comments, blank lines)."""

    def __init__(self, header: str):
        self.header = header
        self.items: list[tuple] = []

    def attr(self, key: str, expr: str) -> "Block":
        self.items.append(("a", key, expr))
        return self

    def s(self, key: str, value: str) -> "Block":
        return self.attr(key, q(value))

    def blank(self) -> "Block":
        self.items.append(("",))
        return self

    def comment(self, text: str) -> "Block":
        for line in text.split("\n"):
            self.items.append(("c", line))
        return self

    def block(self, header: str) -> "Block":
        b = Block(header)
        self.items.append(("b", b))
        return b

    def render(self, ind: int = 0) -> str:
        pad, inner = "  " * ind, "  " * (ind + 1)
        out = [f"{pad}{self.header} {{\n"]
        group: list[tuple[str, str]] = []

        def flush() -> None:
            out.extend(align(group, inner))
            group.clear()

        for it in self.items:
            if it[0] == "a":
                group.append((it[1], it[2]))
                continue
            flush()
            if it[0] == "c":
                out.append(f"{inner}# {it[1]}".rstrip() + "\n")
            elif it[0] == "":
                out.append("\n")
            else:
                out.append(it[1].render(ind + 1))
        flush()
        out.append(f"{pad}}}\n")
        return "".join(out)


def commented(text: str) -> str:
    """Comment out a rendered HCL snippet line by line."""
    return "".join(f"# {ln}".rstrip() + "\n" for ln in text.rstrip("\n").split("\n"))


def comment_lines(text: str, width: int = 100) -> str:
    """Wrap prose into `# ` comment lines."""
    out: list[str] = []
    for para in text.split("\n"):
        words, cur = para.split(), ""
        if not words:
            out.append("#")
            continue
        for w in words:
            if cur and len(cur) + 1 + len(w) > width:
                out.append(f"# {cur}")
                cur = w
            else:
                cur = f"{cur} {w}" if cur else w
        out.append(f"# {cur}")
    return "\n".join(out) + "\n"
