"""policy_studio must stay extractable: no imports from the demo (agdemo_core / agdemo_ui) and read-only GCP."""
import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1] / "policy_studio"
FILES = sorted(PKG.rglob("*.py"))
ALLOWED_THIRD_PARTY = {"fastapi", "pydantic", "google", "starlette", "requests", "uvicorn"}


def imports(path: Path) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.append(node.module)
    return out


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(PKG)))
def test_no_demo_imports(path):
    for mod in imports(path):
        top = mod.split(".")[0]
        assert top not in ("agdemo_core", "agdemo_ui", "ui"), f"{path.name} imports {mod}"
        assert top in sys.stdlib_module_names or top in ALLOWED_THIRD_PARTY or top == "policy_studio", \
            f"{path.name} imports unexpected package {mod}"


def test_no_demo_imports_at_runtime():
    """Import every module in a fresh interpreter; nothing from the demo may be loaded."""
    code = ("import importlib, pkgutil, sys, policy_studio\n"
            "for m in pkgutil.walk_packages(policy_studio.__path__, 'policy_studio.'):\n"
            "    importlib.import_module(m.name)\n"
            "bad = [m for m in sys.modules if m.split('.')[0] in ('agdemo_core', 'agdemo_ui')]\n"
            "assert not bad, bad\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=PKG.parent, capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(PKG.parent)})
    assert r.returncode == 0, r.stderr


def test_gcp_layer_is_read_only():
    """No write verbs or write RPCs in the GCP layer (except writer.py, the apply-mode-only write path); the read
    client refuses non-read POSTs."""
    from policy_studio.gcp.rest import Rest

    for path in (PKG / "gcp").glob("*.py"):
        if path.name == "writer.py":
            continue
        src = path.read_text()
        assert not re.search(r"\.(patch|put|delete)\(", src), path.name
        assert not re.search(r'"(PATCH|PUT|DELETE)"', src), path.name
        for rpc in (":setIamPolicy", ":batchEnable", ":enable"):
            assert rpc not in src, (path.name, rpc)

    r = Rest(credentials=object())
    with pytest.raises(ValueError):
        r.post("https://iap.googleapis.com/v1/projects/1/locations/r/iap_web/agentRegistry:setIamPolicy", json={})
    with pytest.raises(ValueError):
        r.post("https://networksecurity.googleapis.com/v1/projects/p/locations/r/authzPolicies", json={})


def test_writes_only_through_writer():
    """Only gcp/writer.py issues write verbs (rest.py's POST is limited to read-only RPCs, tested above)."""
    for path in FILES:
        if path.name in ("writer.py", "rest.py"):
            continue
        src = path.read_text()
        assert not re.search(r"_request\(\s*\"(POST|PATCH|PUT|DELETE)\"", src), path.name
