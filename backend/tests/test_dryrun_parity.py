"""Member matching and condition evaluation agree with the frontend's port (frontend/src/map/evaluate.ts): both read
fixtures/egress_cases.json, so a change on one side fails the other side's test."""
import json
from pathlib import Path

import pytest

from policy_studio.dryrun import condition_allows, member_matches

CASES = json.loads((Path(__file__).parent / "fixtures" / "egress_cases.json").read_text())


@pytest.mark.parametrize("case", CASES["member_matches"], ids=lambda c: c["name"])
def test_member_matches(case):
    assert member_matches(case["member"], case["principal"]) is case["expected"]


@pytest.mark.parametrize("case", CASES["condition_allows"], ids=lambda c: c["name"])
def test_condition_allows(case):
    entry = {"mcp_method": case["mcp_method"], "mcp_tool": case["mcp_tool"]}
    assert condition_allows(case["condition"], entry, case["tools"]) is case["expected"]
