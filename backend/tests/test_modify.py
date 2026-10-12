"""The modify intent: change a grant's condition in one read-modify-write (apply, preflight, diff, render, English,
undo), and fixtures/modify_cases.json, which the frontend mock's test reads too."""
import itertools
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

import fakegcp as F
from policy_studio import service
from policy_studio.apply import modify_binding
from policy_studio.conditions import READ_ONLY_EXPRESSION, condition_for, tools_expression
from policy_studio.diff import diff
from policy_studio.model import Access, Binding, Condition, Context, Destination, Intent, Inventory, Source
from policy_studio.render import JQ_MODIFY, PY_IAP_HELPERS, PY_MODIFY_HELPER, RenderEnv, render
from test_apply import CTX, MCP_RES, Q, adc, client, final, gcp, run  # noqa: F401  (fixtures)
from test_render import ENV, JQ, TERRAFORM, check_syntax

P = F.principal("222")
CUSTOM = "request.time < timestamp('2030-01-01T00:00:00Z')"
TOOLS = ["list_tickets", "add_note"]
# Each access as the binding it writes (expression; None = unconditional) and as the builder / map stages it.
FORMS = {"all": (None, {"mode": "all"}),
         "read_only_hint": (READ_ONLY_EXPRESSION, {"mode": "read_only_hint"}),
         "tools": (tools_expression(TOOLS), {"mode": "tools", "tools": TOOLS}),
         "custom": (CUSTOM, {"mode": "custom", "expression": CUSTOM})}
DEST = {"kind": "mcp_server", "id": "agentregistry-mcp", "name": F.MCP, "label": "Tickets MCP"}
SRC = {"type": "engine", "principal": P, "label": "Pricing Analyst", "engine": F.E2}


def binding(expr, member=P, title="old"):
    return {"role": "roles/iap.egressor", "members": [member], **({"condition": {"title": title, "expression": expr}}
                                                                   if expr else {})}


def exact(expr, title="old"):
    """What the UI's grantToModify puts in access_from: the binding's condition verbatim."""
    return {"mode": "custom", "expression": expr, "title": title} if expr else {"mode": "all"}


def modify_intent(iid, frm, to, src=SRC):
    return {"id": iid, "kind": "modify", "source": src, "destination": DEST, "access_from": frm, "access": to}


def post(client, path, intents):
    return client.post(f"/api/studio/{path}", json={"context": CTX, "intents": intents}).json()["items"]


def canon(bindings):
    return sorted(json.dumps(b, sort_keys=True) for b in bindings)


# ------------------------------------------------------------------ every pair, end to end
@pytest.mark.parametrize("src,dst", list(itertools.permutations(FORMS, 2)))
def test_modify_round_trip(client, gcp, adc, src, dst):
    """Change the grant from one form to another: diff replace, preflight ok, apply verified with every other binding
    (same role, same member's other grant) untouched, then the undo puts the policy back."""
    other = next(k for k in FORMS if k not in (src, dst))
    gcp.iap[MCP_RES]["bindings"] += [binding(FORMS[src][0]), binding(FORMS[other][0], title="keep")]
    before = json.loads(json.dumps(gcp.iap[MCP_RES]["bindings"]))
    it = modify_intent("m", exact(FORMS[src][0]), FORMS[dst][1])

    d, = post(client, "diff", [it])
    assert d["status"] == "replace", d
    assert [(b.get("condition") or {}).get("expression") for b in d["after"]] == [FORMS[other][0], FORMS[dst][0]]
    pf, = post(client, "preflight", [it])
    assert pf["status"] == "ok", pf
    r, = post(client, "render", [it])
    assert not r.get("error") and r["english"].startswith("Change Pricing Analyst's access to Tickets MCP: ")

    f = final(run(client, [it]))["m"]                                   # not destructive: no acknowledgement
    assert f["state"] == "verified", f
    (method, url, body), = gcp.writes                                   # one setIamPolicy
    assert url.endswith(f"{MCP_RES}:setIamPolicy") and body["policy"]["etag"] == "e0"
    after = gcp.iap[MCP_RES]["bindings"]
    assert after[:-1] == [b for b in before if b != binding(FORMS[src][0])]
    new = condition_for(Access(**FORMS[dst][1]))
    assert after[-1] == binding(new.expression if new else None, title=new.title if new else "")

    undo = f["undo"]
    assert undo["kind"] == "modify" and undo["id"] == "undo-m"
    assert undo["access_from"] == exact(new.expression if new else None, new.title if new else "")
    assert undo["access"] == exact(FORMS[src][0])
    assert final(run(client, [undo]))["undo-m"]["state"] == "verified"
    assert canon(gcp.iap[MCP_RES]["bindings"]) == canon(before)


def test_modify_shared_binding_keeps_other_members(client, gcp, adc):
    """The member shares the binding with someone else: only the member moves to the new condition."""
    gcp.iap[MCP_RES]["bindings"].append({"role": "roles/iap.egressor", "members": ["user:x@example.com", P]})
    f = final(run(client, [modify_intent("m", {"mode": "all"}, {"mode": "read_only_hint"})]))["m"]
    assert f["state"] == "verified"
    b = gcp.iap[MCP_RES]["bindings"]
    assert {"role": "roles/iap.egressor", "members": ["user:x@example.com"]} in b
    assert b[-1]["members"] == [P] and b[-1]["condition"]["expression"] == READ_ONLY_EXPRESSION


def test_modify_retries_etag_conflict(client, gcp, adc):
    gcp.iap[MCP_RES]["bindings"].append(binding(None))
    gcp.etag_conflicts = 1
    ev = run(client, [modify_intent("m", {"mode": "all"}, {"mode": "read_only_hint"})])
    assert final(ev)["m"]["state"] == "verified"
    assert len(gcp.writes) == 2 and sum("etag conflict" in e.get("detail", "") for e in ev) == 1
    mine = [b for b in gcp.iap[MCP_RES]["bindings"] if P in b["members"]]
    assert mine == [binding(READ_ONLY_EXPRESSION, title="Read-only MCP tools (by hint)")]


def test_modify_not_found_is_blocked(client, gcp, adc):
    """The grant changed since it was read: preflight blocks it, and apply fails without writing."""
    gcp.iap[MCP_RES]["bindings"].append(binding(READ_ONLY_EXPRESSION))
    it = modify_intent("m", exact(tools_expression(["list_tickets"])), {"mode": "all"})
    pf, = post(client, "preflight", [it])
    assert pf["status"] == "blocked" and "changed since you looked" in pf["reason"]
    assert post(client, "diff", [it])[0]["status"] == "absent"
    f = final(run(client, [it]))["m"]
    assert f["state"] == "failed" and "changed since you looked" in f["detail"] and not gcp.writes


def test_modify_same_access_is_blocked(client, gcp, adc):
    gcp.iap[MCP_RES]["bindings"].append(binding(READ_ONLY_EXPRESSION))
    it = modify_intent("m", exact(READ_ONLY_EXPRESSION), {"mode": "read_only_hint"})
    pf, = post(client, "preflight", [it])
    assert pf["status"] == "blocked" and pf["fix"] == "already"
    assert any("same as the current one" in w for w in post(client, "render", [it])[0]["warnings"])


def test_modify_already_done_is_skipped(client, gcp, adc):
    """The old binding is gone and the new one is there (applied elsewhere): not blocked, diff present, skipped."""
    gcp.iap[MCP_RES]["bindings"].append(binding(READ_ONLY_EXPRESSION))
    it = modify_intent("m", {"mode": "all"}, {"mode": "read_only_hint"})
    assert post(client, "preflight", [it])[0]["status"] == "ok"
    assert post(client, "diff", [it])[0]["status"] == "present"
    f = final(run(client, [it]))["m"]
    assert f["state"] == "skipped" and "Already changed" in f["detail"] and not gcp.writes


def test_modify_widening_warns(client, gcp, adc):
    gcp.iap[MCP_RES]["bindings"].append(binding(READ_ONLY_EXPRESSION))
    it = modify_intent("m", exact(READ_ONLY_EXPRESSION), {"mode": "all"})
    pf, = post(client, "preflight", [it])
    assert pf["status"] == "ok" and pf["warning"] == "This widens access: only read-only tools → full access."
    gcp.iap[MCP_RES]["bindings"].append(binding(None))
    service.cache.clear()                                               # (a Sync)
    narrower, = post(client, "preflight", [modify_intent("n", {"mode": "all"}, {"mode": "read_only_hint"})])
    assert narrower["status"] == "ok" and "warning" not in narrower


def test_modify_validation(client):
    """modify needs source, destination, access_from and access; a bad item fails alone."""
    r = post(client, "render", [{"id": "bad", "kind": "modify", "source": SRC, "destination": DEST,
                                 "access": {"mode": "all"}},
                                modify_intent("ok", {"mode": "all"}, {"mode": "read_only_hint"})])
    assert r[0]["error"].startswith("invalid intent") and "access_from" in r[0]["error"]
    assert not r[1].get("error")


# ------------------------------------------------------------------ render
def test_modify_render_outputs():
    it = Intent.model_validate(modify_intent("m", exact(None), {"mode": "read_only_hint"}))
    item = render([it], ENV).items[0]
    o = item.outputs
    assert item.english == "Change Pricing Analyst's access to Tickets MCP: full access → only read-only tools."
    assert "gcloud iap web get-iam-policy" in o.gcloud and "gcloud iap web set-iam-policy policy-agentregistry-mcp" \
        in o.gcloud
    assert "web add-iam-policy-binding" not in o.gcloud and "web remove-iam-policy-binding" not in o.gcloud
    assert "--mcp-server=agentregistry-mcp" in o.gcloud and "FROM=''" in o.gcloud
    assert '--arg from "$FROM"' in o.rest and o.rest.count(":setIamPolicy") == 1
    assert "modify(" in o.python and "old_expression" not in o.python.split("modify(\n")[-1]
    assert "create_before_destroy = true" in o.terraform and "# Today:" in o.terraform
    assert item.anatomy.condition == READ_ONLY_EXPRESSION
    assert any("replaces the binding" in n for n in item.anatomy.notes)
    check_syntax(item)
    back = render([Intent.model_validate(modify_intent("u", exact(READ_ONLY_EXPRESSION), {"mode": "all"}))],
                  ENV).items[0]
    assert f"old_expression={json.dumps(READ_ONLY_EXPRESSION)}" in back.outputs.python
    assert "This widens access: only read-only tools → full access." in back.warnings
    check_syntax(back)


def test_modify_bundle(tmp_path):
    """A bundle with a modify next to a grant: Python helpers once, valid shell, Terraform fmt (and validate with
    STUDIO_TF_VALIDATE)."""
    src = Source(**SRC)
    res = render([Intent(id="g", kind="grant", source=src, destination=Destination(**DEST), access=Access(mode="all")),
                  Intent.model_validate(modify_intent("m", exact(READ_ONLY_EXPRESSION), FORMS["tools"][1]))], ENV)
    assert res.bundle.python.count("def modify(") == 1 and res.bundle.python.count("def grant(") == 1
    assert res.bundle.python.index("def _get_policy(") < res.bundle.python.index("def modify(")
    compile(res.bundle.python, "<bundle>", "exec")
    for text in (res.bundle.gcloud, res.bundle.rest):
        assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0
    main = res.bundle.terraform["main.tf"]
    assert "lifecycle {" in main
    if TERRAFORM:
        for k, v in res.bundle.terraform.items():
            (tmp_path / k).write_text(v)
        r = subprocess.run([TERRAFORM, "fmt", "-check", "-diff", str(tmp_path)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout
        if os.environ.get("STUDIO_TF_VALIDATE"):
            assert subprocess.run([TERRAFORM, "init", "-backend=false", "-input=false"], cwd=tmp_path,
                                  capture_output=True).returncode == 0
            r = subprocess.run([TERRAFORM, "validate"], cwd=tmp_path, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr


POLICY = {"etag": "BwX", "version": 1, "bindings": [
    {"role": "roles/iap.egressor", "members": ["user:a@x.com", "user:b@x.com"]},
    {"role": "roles/iap.egressor", "members": ["user:a@x.com"], "condition": {"title": "ro", "expression": "E"}}]}


def jq_modify(policy, member, frm, expr="", title=""):
    return subprocess.run([JQ, "--arg", "role", "roles/iap.egressor", "--arg", "member", member, "--arg", "title",
                           title, "--arg", "expr", expr, "--arg", "from", frm, JQ_MODIFY],
                          input=json.dumps(policy), capture_output=True, text=True)


@pytest.mark.skipif(not JQ, reason="jq not installed")
def test_jq_modify():
    r = jq_modify(POLICY, "user:a@x.com", "", "F", "t")                  # unconditional -> F
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["version"] == 3 and out["etag"] == "BwX"
    assert out["bindings"] == [{"role": "roles/iap.egressor", "members": ["user:b@x.com"]}, POLICY["bindings"][1],
                               {"role": "roles/iap.egressor", "members": ["user:a@x.com"],
                                "condition": {"title": "t", "expression": "F"}}]
    out = json.loads(jq_modify(POLICY, "user:a@x.com", "", "E").stdout)  # the new one exists already: no duplicate
    assert out["bindings"] == [{"role": "roles/iap.egressor", "members": ["user:b@x.com"]}, POLICY["bindings"][1]]
    r = jq_modify(POLICY, "user:c@x.com", "", "F")                       # not found: fails, nothing to write
    assert r.returncode != 0 and "was not found" in r.stderr and not r.stdout.strip()


def test_python_modify_helper_against_stub(monkeypatch):
    policy_pb2 = pytest.importorskip("google.iam.v1.policy_pb2")
    store = {"p": policy_pb2.Policy(etag=b"e", bindings=[
        policy_pb2.Binding(role="roles/iap.egressor", members=["user:a@x.com", "user:b@x.com"])])}

    class Client:
        def get_iam_policy(self, request):
            out = policy_pb2.Policy()
            out.CopyFrom(store[request.resource])
            return out

        def set_iam_policy(self, request):
            store[request.resource] = request.policy

    iap_v1 = types.ModuleType("google.cloud.iap_v1")
    iap_v1.IdentityAwareProxyAdminServiceClient = Client
    monkeypatch.setitem(sys.modules, "google.cloud.iap_v1", iap_v1)
    import google.cloud
    monkeypatch.setattr(google.cloud, "iap_v1", iap_v1, raising=False)
    ns: dict = {}
    exec(PY_IAP_HELPERS + "\n\n" + PY_MODIFY_HELPER, ns)
    ns["modify"]("p", "user:a@x.com", title="t", expression="E")
    b = store["p"].bindings
    assert store["p"].version == 3 and list(b[0].members) == ["user:b@x.com"]
    assert list(b[1].members) == ["user:a@x.com"] and b[1].condition.expression == "E"
    ns["modify"]("p", "user:a@x.com", old_expression="E")                                # back to unconditional
    assert [(list(x.members), x.condition.expression) for x in store["p"].bindings] == \
        [(["user:b@x.com"], ""), (["user:a@x.com"], "")]
    with pytest.raises(SystemExit):
        ns["modify"]("p", "user:z@x.com", expression="E")


# ------------------------------------------------------------------ the shared fixture (the mock runs it too)
MODIFY = json.loads((Path(__file__).parent / "fixtures" / "modify_cases.json").read_text())


def flat(policy_bindings):
    return [{"member": m, "expression": (b.get("condition") or {}).get("expression") or None}
            for b in policy_bindings for m in b["members"]]


@pytest.mark.parametrize("case", MODIFY["cases"], ids=lambda c: c["name"])
def test_modify_cases(case):
    member = MODIFY["member"]
    pol = {"etag": "e", "bindings": [binding(b["expression"], b["member"]) for b in case["bindings"]]}
    old, new = condition_for(Access(**case["access_from"])), condition_for(Access(**case["access"]))
    out, outcome, _ = modify_binding(pol, member, "roles/iap.egressor", old, new)
    assert outcome == case["outcome"]
    assert flat(out["bindings"]) == case["after"]
    inv = Inventory(access={F.MCP: [Binding(role="roles/iap.egressor", member=b["member"],
                                            condition=Condition(title="t", expression=b["expression"])
                                            if b["expression"] else None) for b in case["bindings"]]})
    it = Intent(id="m", kind="modify", source=Source(type="custom", principal=member, label="x"),
                destination=Destination(**DEST), access_from=Access(**case["access_from"]),
                access=Access(**case["access"]))
    assert diff([it], inv, [], RenderEnv(ctx=Context(project=F.P, region=F.R)))[0].status == case["status"]
