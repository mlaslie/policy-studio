import json
import os
import re
import shutil
import subprocess
import sys
import types

import pytest

import fakegcp as F
from policy_studio.conditions import READ_ONLY_EXPRESSION
from policy_studio.model import Access, Context, Destination, GatewayRef, Intent, Source
from policy_studio.render import JQ_ADD, JQ_REMOVE, PY_IAP_HELPERS, RenderEnv, render, shq

TERRAFORM = shutil.which("terraform") or ("/opt/homebrew/bin/terraform"
                                          if os.path.exists("/opt/homebrew/bin/terraform") else None)
JQ = shutil.which("jq")
CTX = Context(project=F.P, region=F.R, project_number=F.N, gateway_project_number=F.N, ge_app="hr-app")
ENV = RenderEnv(ctx=CTX, engines={F.E1: {"egress": F.EG}, F.E2: {}, F.E3: {}},
                engine_info={F.E1: {"display_name": "HR Assistant", "bindable": True},
                             F.E2: {"display_name": "Pricing Analyst", "bindable": True},
                             F.E3: {"display_name": "Legacy Bot", "bindable": False}},
                mcp_tools={"agentregistry-mcp": [{"name": "list_tickets", "read_only": True},
                                                 {"name": "delete_ticket", "read_only": False}]})
HR = Source(type="engine", principal=F.principal("111"), label="HR Assistant", engine=F.E1)
ALL = Source(type="project_agents", principal=F.PROJECT_SET, label="All agents in project")
DEST = {"agent": Destination(kind="agent", id="agentregistry-aaa", name=F.AGENT_A, label="KB Agent"),
        "mcp_server": Destination(kind="mcp_server", id="agentregistry-mcp", name=F.MCP, label="Tickets MCP"),
        "endpoint": Destination(kind="endpoint", id="agentregistry-ep", name=F.EP, label="Weather API")}
CUSTOM = 'request.time < timestamp("2027-01-01T00:00:00Z") && api.getAttribute(\'iap.googleapis.com/mcp.toolName\', \'\') != "x"'
ACCESS = {"all": Access(mode="all"), "read_only_hint": Access(mode="read_only_hint"),
          "tools": Access(mode="tools", tools=["list_tickets", "get_ticket"]),
          "custom": Access(mode="custom", expression=CUSTOM)}


def one(intent, env=ENV):
    return render([intent], env).items[0]


def check_syntax(item):
    for k in ("gcloud", "rest"):
        r = subprocess.run(["bash", "-n"], input=item.outputs.model_dump()[k], capture_output=True, text=True)
        assert r.returncode == 0, (k, r.stderr)
    compile(item.outputs.python, "<python>", "exec")
    if TERRAFORM:
        r = subprocess.run([TERRAFORM, "fmt", "-check", "-"], input=item.outputs.terraform, capture_output=True,
                           text=True)
        assert r.returncode == 0, item.outputs.terraform


# ------------------------------------------------------------------ grant / revoke, every kind and mode
@pytest.mark.parametrize("op", ["grant", "revoke"])
@pytest.mark.parametrize("kind", ["agent", "mcp_server", "endpoint"])
@pytest.mark.parametrize("mode", list(ACCESS))
def test_iam_matrix(op, kind, mode):
    it = one(Intent(id="x", kind=op, source=HR, destination=DEST[kind], access=ACCESS[mode]))
    o = it.outputs
    flag = {"agent": "--agent", "mcp_server": "--mcp-server", "endpoint": "--endpoint"}[kind]
    coll = {"agent": "agents", "mcp_server": "mcpServers", "endpoint": "endpoints"}[kind]
    rid = DEST[kind].id
    # anatomy
    assert it.anatomy.resource == f"projects/{F.N}/locations/{F.R}/iap_web/agentRegistry/{coll}/{rid}"
    assert it.anatomy.role == "roles/iap.egressor" and it.anatomy.member == F.principal("111")
    # gcloud
    verb = "add-iam-policy-binding" if op == "grant" else "remove-iam-policy-binding"
    assert f"gcloud iap web {verb}" in o.gcloud
    for part in (f"--project={F.P}", "--resource-type=agent-registry", f"--region={F.R}", f"{flag}={rid}",
                 f"--member={F.principal('111')}", "--role=roles/iap.egressor"):
        assert part in o.gcloud
    # Terraform
    res = {"agent": "agent", "mcp_server": "mcp_server", "endpoint": "endpoint"}[kind]
    assert f'resource "google_iap_agent_registry_{res}_iam_member"' in o.terraform
    assert re.search(rf'{res}_id\s+= "{rid}"', o.terraform)
    # REST + Python
    assert f"https://iap.googleapis.com/v1/projects/{F.N}/locations/{F.R}/iap_web/agentRegistry/{coll}/{rid}" in o.rest
    assert ("grant(" if op == "grant" else "revoke(") in o.python
    if mode == "all":
        assert "--condition=None" in o.gcloud and "condition {" not in o.terraform and it.anatomy.condition is None
    else:
        assert "condition {" in o.terraform and it.anatomy.condition
        assert "expression=" in o.python
        if mode == "custom":
            assert "--condition-from-file=" in o.gcloud and "EXPR=$(cat <<'EOF'" in o.rest
        else:
            assert "--condition=" in o.gcloud and "^~^title=" in o.gcloud
    if op == "revoke":
        assert not any(ln.startswith("resource") for ln in o.terraform.splitlines())    # commented out
    if kind != "mcp_server" and mode != "all":
        assert any("only apply to MCP servers" in w for w in it.warnings)
    check_syntax(it)


def test_read_only_grant_snapshot():
    it = one(Intent(id="g", kind="grant", source=HR, destination=DEST["mcp_server"], access=ACCESS["read_only_hint"]))
    assert it.english == ("HR Assistant can call only the read-only tools of Tickets MCP (by MCP hint; new read-only "
                          "tools are included automatically).")
    assert it.outputs.gcloud.splitlines()[-1] == (
        "  --condition=\"^~^title=Read-only MCP tools (by hint)~expression=" + READ_ONLY_EXPRESSION + "\"")
    assert '    expression = "' + READ_ONLY_EXPRESSION + '"' in it.outputs.terraform
    assert any("''" in n for n in it.anatomy.notes)
    assert not it.warnings


def test_project_agents_and_tool_warnings():
    it = one(Intent(id="t", kind="grant", source=ALL, destination=DEST["mcp_server"],
                    access=Access(mode="tools", tools=["list_tickets", "nope"])))
    assert any("nope" in w for w in it.warnings)
    assert F.PROJECT_SET in it.outputs.gcloud and "principalSet" in it.anatomy.notes[2]
    empty = one(Intent(id="e", kind="grant", source=ALL, destination=DEST["mcp_server"], access=Access(mode="tools")))
    assert any("No tools selected" in w for w in empty.warnings)


def test_grant_for_unbound_engine_warns():
    src = Source(type="engine", principal=F.principal("222"), label="Pricing Analyst", engine=F.E2)
    it = one(Intent(id="u", kind="grant", source=src, destination=DEST["agent"]))
    assert any("isn't bound to an egress gateway" in w for w in it.warnings)


# ------------------------------------------------------------------ bind / unbind
def body_of(rest: str) -> dict:
    return json.loads(rest.split("-d '", 1)[1].split("'", 1)[0])


def test_bind_preserves_other_direction():
    env = RenderEnv(ctx=CTX, engines={F.E1: {"ingress": F.IG}})
    it = one(Intent(id="b", kind="bind_gateway", engine=F.E1, gateway=GatewayRef(name="corp-out")), env)
    cfg = body_of(it.outputs.rest)["spec"]["deploymentSpec"]["agentGatewayConfig"]
    assert cfg == {"agentToAnywhereConfig": {"agentGateway": F.EG}, "clientToAgentConfig": {"agentGateway": F.IG}}
    assert f"https://{F.R}-aiplatform.googleapis.com/v1/{F.E1}?updateMask=spec.deploymentSpec.agentGatewayConfig" \
        in it.outputs.rest
    assert "No gcloud command manages Agent Runtime engines" in it.outputs.gcloud
    assert 'resource "terraform_data"' in it.outputs.terraform and "google_vertex_ai_reasoning_engine" in \
        it.outputs.terraform
    assert "set_gateway_config(" in it.outputs.python and "AuthorizedSession" in it.outputs.python
    assert it.anatomy.resource == F.E1
    check_syntax(it)


def test_unbind_last_direction_sends_empty_config():
    it = one(Intent(id="u", kind="unbind_gateway", engine=F.E1, gateway=GatewayRef(name=F.EG)))
    assert body_of(it.outputs.rest) == {"spec": {"deploymentSpec": {"agentGatewayConfig": {}}}}
    check_syntax(it)


def test_bind_warnings():
    old = one(Intent(id="o", kind="bind_gateway", engine=F.E3, gateway=GatewayRef(name=F.EG)))
    assert old.error and "can't be bound" in old.error and not old.error.startswith("Blocked")
    unknown = one(Intent(id="n", kind="bind_gateway", engine="projects/1/locations/x/reasoningEngines/5",
                         gateway=GatewayRef(name=F.EG)))
    assert any("unknown" in w for w in unknown.warnings)


def test_bundle_merges_changes_to_one_engine():
    env = RenderEnv(ctx=CTX, engines={F.E1: {"ingress": F.IG}})
    res = render([Intent(id="b", kind="bind_gateway", engine=F.E1, gateway=GatewayRef(name=F.EG)),
                  Intent(id="u", kind="unbind_gateway", engine=F.E1,
                         gateway=GatewayRef(name=F.IG, direction="ingress"))], env)
    second = res.items[1]
    assert body_of(second.outputs.rest)["spec"]["deploymentSpec"]["agentGatewayConfig"] == \
        {"agentToAnywhereConfig": {"agentGateway": F.EG}}
    assert any("earlier staged change" in n for n in second.anatomy.notes) and not second.warnings
    assert res.bundle.gcloud.count("-X PATCH") == 1
    assert res.bundle.terraform["main.tf"].count('resource "terraform_data"') == 1


# ------------------------------------------------------------------ Model Armor
def test_model_armor_on_off():
    ext = f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-ma"
    on = one(Intent(id="m", kind="model_armor_on", gateway=GatewayRef(name="corp-out", extension=ext)))
    assert "gcloud network-security authz-policies import corp-out-ma-policy" in on.outputs.gcloud
    assert "policyProfile: CONTENT_AUTHZ" in on.outputs.gcloud and f"- {ext}" in on.outputs.gcloud
    assert 'policy_profile = "CONTENT_AUTHZ"' in on.outputs.terraform
    assert "authzPolicies?authzPolicyId=corp-out-ma-policy" in on.outputs.rest
    assert body_of(on.outputs.rest)["customProvider"] == {"authzExtension": {"resources": [ext]}}
    assert "model_armor_on(" in on.outputs.python and not on.warnings
    check_syntax(on)
    off = one(Intent(id="f", kind="model_armor_off", gateway=GatewayRef(name="corp-in", direction="ingress",
                                                                       policy="corp-in-ma")))
    assert "authz-policies delete corp-in-ma" in off.outputs.gcloud and "-X DELETE" in off.outputs.rest
    assert off.outputs.terraform.count("\n# resource") == 1
    check_syntax(off)
    missing = one(Intent(id="x", kind="model_armor_on", gateway=GatewayRef(name="corp-out")))
    assert any("MODEL_ARMOR_EXTENSION" in w for w in missing.warnings)


# ------------------------------------------------------------------ bundle
def bundle_intents():
    return [Intent(id="g1", kind="grant", source=HR, destination=DEST["mcp_server"], access=ACCESS["read_only_hint"]),
            Intent(id="g2", kind="grant", source=HR, destination=DEST["mcp_server"], access=ACCESS["tools"]),
            Intent(id="g3", kind="grant", source=ALL, destination=DEST["endpoint"]),
            Intent(id="g4", kind="grant", source=HR, destination=DEST["agent"], access=ACCESS["custom"]),
            Intent(id="r1", kind="revoke", source=HR, destination=DEST["mcp_server"]),
            Intent(id="b1", kind="bind_gateway", engine=F.E2, gateway=GatewayRef(name="corp-out")),
            Intent(id="m1", kind="model_armor_on", gateway=GatewayRef(
                name="corp-out", extension=f"projects/{F.P}/locations/{F.R}/authzExtensions/corp-ma")),
            Intent(id="m2", kind="model_armor_off", gateway=GatewayRef(name="corp-in", direction="ingress"))]


def test_bundle_order_and_syntax(tmp_path):
    res = render(bundle_intents(), ENV)
    sh = res.bundle.gcloud
    assert sh.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in sh
    assert sh.index("-X PATCH") < sh.index("authz-policies import") < sh.index("add-iam-policy-binding")
    for text in (res.bundle.gcloud, res.bundle.rest):
        assert subprocess.run(["bash", "-n"], input=text, text=True).returncode == 0
    compile(res.bundle.python, "<bundle>", "exec")
    main = res.bundle.terraform["main.tf"]
    assert "local.gateway_project" in main and "var.region" in main
    assert f'default     = "{F.P}"' in res.bundle.terraform["variables.tf"]
    assert 'default     = "hr-app"' in res.bundle.terraform["variables.tf"]
    names = [ln.split('"')[3] for ln in main.splitlines() if ln.startswith("resource ")]
    assert len(names) == len(set(names))
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


def test_shq():
    assert shq("roles/iap.egressor") == "roles/iap.egressor"
    assert shq("a b") == "'a b'"
    assert shq("it's") == '"it\'s"'
    assert shq("it's $x") == "'it'\"'\"'s $x'"


# ------------------------------------------------------------------ the generated jq and Python actually work
POLICY = {"etag": "BwX", "version": 1, "bindings": [
    {"role": "roles/iap.egressor", "members": ["user:a@x.com", "user:b@x.com"]},
    {"role": "roles/iap.egressor", "members": ["user:a@x.com"], "condition": {"title": "ro", "expression": "E"}}]}


def jq(filt, policy, member, expr="", title=""):
    r = subprocess.run([JQ, "--arg", "role", "roles/iap.egressor", "--arg", "member", member, "--arg", "title", title,
                        "--arg", "expr", expr, filt], input=json.dumps(policy), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["policy"]


@pytest.mark.skipif(not JQ, reason="jq not installed")
def test_jq_filters():
    added = jq(JQ_ADD, POLICY, "user:c@x.com", "F", "t")
    assert added["version"] == 3 and added["etag"] == "BwX"
    assert added["bindings"][-1] == {"role": "roles/iap.egressor", "members": ["user:c@x.com"],
                                     "condition": {"title": "t", "expression": "F"}}
    assert jq(JQ_ADD, POLICY, "user:a@x.com", "E")["bindings"] == POLICY["bindings"]          # idempotent
    assert jq(JQ_ADD, {"etag": "x"}, "user:z@x.com")["bindings"] == [{"role": "roles/iap.egressor",
                                                                     "members": ["user:z@x.com"]}]
    removed = jq(JQ_REMOVE, POLICY, "user:a@x.com", "E")                 # only the conditional one
    assert removed["bindings"] == [POLICY["bindings"][0]]
    removed = jq(JQ_REMOVE, POLICY, "user:a@x.com")                      # only the unconditional one
    assert removed["bindings"] == [{"role": "roles/iap.egressor", "members": ["user:b@x.com"]}, POLICY["bindings"][1]]


def test_python_iap_helpers_against_stub(monkeypatch):
    policy_pb2 = pytest.importorskip("google.iam.v1.policy_pb2")

    store = {"p": policy_pb2.Policy(etag=b"e", bindings=[policy_pb2.Binding(role="roles/iap.egressor",
                                                                           members=["user:a@x.com", "user:b@x.com"])])}

    class Client:
        def get_iam_policy(self, request):
            assert request.options.requested_policy_version == 3
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
    exec(PY_IAP_HELPERS, ns)
    ns["grant"]("p", "user:c@x.com", title="t", expression="E")
    assert store["p"].version == 3 and store["p"].bindings[-1].condition.expression == "E"
    ns["grant"]("p", "user:c@x.com", title="t", expression="E")                          # no duplicate
    assert len(store["p"].bindings) == 2
    ns["revoke"]("p", "user:a@x.com")                                                    # unconditional only
    assert list(store["p"].bindings[0].members) == ["user:b@x.com"]
    ns["revoke"]("p", "user:c@x.com", expression="E")
    assert len(store["p"].bindings) == 1


def test_staged_binding_silences_unbound_warning():
    src = Source(type="engine", principal=F.principal("222"), label="Pricing Analyst", engine=F.E2)
    res = render([Intent(id="g", kind="grant", source=src, destination=DEST["agent"]),
                  Intent(id="b", kind="bind_gateway", engine=F.E2, gateway=GatewayRef(name="corp-out"))], ENV)
    assert not any("isn't bound" in w for w in res.items[0].warnings)


def test_registry_wide_grant_and_revoke():
    reg = Destination(kind="registry", id="", name=f"projects/{F.P}/locations/{F.R}", label="Agent Registry")
    it = one(Intent(id="r", kind="revoke", source=ALL, destination=reg))
    assert it.anatomy.resource == f"projects/{F.N}/locations/{F.R}/iap_web/agentRegistry"
    assert "--resource-type=agent-registry" in it.outputs.gcloud
    assert not any(f in it.outputs.gcloud for f in ("--agent=", "--mcp-server=", "--endpoint="))
    assert "google_iap_agent_registry_iam_member" in it.outputs.terraform
    assert f"RESOURCE=https://iap.googleapis.com/v1/projects/{F.N}/locations/{F.R}/iap_web/agentRegistry\n" in \
        it.outputs.rest
    check_syntax(it)
    g = one(Intent(id="g", kind="grant", source=ALL, destination=reg, access=ACCESS["read_only_hint"]))
    assert not g.warnings and "_id" not in g.outputs.terraform.split("role")[0]


def test_intent_ignores_unknown_fields_and_bad_intent_is_per_item():
    it = Intent.model_validate({"id": "x", "kind": "bind_gateway", "engine": F.E1, "engine_label": "HR",
                                "gateway": {"name": "corp-out", "direction": "egress", "junk": 1}})
    assert "engine_label" not in it.model_dump()
    res = render([it, Intent(id="bad", kind="grant", source=HR, destination=DEST["agent"],
                             access=Access.model_construct(mode="tools", tools=[1, None]))], ENV)
    assert res.items[0].error is None and res.items[1].intent_id == "bad" and res.items[1].error
    assert res.bundle.gcloud.count("-X PATCH") == 1             # the bad item is left out of the bundle
