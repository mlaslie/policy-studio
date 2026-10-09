"""Intent -> Terraform / gcloud / REST (curl) / Python, with an IAM anatomy, plain English and warnings.

Pure functions: no GCP calls. Everything is generated from the Intent plus a RenderEnv (resolved context and,
optionally, what discovery knows: current engine gateway bindings, MCP tools).

Sources of truth (verified live in the demo project; see docs/BACKLOG.md "#17 research" there):
  grant/revoke   IAP IAM on Agent Registry entries, roles/iap.egressor, policy version 3
                 gcloud iap web add-/remove-iam-policy-binding --resource-type=agent-registry --region=R
                        --agent=ID | --mcp-server=ID | --endpoint=ID [--condition=...]
                 Terraform google_iap_agent_registry_{agent,mcp_server,endpoint}_iam_member (+ condition {})
                 Python google-cloud-iap IdentityAwareProxyAdminServiceClient get/set_iam_policy
  bind/unbind    PATCH https://R-aiplatform.googleapis.com/v1/<engine>?updateMask=spec.deploymentSpec.agentGatewayConfig
                 (replaces the whole field, so the other direction is re-sent). No gcloud command exists.
  model armor    networksecurity authzPolicies: CONTENT_AUTHZ, action CUSTOM -> Model Armor authz extension
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from . import hcl
from .conditions import EGRESSOR, condition_for
from .english import PROJECT_AGENTS_RE, engine_principal_parts, intent_english, member_label
from .model import Anatomy, Bundle, Condition, Context, Intent, Outputs, RenderItem, RenderResult

PROVIDER_VERSION = ">= 8.1.0"
TF_VERSION = ">= 1.5"
ENGINE_MASK = "spec.deploymentSpec.agentGatewayConfig"
GW_KEYS = {"egress": "agentToAnywhereConfig", "ingress": "clientToAgentConfig"}
COLLECTION = {"agent": "agents", "mcp_server": "mcpServers", "endpoint": "endpoints"}
GCLOUD_FLAG = {"agent": "--agent", "mcp_server": "--mcp-server", "endpoint": "--endpoint"}
TF_RESOURCE = {"agent": ("google_iap_agent_registry_agent_iam_member", "agent_id"),
               "mcp_server": ("google_iap_agent_registry_mcp_server_iam_member", "mcp_server_id"),
               "endpoint": ("google_iap_agent_registry_endpoint_iam_member", "endpoint_id")}
KIND_LABEL = {"agent": "A2A agent", "mcp_server": "MCP server", "endpoint": "API endpoint",
              "registry": "Agent Registry (every entry)"}
ORDER = {"bind_gateway": 0, "unbind_gateway": 0, "model_armor_on": 1, "model_armor_off": 1, "grant": 2, "revoke": 2}


# ====================================================================== environment
@dataclass
class RenderEnv:
    ctx: Context
    engines: dict[str, dict[str, str]] = field(default_factory=dict)   # engine name -> {egress?, ingress?}
    engine_info: dict[str, dict[str, Any]] = field(default_factory=dict)  # engine name -> {display_name, bindable}
    mcp_tools: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # mcp id -> [{name, read_only}]
    staged_egress: set[str] = field(default_factory=set)   # engines a staged intent binds to an egress gateway

    @property
    def project(self) -> str:
        return self.ctx.project or "PROJECT_ID"

    @property
    def number(self) -> str:
        return self.ctx.project_number or "PROJECT_NUMBER"

    @property
    def region(self) -> str:
        return self.ctx.region or "REGION"

    @property
    def gw_project(self) -> str:
        return self.ctx.gateway_project or self.project

    @property
    def gw_number(self) -> str:
        if self.ctx.gateway_project_number:
            return self.ctx.gateway_project_number
        return self.number if self.gw_project == self.project else "GATEWAY_PROJECT_NUMBER"


def short(name: str) -> str:
    return (name or "").rstrip("/").split("/")[-1]


def project_of(resource: str) -> Optional[str]:
    m = re.match(r"^projects/([^/]+)/", resource or "")
    return m.group(1) if m else None


# ====================================================================== shell helpers
_SAFE = re.compile(r"^[A-Za-z0-9_@%+=:,./-]+$")


def shq(s: str) -> str:
    """Shell-quote for copy-paste readability: bare if safe, '...' if possible, "..." if that's safe, else '"'"'."""
    if s and _SAFE.match(s):
        return s
    if "'" not in s:
        return f"'{s}'"
    if not re.search(r'["$`\\!]', s):
        return f'"{s}"'
    return "'" + s.replace("'", "'\"'\"'") + "'"


UGLY = "'\"'\"'"


def sh_assign(var: str, value: str) -> str:
    """VAR=value, with a quoted heredoc when plain quoting would be unreadable."""
    quoted = shq(value)
    if UGLY not in quoted and "\n" not in value:
        return f"{var}={quoted}"
    return f"{var}=$(cat <<'EOF'\n{value}\nEOF\n)"


def cont(lines: list[str], indent: str = "  ") -> str:
    """Join command parts with ` \\` continuations."""
    return (" \\\n" + indent).join(lines)


def curl(method: str, url: str, body: Optional[str] = None, data_flag: Optional[str] = None) -> str:
    parts = [f"curl -sS --fail-with-body -X {method} {shq(url)}",
             '-H "Authorization: Bearer $TOKEN"']
    if body is not None or data_flag:
        parts.append('-H "Content-Type: application/json"')
    if body is not None:
        parts.append(f"-d {shq(body)}")
    if data_flag:
        parts.append(data_flag)
    return cont(parts)


TOKEN_LINE = 'TOKEN="$(gcloud auth print-access-token)"'


# ====================================================================== specs
@dataclass
class IamSpec:
    op: str                        # add | remove
    kind: str                      # agent | mcp_server | endpoint
    rid: str
    member: str
    role: str
    condition: Optional[Condition]
    resource: str                  # IAP resource path (project number)
    dest_label: str
    src_label: str


@dataclass
class BindSpec:
    op: str                        # bind | unbind
    engine: str
    engine_label: str
    direction: str
    gateway: str
    new: dict[str, str]
    prev: dict[str, str]
    known: bool


@dataclass
class MaSpec:
    op: str                        # on | off
    gateway: str
    project: str
    policy: str
    extension: str


def gateway_full(env: RenderEnv, name: str, direction: str) -> str:
    if name.startswith("projects/"):
        return name
    proj = env.gw_project if direction == "egress" else env.project
    return f"projects/{proj}/locations/{env.region}/agentGateways/{name or 'GATEWAY'}"


def engine_full(env: RenderEnv, engine: str) -> str:
    if engine.startswith("projects/"):
        return engine
    return f"projects/{env.number}/locations/{env.region}/reasoningEngines/{engine or 'ENGINE_ID'}"


def iam_spec(intent: Intent, env: RenderEnv, warnings: list[str]) -> IamSpec:
    d = intent.destination
    s = intent.source
    if d is None:
        warnings.append("No destination: pick an A2A agent, MCP server or API endpoint.")
    kind = d.kind if d else "mcp_server"
    rid = "" if kind == "registry" else ((d.id or short(d.name)) if d else "REGISTRY_ID")
    member = s.principal if s and s.principal else "PRINCIPAL"
    if not s or not s.principal:
        warnings.append("No source principal: pick an agent, all agents in the project, or enter a principal.")
    acc = intent.access
    cond = condition_for(acc)
    if acc and acc.mode != "all" and kind not in ("mcp_server", "registry"):
        warnings.append(f"Tool conditions only apply to MCP servers. On an {KIND_LABEL[kind]} the MCP attributes are "
                        "empty, so the toolName == '' branch matches every request: this is effectively full access.")
    if acc and acc.mode == "tools" and not [t for t in acc.tools or [] if t]:
        warnings.append("No tools selected: only MCP setup calls (initialize, tools/list) will be allowed.")
    if acc and acc.mode == "custom" and not (acc.expression or "").strip():
        warnings.append("The custom condition is empty.")
    if acc and acc.mode == "tools" and d and env.mcp_tools.get(rid):
        known = {t["name"] for t in env.mcp_tools[rid]}
        unknown = [t for t in acc.tools or [] if t and t not in known]
        if unknown:
            warnings.append(f"Not tools of this MCP server (per Agent Registry): {', '.join(unknown)}.")
    if member.startswith("serviceAccount:") and s and s.type == "engine":
        warnings.append("This agent runs as a service account, not an Agent Identity. Agent Gateway identifies "
                        "Agent Runtime agents by Agent Identity; redeploy it with identity_type AGENT_IDENTITY.")
    if s and s.type == "engine" and s.engine and env.engines.get(s.engine) is not None \
            and not env.engines[s.engine].get("egress") and s.engine not in env.staged_egress:
        warnings.append(f"{s.label or short(s.engine)} isn't bound to an egress gateway, so this grant isn't enforced "
                        "until it is (stage a gateway binding).")
    resource = f"projects/{env.gw_number}/locations/{env.region}/iap_web/agentRegistry"
    if kind != "registry":
        resource += f"/{COLLECTION[kind]}/{rid}"
    return IamSpec(op="add" if intent.kind == "grant" else "remove", kind=kind, rid=rid, member=member,
                   role=EGRESSOR, condition=cond, resource=resource,
                   dest_label=(d.label or d.name or d.id or KIND_LABEL[kind]) if d else "the destination",
                   src_label=(s.label if s and s.label else member_label(member)))


def bind_spec(intent: Intent, env: RenderEnv, warnings: list[str]) -> BindSpec:
    gw = intent.gateway
    direction = gw.direction if gw else "egress"
    engine = engine_full(env, intent.engine or "")
    if not intent.engine:
        warnings.append("No engine: pick the Agent Runtime agent to bind.")
    gateway = gateway_full(env, gw.name if gw else "", direction)
    known = engine in env.engines
    prev = dict(env.engines.get(engine) or {})
    if not known:
        warnings.append("The engine's current gateway bindings are unknown (not in this region's inventory). The "
                        "PATCH replaces the whole agentGatewayConfig: add the other direction if it is bound.")
    new = dict(prev)
    if intent.kind == "bind_gateway":
        new[direction] = gateway
        if prev.get(direction) and prev[direction] != gateway:
            warnings.append(f"The engine is bound to {short(prev[direction])} for {direction}; this replaces it.")
    else:
        if prev.get(direction) and short(prev[direction]) != short(gateway):
            warnings.append(f"The engine's {direction} gateway is {short(prev[direction])}, not {short(gateway)}; "
                            "unbinding removes it anyway.")
        new.pop(direction, None)
    info = env.engine_info.get(engine) or {}
    if intent.kind == "bind_gateway" and info and not info.get("bindable", True):
        warnings.append("This engine was created before 2026-04-29 and can't be bound to a gateway; redeploy it first.")
    return BindSpec(op="bind" if intent.kind == "bind_gateway" else "unbind", engine=engine,
                    engine_label=info.get("display_name") or short(engine), direction=direction, gateway=gateway,
                    new=new, prev=prev, known=known)


def ma_spec(intent: Intent, env: RenderEnv, warnings: list[str]) -> MaSpec:
    gw = intent.gateway
    direction = gw.direction if gw else "egress"
    gateway = gateway_full(env, gw.name if gw else "", direction)
    project = project_of(gateway) or env.gw_project
    if project.isdigit():
        project = env.project if project == env.ctx.project_number else (
            env.gw_project if project == env.ctx.gateway_project_number else project)
    policy = (gw.policy if gw and gw.policy else f"{short(gateway)}-ma-policy")
    policy = short(policy)
    if intent.kind == "model_armor_off" and not (gw and gw.policy):
        warnings.append(f"Policy name assumed to be {policy}; check the Model Armor step for the actual name.")
    ext = gw.extension if gw and gw.extension else ("AUTHZ_EXTENSION" if intent.kind == "model_armor_off" else "")
    if intent.kind == "model_armor_on" and not ext:
        ext = f"projects/{project}/locations/{env.region}/authzExtensions/MODEL_ARMOR_EXTENSION"
        warnings.append("No Model Armor authz extension found in this region: create one (service "
                        f"modelarmor.{env.region}.rep.googleapis.com, metadata.model_armor_settings naming a template) "
                        "and replace MODEL_ARMOR_EXTENSION.")
    return MaSpec(op="on" if intent.kind == "model_armor_on" else "off", gateway=gateway, project=project,
                  policy=policy, extension=ext)


# ====================================================================== anatomy
def _member_note(member: str) -> str:
    if PROJECT_AGENTS_RE.match(member):
        return ("member: principalSet of every Agent Runtime agent (Agent Identity) in the project: "
                "any of them, current or future")
    if engine_principal_parts(member):
        return ("member: the agent's Agent Identity (principal://<trust domain>/resources/aiplatform/projects/"
                "<number>/locations/<region>/reasoningEngines/<id>), the identity the gateway sees")
    if member in ("allUsers", "allAuthenticatedUsers"):
        return "member: a public principal: anyone (or any Google account). Avoid this on egress."
    return "member: the principal that gets the role"


def iam_anatomy(sp: IamSpec) -> Anatomy:
    notes = [("resource: the whole Agent Registry: the grant covers every agent, MCP server and endpoint in it, "
              "including ones registered later" if sp.kind == "registry" else
              f"resource: the Agent Registry entry being protected ({KIND_LABEL[sp.kind]} {sp.dest_label})")
             + "; IAP paths use the project number",
             f"role: {sp.role} = may send traffic to it through the egress gateway",
             _member_note(sp.member)]
    if sp.condition:
        if "mcp.toolName', '') == ''" in sp.condition.expression or "''" in sp.condition.expression:
            notes.append("condition: the '' branch is there because MCP setup calls (initialize, tools/list) carry no "
                         "tool name; without it the agent couldn't even list tools")
        if "isReadOnly" in sp.condition.expression:
            notes.append("condition: isReadOnly comes from the tool's readOnlyHint in the registered tool spec, so new "
                         "read-only tools are included automatically")
    else:
        notes.append("condition: none, so the grant covers every request (all tools)")
    if sp.op == "remove":
        notes.append("revoke: IAM matches the binding by member, role and condition, so the revoke repeats the same "
                     "condition")
    return Anatomy(resource=sp.resource, role=sp.role, member=sp.member,
                   condition=sp.condition.expression if sp.condition else None, notes=notes)


# ====================================================================== grant / revoke
def _cond_flag(c: Optional[Condition]) -> list[str]:
    """gcloud --condition. Expressions contain commas (and '||'), so a custom delimiter is used."""
    if c is None:
        return ["--condition=None"]
    for d in ("~", "#", "@", ";", "%", "+"):
        if d not in c.title and d not in c.expression and "\n" not in c.expression:
            flag = shq(f"^{d}^title={c.title}{d}expression={c.expression}")
            return [] if UGLY in flag else ["--condition=" + flag]
    return []     # caller falls back to --condition-from-file


def gcloud_iam(sp: IamSpec, env: RenderEnv) -> str:
    verb = "add-iam-policy-binding" if sp.op == "add" else "remove-iam-policy-binding"
    flags = [f"gcloud iap web {verb}", f"--project={env.gw_project}", "--resource-type=agent-registry",
             f"--region={env.region}", *([f"{GCLOUD_FLAG[sp.kind]}={sp.rid}"] if sp.kind in GCLOUD_FLAG else []),
             f"--member={shq(sp.member)}",
             f"--role={sp.role}"]
    cf = _cond_flag(sp.condition)
    pre = ""
    if sp.condition and not cf:
        fname = f"condition-{sp.rid or 'registry'}.json"
        pre = (f"cat > {fname} <<'EOF'\n"
               + json.dumps({"title": sp.condition.title, "expression": sp.condition.expression}, indent=2)
               + "\nEOF\n")
        cf = [f"--condition-from-file={fname}"]
    return pre + cont(flags + cf)


JQ_ADD = """{policy: (.version = 3
  | .bindings = ((.bindings // []) as $b
      | if any($b[]; .role == $role and any(.members[]; . == $member)
                     and ((.condition.expression // "") == $expr))
        then $b
        else $b + [{role: $role, members: [$member]}
                   + (if $expr == "" then {} else {condition: {title: $title, expression: $expr}} end)]
        end))}"""

JQ_REMOVE = """{policy: (.version = 3
  | .bindings = [(.bindings // [])[]
      | if .role == $role and ((.condition.expression // "") == $expr)
        then .members -= [$member] else . end
      | select(.members | length > 0)])}"""


def rest_iam(sp: IamSpec) -> str:
    c = sp.condition
    lines = [f"RESOURCE={shq('https://iap.googleapis.com/v1/' + sp.resource)}",
             f"MEMBER={shq(sp.member)}",
             f"ROLE={sp.role}",
             sh_assign("TITLE", c.title if c else ""),
             sh_assign("EXPR", c.expression if c else ""),
             "",
             f"# Read-modify-write: get the policy (version 3 keeps conditions), "
             f"{'add' if sp.op == 'add' else 'remove'} the binding with jq, set it back (the etag guards against "
             "concurrent edits).",
             cont(['curl -sS --fail-with-body -X POST "$RESOURCE:getIamPolicy"',
                   '-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"',
                   "-d '{\"options\":{\"requestedPolicyVersion\":3}}'"]) + " \\",
             '| jq --arg role "$ROLE" --arg member "$MEMBER" --arg title "$TITLE" --arg expr "$EXPR" \'',
             (JQ_ADD if sp.op == "add" else JQ_REMOVE) + "' \\",
             cont(['| curl -sS --fail-with-body -X POST "$RESOURCE:setIamPolicy"',
                   '-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"', "-d @-"])]
    return "\n".join(lines)


PY_IAP_HELPERS = '''from google.cloud import iap_v1  # pip install google-cloud-iap
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2
from google.type import expr_pb2

EGRESSOR = "roles/iap.egressor"
iap = iap_v1.IdentityAwareProxyAdminServiceClient()


def _get_policy(resource):
    return iap.get_iam_policy(request=iam_policy_pb2.GetIamPolicyRequest(
        resource=resource, options=options_pb2.GetPolicyOptions(requested_policy_version=3)))


def _matches(binding, member, role, expression):
    return (binding.role == role and member in binding.members
            and (binding.condition.expression or None) == (expression or None))


def grant(resource, member, role=EGRESSOR, title=None, expression=None):
    """Add member to role on an IAP resource (read-modify-write, IAM policy version 3)."""
    policy = _get_policy(resource)
    if any(_matches(b, member, role, expression) for b in policy.bindings):
        print(f"already granted: {member} on {resource}")
        return
    binding = policy_pb2.Binding(role=role, members=[member])
    if expression:
        binding.condition.CopyFrom(expr_pb2.Expr(title=title or "", expression=expression))
    policy.bindings.append(binding)
    policy.version = 3
    iap.set_iam_policy(request=iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy))
    print(f"granted {role} to {member} on {resource}")


def revoke(resource, member, role=EGRESSOR, expression=None):
    """Remove member from the binding of role with exactly this condition (None = the unconditional one)."""
    policy = _get_policy(resource)
    kept, changed = [], False
    for b in policy.bindings:
        members = list(b.members)
        if _matches(b, member, role, expression):
            members.remove(member)
            changed = True
        if members:
            nb = policy_pb2.Binding(role=b.role, members=members)
            if b.HasField("condition"):
                nb.condition.CopyFrom(b.condition)
            kept.append(nb)
    if not changed:
        print(f"not present: {member} on {resource}")
        return
    policy.ClearField("bindings")
    policy.bindings.extend(kept)
    policy.version = 3
    iap.set_iam_policy(request=iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy))
    print(f"revoked {role} from {member} on {resource}")
'''


def py_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def python_iam_call(sp: IamSpec) -> str:
    c = sp.condition
    args = [py_str(sp.resource), py_str(sp.member)]
    if sp.op == "add":
        call = "grant(\n    " + ",\n    ".join(args + ([f"title={py_str(c.title)}", f"expression={py_str(c.expression)}"]
                                                   if c else [])) + ",\n)"
    else:
        call = "revoke(\n    " + ",\n    ".join(args + ([f"expression={py_str(c.expression)}"] if c else [])) + ",\n)"
    return call


def tf_iam(sp: IamSpec, env: RenderEnv, name: str, bundle: bool) -> str:
    rtype, key = TF_RESOURCE.get(sp.kind, ("google_iap_agent_registry_iam_member", ""))
    b = hcl.Block(f'resource "{rtype}" "{name}"')
    b.attr("project", "local.gateway_project" if bundle else hcl.q(env.gw_project))
    b.attr("location", "var.region" if bundle else hcl.q(env.region))
    if key:
        b.s(key, sp.rid)
    b.s("role", sp.role)
    b.s("member", sp.member)
    if sp.condition:
        b.blank()
        cb = b.block("condition")
        cb.s("title", sp.condition.title)
        cb.s("expression", sp.condition.expression)
    text = b.render()
    if sp.op == "add":
        return text
    return (hcl.comment_lines(
        "Revoke: Terraform removes a grant when the resource that created it is deleted. Delete this block from "
        "your configuration and run `terraform apply`. If the grant was made outside Terraform, use the gcloud, "
        "REST or Python tab instead.") + "#\n" + hcl.commented(text))


# ====================================================================== bind / unbind
def engine_body(cfg: dict[str, str]) -> dict[str, Any]:
    return {"spec": {"deploymentSpec": {"agentGatewayConfig": {
        GW_KEYS[d]: {"agentGateway": cfg[d]} for d in ("egress", "ingress") if cfg.get(d)}}}}


def engine_url(env: RenderEnv, engine: str) -> str:
    return f"https://{env.region}-aiplatform.googleapis.com/v1/{engine}?updateMask={ENGINE_MASK}"


def bind_anatomy(sp: BindSpec) -> Anatomy:
    notes = [f"resource: the Agent Runtime engine {sp.engine_label}",
             f"field: spec.deploymentSpec.agentGatewayConfig.{GW_KEYS[sp.direction]}.agentGateway "
             f"({'outbound: agent to anywhere' if sp.direction == 'egress' else 'inbound: client to agent'})",
             "the PATCH replaces the whole agentGatewayConfig, so the other direction is re-sent unchanged",
             "a long-running operation: the engine redeploys (several minutes)"]
    if sp.op == "unbind":
        notes.append("unbinding: the PATCH omits this direction ({} when none is left)")
    return Anatomy(resource=sp.engine, role=f"agentGatewayConfig.{GW_KEYS[sp.direction]}",
                   member=sp.gateway if sp.op == "bind" else "(none)", notes=notes)


def rest_bind(sp: BindSpec, env: RenderEnv) -> str:
    body = json.dumps(engine_body(sp.new), separators=(",", ":"))
    return ("# Long-running operation: the engine redeploys; poll the returned operation name.\n"
            + curl("PATCH", engine_url(env, sp.engine), body=body))


def gcloud_bind(sp: BindSpec, env: RenderEnv) -> str:
    return ("# No gcloud command manages Agent Runtime engines (checked gcloud ai / beta ai / alpha ai). Use the REST\n"
            "# PATCH with a gcloud access token. (agents-cli deploy --agent-gateway-egress binds as part of a full\n"
            "# redeploy of the agent source.)\n" + TOKEN_LINE + "\n" + rest_bind(sp, env))


PY_ENGINE_HELPERS = '''import google.auth
from google.auth.transport.requests import AuthorizedSession

# The GAPIC aiplatform client has no agent_gateway_config field, and vertexai's agent_engines.update() needs the
# agent code; a plain authorized PATCH is the reliable way to change only the gateway binding.
session = AuthorizedSession(google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])[0])


def set_gateway_config(region, engine, config):
    """PATCH agentGatewayConfig (replaces the whole field: include every direction to keep).
    Returns the long-running operation; the engine redeploys over several minutes."""
    r = session.patch(
        f"https://{region}-aiplatform.googleapis.com/v1/{engine}",
        params={"updateMask": "spec.deploymentSpec.agentGatewayConfig"},
        json={"spec": {"deploymentSpec": {"agentGatewayConfig": config}}},
    )
    r.raise_for_status()
    return r.json()
'''


def python_bind_call(sp: BindSpec, env: RenderEnv) -> str:
    cfg = engine_body(sp.new)["spec"]["deploymentSpec"]["agentGatewayConfig"]
    cfg_txt = json.dumps(cfg, indent=4).replace("\n", "\n    ") if cfg else "{}"
    return (f"op = set_gateway_config(\n    {py_str(env.region)},\n    {py_str(sp.engine)},\n    {cfg_txt},\n)\n"
            'print("started", op.get("name"))')


def tf_bind(sp: BindSpec, env: RenderEnv, name: str, bundle: bool) -> str:
    url = (f"https://${{var.region}}-aiplatform.googleapis.com/v1/{sp.engine}?updateMask={ENGINE_MASK}" if bundle
           else engine_url(env, sp.engine))
    url_expr = '"' + url.replace('"', '\\"') + '"' if bundle else hcl.q(url)
    b = hcl.Block(f'resource "terraform_data" "{name}"')
    inp = ("{\n" + f"    url = {url_expr}\n"
           + "    body = jsonencode(" + hcl.obj(engine_body(sp.new), 2) + ")\n"
           + "    undo = jsonencode(" + hcl.obj(engine_body(sp.prev), 2) + ")\n  }")
    b.attr("input", inp)
    b.blank()
    curl_cmd = ('curl -sS --fail-with-body -X PATCH "$URL" \\\n'
                '  -H "Authorization: Bearer $(gcloud auth print-access-token)" \\\n'
                '  -H "Content-Type: application/json" \\\n'
                '  -d "$BODY"')
    p1 = b.block('provisioner "local-exec"')
    p1.comment(("Bind" if sp.op == "bind" else "Unbind") + ": PATCH agentGatewayConfig to the desired directions.")
    p1.attr("command", hcl.heredoc(curl_cmd, 2))
    p1.attr("environment", "{\n      URL  = self.input.url\n      BODY = self.input.body\n    }")
    b.blank()
    p2 = b.block('provisioner "local-exec"')
    p2.comment("On destroy: restore the previous agentGatewayConfig.")
    p2.attr("when", "destroy")
    p2.attr("command", hcl.heredoc(curl_cmd, 2))
    p2.attr("environment", "{\n      URL  = self.input.url\n      BODY = self.input.undo\n    }")
    text = b.render()
    head = hcl.comment_lines(
        "No Terraform resource binds an existing Agent Runtime engine to an Agent Gateway, so this runs the same "
        "PATCH as the REST tab (a long-running operation that redeploys the engine). Needs curl and an "
        "authenticated gcloud where Terraform runs.\n"
        "Teams that manage the engine itself in Terraform set the binding on it instead (google >= 8.1.0; requires "
        "importing the existing engine with a matching spec; not verified):")
    eng_blk = hcl.Block('resource "google_vertex_ai_reasoning_engine" "agent"')
    eng_blk.comment("... display_name, spec.package_spec / source_code_spec, identity_type ...")
    agc = eng_blk.block("spec").block("deployment_spec").block("agent_gateway_config")
    for d, blk in (("egress", "agent_to_anywhere_config"), ("ingress", "client_to_agent_config")):
        if sp.new.get(d):
            agc.block(blk).s("agent_gateway", sp.new[d])
    return head + "#\n" + hcl.commented(eng_blk.render()) + text


# ====================================================================== Model Armor
def ma_body(sp: MaSpec) -> dict[str, Any]:
    return {"target": {"resources": [sp.gateway]}, "policyProfile": "CONTENT_AUTHZ", "action": "CUSTOM",
            "customProvider": {"authzExtension": {"resources": [sp.extension]}}}


def ma_url(sp: MaSpec, env: RenderEnv, with_id: bool) -> str:
    base = f"https://networksecurity.googleapis.com/v1/projects/{sp.project}/locations/{env.region}/authzPolicies"
    return f"{base}?authzPolicyId={sp.policy}" if with_id else f"{base}/{sp.policy}"


def ma_anatomy(sp: MaSpec, env: RenderEnv) -> Anatomy:
    notes = ["resource: a Network Security authz policy attached to the gateway",
             "profile CONTENT_AUTHZ = inspect request/response content; action CUSTOM = delegate to an authz extension",
             f"extension: the Model Armor authz extension (service modelarmor.{env.region}.rep.googleapis.com) whose "
             "metadata names the template",
             "verified: egress screening covers MCP traffic, not A2A",
             "a long-running operation (about 4 minutes)"]
    return Anatomy(resource=f"projects/{sp.project}/locations/{env.region}/authzPolicies/{sp.policy}",
                   role="CONTENT_AUTHZ → CUSTOM (Model Armor)", member=sp.gateway, notes=notes)


def ma_yaml(sp: MaSpec) -> str:
    return (f"name: {sp.policy}\n"
            f"target:\n  resources:\n    - {sp.gateway}\n"
            "policyProfile: CONTENT_AUTHZ\n"
            "action: CUSTOM\n"
            f"customProvider:\n  authzExtension:\n    resources:\n      - {sp.extension}\n")


def gcloud_ma(sp: MaSpec, env: RenderEnv) -> str:
    if sp.op == "on":
        f = f"{sp.policy}.yaml"
        return (f"cat > {f} <<'EOF'\n{ma_yaml(sp)}EOF\n"
                + cont([f"gcloud network-security authz-policies import {sp.policy}", f"--source={f}",
                        f"--location={env.region}", f"--project={sp.project}"]))
    return cont([f"gcloud network-security authz-policies delete {sp.policy}", f"--location={env.region}",
                 f"--project={sp.project}", "--quiet"])


def rest_ma(sp: MaSpec, env: RenderEnv) -> str:
    if sp.op == "on":
        return ("# Long-running operation (about 4 minutes).\n"
                + curl("POST", ma_url(sp, env, True), body=json.dumps(ma_body(sp), separators=(",", ":"))))
    return "# Long-running operation (about 4 minutes).\n" + curl("DELETE", ma_url(sp, env, False))


PY_NS_HELPERS = '''from google.cloud import network_security_v1  # pip install google-cloud-network-security (pre-1.0)

ns = network_security_v1.NetworkSecurityClient()
AuthzPolicy = network_security_v1.AuthzPolicy


def model_armor_on(project, region, name, gateway, extension):
    """Attach a CONTENT_AUTHZ authz policy that sends the gateway's traffic to a Model Armor extension."""
    policy = AuthzPolicy(
        target=AuthzPolicy.Target(resources=[gateway]),
        policy_profile=AuthzPolicy.PolicyProfile.CONTENT_AUTHZ,
        action=AuthzPolicy.AuthzAction.CUSTOM,
        custom_provider=AuthzPolicy.CustomProvider(
            authz_extension=AuthzPolicy.CustomProvider.AuthzExtension(resources=[extension])),
    )
    op = ns.create_authz_policy(parent=f"projects/{project}/locations/{region}", authz_policy=policy,
                                authz_policy_id=name)
    return op.result(timeout=900)


def model_armor_off(project, region, name):
    op = ns.delete_authz_policy(name=f"projects/{project}/locations/{region}/authzPolicies/{name}")
    return op.result(timeout=900)
'''


def python_ma_call(sp: MaSpec, env: RenderEnv) -> str:
    if sp.op == "on":
        args = [sp.project, env.region, sp.policy, sp.gateway, sp.extension]
        return "model_armor_on(\n    " + ",\n    ".join(py_str(a) for a in args) + ",\n)"
    return "model_armor_off(" + ", ".join(py_str(a) for a in (sp.project, env.region, sp.policy)) + ")"


def tf_ma(sp: MaSpec, env: RenderEnv, name: str, bundle: bool) -> str:
    b = hcl.Block(f'resource "google_network_security_authz_policy" "{name}"')
    if bundle:
        b.attr("project", "local.gateway_project" if sp.project == env.gw_project else
               ("var.project_id" if sp.project == env.project else hcl.q(sp.project)))
        b.attr("location", "var.region")
    else:
        b.s("project", sp.project)
        b.s("location", env.region)
    b.s("name", sp.policy)
    b.s("policy_profile", "CONTENT_AUTHZ")
    b.s("action", "CUSTOM")
    b.blank()
    b.block("target").attr("resources", hcl.obj([sp.gateway], 2))
    b.blank()
    b.block("custom_provider").block("authz_extension").attr("resources", hcl.obj([sp.extension], 3))
    text = b.render()
    if sp.op == "on":
        return text
    return (hcl.comment_lines(
        "Model Armor off: Terraform deletes the authz policy when its resource is removed. Delete this block from "
        "your configuration and run `terraform apply`. If the policy was created outside Terraform, use the "
        "gcloud, REST or Python tab instead.") + "#\n" + hcl.commented(text))


# ====================================================================== per intent
@dataclass
class _Rendered:
    item: RenderItem
    kind: str
    spec: Any
    py_helpers: str
    py_call: str
    rest_body: str
    gcloud_body: str
    tf_name: str


def _tf_name(intent: Intent, spec: Any) -> str:
    if isinstance(spec, IamSpec):
        base = f"{spec.src_label}_{spec.dest_label}" + ("" if not spec.condition else "_conditional")
    elif isinstance(spec, BindSpec):
        base = f"{spec.op}_{spec.engine_label}_{spec.direction}"
    else:
        base = f"model_armor_{short(spec.gateway)}"
    return hcl.ident(base)


def _python_script(helpers: str, calls: list[str]) -> str:
    return helpers.rstrip() + "\n\n\n" + "\n\n".join(calls) + "\n"


def _assemble(intent_id: str, kind: str, english: str, anatomy: Anatomy, sp: Any, g: str, rb: str, helpers: str,
              call: str, tf: str, name: str, warnings: list[str]) -> _Rendered:
    header = f"# {english}\n"
    outputs = Outputs(terraform=header + tf, gcloud=header + g + "\n", rest=header + TOKEN_LINE + "\n" + rb + "\n",
                      python=header + _python_script(helpers, [call]))
    item = RenderItem(intent_id=intent_id, english=english, anatomy=anatomy, outputs=outputs, warnings=warnings)
    return _Rendered(item=item, kind=kind, spec=sp, py_helpers=helpers, py_call=call, rest_body=rb, gcloud_body=g,
                     tf_name=name)


def bind_english(sp: BindSpec) -> str:
    return (f"{'Route' if sp.op == 'bind' else 'Stop routing'} {sp.engine_label}'s "
            f"{'outbound (egress)' if sp.direction == 'egress' else 'inbound (ingress)'} traffic "
            f"through Agent Gateway {short(sp.gateway)}.")


def _from_bind(intent_id: str, kind: str, sp: BindSpec, env: RenderEnv, english: str, name: str,
               warnings: list[str]) -> _Rendered:
    return _assemble(intent_id, kind, english, bind_anatomy(sp), sp, gcloud_bind(sp, env), rest_bind(sp, env),
                     PY_ENGINE_HELPERS, python_bind_call(sp, env), tf_bind(sp, env, name, bundle=False), name,
                     warnings)


def render_one(intent: Intent, env: RenderEnv, tf_name: Optional[str] = None) -> _Rendered:
    warnings: list[str] = []
    k = intent.kind
    if k in ("grant", "revoke"):
        sp: Any = iam_spec(intent, env, warnings)
        name = tf_name or _tf_name(intent, sp)
        return _assemble(intent.id, k, intent_english(intent), iam_anatomy(sp), sp, gcloud_iam(sp, env),
                         rest_iam(sp), PY_IAP_HELPERS, python_iam_call(sp), tf_iam(sp, env, name, bundle=False),
                         name, warnings)
    if k in ("bind_gateway", "unbind_gateway"):
        sp = bind_spec(intent, env, warnings)
        name = tf_name or _tf_name(intent, sp)
        return _from_bind(intent.id, k, sp, env, bind_english(sp), name, warnings)
    sp = ma_spec(intent, env, warnings)
    name = tf_name or _tf_name(intent, sp)
    return _assemble(intent.id, k, intent_english(intent), ma_anatomy(sp, env), sp, gcloud_ma(sp, env),
                     rest_ma(sp, env), PY_NS_HELPERS, python_ma_call(sp, env), tf_ma(sp, env, name, bundle=False),
                     name, warnings)


def merge_binds(group: list[_Rendered], env: RenderEnv) -> _Rendered:
    """Several staged binding changes to one engine become one PATCH (a second PATCH is rejected while the first
    one is still redeploying the engine)."""
    if len(group) == 1:
        return group[0]
    first, last = group[0].spec, group[-1].spec
    sp = BindSpec(op="bind" if any(r.spec.op == "bind" for r in group) else "unbind", engine=first.engine,
                  engine_label=first.engine_label, direction=last.direction, gateway=last.gateway, new=dict(last.new),
                  prev=dict(first.prev), known=first.known)
    english = " ".join(r.item.english for r in group)
    return _from_bind("+".join(r.item.intent_id for r in group), group[0].kind, sp, env, english,
                      hcl.ident(f"gateways_{first.engine_label}"), [])


# ====================================================================== bundle
def _variables(env: RenderEnv) -> str:
    out = []
    for name, desc, default in (
            ("project_id", "Project of the Agent Runtime agents and gateways", env.project),
            ("project_number", "Number of project_id (IAP resource paths use it)", env.number),
            ("region", "Region of the gateways, Agent Registry and agents", env.region),
            ("gateway_project_id", "Project of the egress gateway and Agent Registry (empty = project_id)",
             env.ctx.gateway_project or ""),
            ("ge_app", "Gemini Enterprise app id (informational)", env.ctx.ge_app or ""),
            ("ge_location", "Gemini Enterprise location (informational)", env.ctx.ge_location or "us")):
        b = hcl.Block(f'variable "{name}"')
        b.s("description", desc)
        b.attr("type", "string")
        b.s("default", default)
        out.append(b.render())
    return "\n".join(out)


def _main_tf(env: RenderEnv, rendered: list[_Rendered]) -> str:
    out = [hcl.comment_lines(
        f"Generated by Policy Studio for project {env.project} ({env.number}), region {env.region}"
        + (f", gateway project {env.gw_project}" if env.gw_project != env.project else "") + ".\n"
        "Nothing has been applied: run `terraform init` and `terraform plan`, and review the plan before applying."),
        "\n"]
    tf = hcl.Block("terraform")
    tf.s("required_version", TF_VERSION)
    tf.blank()
    tf.block("required_providers").attr("google", hcl.obj({"source": "hashicorp/google",
                                                           "version": PROVIDER_VERSION}, 2))
    out += [tf.render(), "\n"]
    prov = hcl.Block('provider "google"')
    prov.attr("project", "var.project_id").attr("region", "var.region")
    out += [prov.render(), "\n"]
    lo = hcl.Block("locals")
    lo.attr("gateway_project", "coalesce(var.gateway_project_id, var.project_id)")
    out += [lo.render()]
    for r in rendered:
        out.append("\n")
        out.append(f"# {r.item.english}\n")
        if isinstance(r.spec, IamSpec):
            out.append(tf_iam(r.spec, env, r.tf_name, bundle=True))
        elif isinstance(r.spec, BindSpec):
            out.append(tf_bind(r.spec, env, r.tf_name, bundle=True))
        else:
            out.append(tf_ma(r.spec, env, r.tf_name, bundle=True))
    return re.sub(r"\n{3,}", "\n\n", "".join(out)).rstrip("\n") + "\n"


def _shell_header(env: RenderEnv, what: str) -> str:
    return ("#!/usr/bin/env bash\n"
            f"# {what} generated by Policy Studio for project {env.project} ({env.number}), region {env.region}"
            + (f", gateway project {env.gw_project}" if env.gw_project != env.project else "") + ".\n"
            "# Review before running. Order: gateway bindings, Model Armor, then grants.\n"
            "set -euo pipefail\n")


def _section(n: int, total: int, english: str) -> str:
    return f"\n# ---- [{n}/{total}] {english}\n"


def bundle(env: RenderEnv, rendered: list[_Rendered]) -> Bundle:
    groups: dict[str, list[_Rendered]] = {}
    units: list[Any] = []
    for r in rendered:
        if isinstance(r.spec, BindSpec):
            if r.spec.engine not in groups:
                groups[r.spec.engine] = []
                units.append(r.spec.engine)
            groups[r.spec.engine].append(r)
        else:
            units.append(r)
    merged = [merge_binds(groups[u], env) if isinstance(u, str) else u for u in units]
    ordered = sorted(merged, key=lambda r: ORDER.get(r.kind, 9))
    n = len(ordered)
    gcloud_parts = [_shell_header(env, "apply.sh")]
    rest_parts = [_shell_header(env, "REST calls"), TOKEN_LINE + "\n"]
    for i, r in enumerate(ordered, 1):
        gcloud_parts.append(_section(i, n, r.item.english) + r.gcloud_body + "\n")
        rest_parts.append(_section(i, n, r.item.english) + r.rest_body + "\n")
    helpers: list[str] = []
    for r in ordered:
        if r.py_helpers not in helpers:
            helpers.append(r.py_helpers)
    py = ('"""Generated by Policy Studio for project ' + env.project + ", region " + env.region
          + '. Review before running."""\n' + "\n\n".join(h.rstrip() + "\n" for h in helpers)
          + "\n\n" + "\n\n".join(f"# [{i}/{n}] {r.item.english}\n{r.py_call}" for i, r in enumerate(ordered, 1))
          + "\n")
    return Bundle(terraform={"main.tf": _main_tf(env, ordered), "variables.tf": _variables(env)},
                  gcloud="".join(gcloud_parts), rest="".join(rest_parts), python=py)


def render(intents: list[Intent], env: RenderEnv) -> RenderResult:
    """Render each intent and the bundle. Binding changes to the same engine are chained in order (each one starts
    from the config the previous one leaves), and the bundle sends them as one PATCH."""
    used: dict[str, int] = {}
    rendered: list[_Rendered] = []
    state = {k: dict(v) for k, v in env.engines.items()}
    staged = {engine_full(env, i.engine or "") for i in intents if i.kind == "bind_gateway"
              and (not i.gateway or i.gateway.direction == "egress")}
    env = replace(env, staged_egress=set(env.staged_egress) | staged)
    touched: dict[str, list[str]] = {}
    items: list[RenderItem] = []
    for it in intents:
        e = replace(env, engines={k: dict(v) for k, v in state.items()})
        try:
            r = render_one(it, e)
            base = r.tf_name
            used[base] = used.get(base, 0) + 1
            if used[base] > 1:
                r = render_one(it, e, tf_name=f"{base}_{used[base]}")
        except Exception as ex:  # noqa: BLE001  one bad intent never fails the request
            try:
                english = intent_english(it)
            except Exception:  # noqa: BLE001
                english = it.kind
            items.append(RenderItem(intent_id=it.id, english=english, error=f"{type(ex).__name__}: {ex}"[:400]))
            continue
        if isinstance(r.spec, BindSpec):
            earlier = touched.setdefault(r.spec.engine, [])
            if earlier:
                r.item.anatomy.notes.append(
                    f"Builds on {len(earlier)} earlier staged change(s) to this engine ({', '.join(earlier)}); the "
                    "bundle combines them into one PATCH, because a second PATCH fails while the engine redeploys.")
            earlier.append(it.id)
            state[r.spec.engine] = dict(r.spec.new)
        rendered.append(r)
        items.append(r.item)
    return RenderResult(items=items, bundle=bundle(env, rendered))
