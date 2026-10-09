"""Intent -> Terraform / gcloud / REST (curl) / Python, with an IAM anatomy, plain English and warnings.

Pure functions: no GCP calls. Everything is generated from the Intent plus a RenderEnv (resolved context and,
optionally, what discovery knows: current engine gateway bindings, MCP tools).

Sources of truth (REST shapes, gcloud flags and Terraform resources verified live against Agent Gateway, Oct 2026):
  grant/revoke   IAP IAM on Agent Registry entries, roles/iap.egressor, policy version 3
                 gcloud iap web add-/remove-iam-policy-binding --resource-type=agent-registry --region=R
                        --agent=ID | --mcp-server=ID | --endpoint=ID [--condition=...]
                 Terraform google_iap_agent_registry_{agent,mcp_server,endpoint}_iam_member (+ condition {})
                 Python google-cloud-iap IdentityAwareProxyAdminServiceClient get/set_iam_policy
  bind/unbind    PATCH https://R-aiplatform.googleapis.com/v1/<engine>?updateMask=spec.deploymentSpec.agentGatewayConfig
                 (replaces the whole field, so the other direction is re-sent). No gcloud command exists.
  model armor    networksecurity authzPolicies: CONTENT_AUTHZ, action CUSTOM -> Model Armor authz extension
  setup          Model Armor template  POST https://modelarmor.R.rep.googleapis.com/v1/projects/P/locations/R/templates
                   ?templateId=T; gcloud model-armor templates create (flags checked with --help; regional endpoint
                   via CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR); Terraform google_model_armor_template
                 authz extension  POST https://networkservices.googleapis.com/v1/projects/P/locations/R/authzExtensions
                   ?authzExtensionId=NAME (long-running); gcloud service-extensions authz-extensions import;
                   Terraform google_network_services_authz_extension
                 service agent roles  project getIamPolicy / setIamPolicy (read-modify-write); gcloud projects
                   add-iam-policy-binding; Terraform google_project_iam_member
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from . import hcl
from .conditions import EGRESSOR, condition_for
from .english import PROJECT_AGENTS_RE, engine_principal_parts, intent_english, member_label
from .gcp import model_armor as ma_mod
from .model import (Anatomy, Bundle, Condition, Context, Intent, Outputs, RenderItem, RenderResult, SetupParams,
                    TemplateFilters)

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
# Bundle order: gateway bindings, Model Armor setup (template -> extension -> service agent roles), Model Armor
# on/off, grants. Setup deletes (undo) run after Model Armor off, in reverse.
ORDER = {"bind_gateway": 0, "unbind_gateway": 0, "model_armor_template": 1, "model_armor_extension": 2,
         "iam_project_grant": 3, "model_armor_on": 4, "model_armor_off": 4, "grant": 5, "revoke": 5}
DELETE_ORDER = {"iam_project_grant": 6, "model_armor_extension": 7, "model_armor_template": 8}
PLACEHOLDER_EXT = "MODEL_ARMOR_EXTENSION"


# ====================================================================== environment
@dataclass
class RenderEnv:
    ctx: Context
    engines: dict[str, dict[str, str]] = field(default_factory=dict)   # engine name -> {egress?, ingress?}
    engine_info: dict[str, dict[str, Any]] = field(default_factory=dict)  # engine name -> {display_name, bindable}
    mcp_tools: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # mcp id -> [{name, read_only}]
    staged_egress: set[str] = field(default_factory=set)   # engines a staged intent binds to an egress gateway
    staged_extensions: list[str] = field(default_factory=list)  # Model Armor extensions created by staged intents
    staged_templates: list[str] = field(default_factory=list)   # Model Armor templates created by staged intents
    known_extensions: Optional[list[str]] = None   # Model Armor extensions discovery found (None = not looked up)

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
    staged_extension: bool = False      # the extension is created by a staged intent in this cart


@dataclass
class TemplateSpec:
    op: str                        # create | delete
    project: str
    region: str
    template_id: str
    name: str                      # projects/P/locations/R/templates/T
    body: dict[str, Any]
    summary: list[str]


@dataclass
class ExtSpec:
    op: str                        # create | delete
    project: str
    region: str
    ext_id: str
    name: str                      # projects/P/locations/R/authzExtensions/NAME
    template: str                  # full template name
    body: dict[str, Any]
    staged_template: bool


@dataclass
class ProjIamSpec:
    op: str                        # add | remove
    project: str
    member: str
    roles: list[str]
    gateway: str


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


def engine_info_for(env: RenderEnv, engine: str) -> dict[str, Any]:
    """Discovery info of an engine, matched by full name or, failing that, by engine id (project id vs number)."""
    info = env.engine_info.get(engine)
    if info is None:
        eid = short(engine)
        info = next((v for k, v in env.engine_info.items() if short(k) == eid), None)
    return info or {}


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
    info = engine_info_for(env, engine)
    if intent.kind == "bind_gateway" and info and not info.get("bindable", True):
        raise Blocked(f"{info.get('display_name') or short(engine)} can't be bound to Agent Gateway. "
                      + (info.get("bindable_reason") or "It was created before 2026-04-29; redeploy it first."))
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
    staged = False
    if intent.kind == "model_armor_on" and not ext and env.staged_extensions:
        ext = next((x for x in env.staged_extensions if project_of(x) == project), env.staged_extensions[0])
        staged = True
    elif ext and ext in env.staged_extensions:
        staged = True
    if intent.kind == "model_armor_on" and ext and not staged and env.known_extensions is not None and \
            not any(short(x) == short(ext) for x in env.known_extensions):
        warnings.append(f"Model Armor isn't set up in {env.region} yet: the extension {short(ext)} doesn't exist and "
                        "isn't staged in this cart. Stage the setup (template, extension, service agent roles) with "
                        "this item.")
    if intent.kind == "model_armor_on" and not ext:
        ext = f"projects/{project}/locations/{env.region}/authzExtensions/{PLACEHOLDER_EXT}"
        warnings.append(f"Model Armor isn't set up in {env.region} yet: there's no Model Armor authz extension for "
                        "this gateway to use. Set it up first (a template, an extension and permissions for the "
                        "gateway's service agent); this item then uses the new extension automatically. Until then "
                        f"the commands below use the placeholder {PLACEHOLDER_EXT}.")
    return MaSpec(op="on" if intent.kind == "model_armor_on" else "off", gateway=gateway, project=project,
                  policy=policy, extension=ext, staged_extension=staged)


class Blocked(ValueError):
    """An intent that can't work as staged (rendered as a per-item error with just this message)."""


_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")


def setup_project(p: SetupParams, env: RenderEnv) -> str:
    return (p.project or "").strip() or env.gw_project


def template_spec(intent: Intent, env: RenderEnv, warnings: list[str]) -> TemplateSpec:
    p = intent.params or SetupParams()
    project = setup_project(p, env)
    tid = short(p.template_id or "")
    if not tid:
        warnings.append("No template id: enter a name for the template.")
        tid = "TEMPLATE_ID"
    elif not _ID_RE.match(tid):
        warnings.append(f"Template id {tid!r} should use only letters, digits, - and _ (at most 63).")
    filters = p.filters or TemplateFilters()
    body: dict[str, Any] = {}
    summary: list[str] = []
    if not p.delete:
        if filters.sdp == "advanced" and not p.inspect_template:
            warnings.append("Sensitive data “advanced” needs a Sensitive Data Protection inspect template; the "
                            "commands use the placeholder INSPECT_TEMPLATE.")
        body = ma_mod.template_body(filters, p.block_message if p.block_message is not None
                                    else ma_mod.DEFAULT_BLOCK_MESSAGE, p.inspect_template)
        if not body["filterConfig"]:
            warnings.append("Every filter is off, so this template screens nothing.")
        summary = ma_mod.parse_template({"name": "x", **body}).summary
    return TemplateSpec(op="delete" if p.delete else "create", project=project, region=env.region, template_id=tid,
                        name=f"projects/{project}/locations/{env.region}/templates/{tid}", body=body, summary=summary)


def ext_spec(intent: Intent, env: RenderEnv, warnings: list[str]) -> ExtSpec:
    p = intent.params or SetupParams()
    project = setup_project(p, env)
    name = short(p.name or "")
    if not name:
        warnings.append("No extension name: enter a name for the authz extension.")
        name = "EXTENSION_NAME"
    elif not re.match(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", name):
        warnings.append(f"Extension name {name!r} should be lowercase letters, digits and hyphens, starting with a "
                        "letter (at most 63).")
    template = ""
    if not p.delete:
        if not p.template:
            warnings.append("No template: pick the Model Armor template this extension screens with.")
        template = ma_mod.template_name(project, env.region, p.template or "TEMPLATE_ID")
        loc = ma_mod.region_of(template, env.region)
        if loc != env.region:
            warnings.append(f"The template is in {loc}, but the extension is in {env.region}: a Model Armor "
                            "extension uses templates of its own region.")
    body = ma_mod.extension_body(env.region, template) if not p.delete else {}
    return ExtSpec(op="delete" if p.delete else "create", project=project, region=env.region, ext_id=name,
                   name=f"projects/{project}/locations/{env.region}/authzExtensions/{name}", template=template,
                   body=body, staged_template=template in env.staged_templates)


def proj_iam_spec(intent: Intent, env: RenderEnv, warnings: list[str]) -> ProjIamSpec:
    p = intent.params or SetupParams()
    member = ma_mod.normalize_member(p.member or "")
    if not member:
        warnings.append("No member: pick the gateway service agent to grant the roles to.")
        member = "serviceAccount:SERVICE_AGENT"
    roles = list(dict.fromkeys(p.roles or ma_mod.MA_ROLES))
    other = [r for r in roles if r not in ma_mod.MA_ROLES]
    if other:
        warnings.append(f"Policy Studio only grants the Model Armor roles ({', '.join(ma_mod.MA_ROLES)}); Apply "
                        f"refuses {', '.join(other)}.")
    return ProjIamSpec(op="remove" if p.delete else "add", project=setup_project(p, env), member=member,
                       roles=roles, gateway=p.gateway or "")


def with_staged(env: RenderEnv, intents: list[Intent]) -> RenderEnv:
    """Remember the Model Armor templates / extensions that staged intents create, so later intents in the same
    cart (an extension naming the template, model_armor_on without an extension) refer to them."""
    exts, tmpls = list(env.staged_extensions), list(env.staged_templates)
    for it in intents:
        if it.is_delete or not it.params:
            continue
        project = setup_project(it.params, env)
        if it.kind == "model_armor_extension" and it.params.name:
            n = f"projects/{project}/locations/{env.region}/authzExtensions/{short(it.params.name)}"
            if n not in exts:
                exts.append(n)
        if it.kind == "model_armor_template" and it.params.template_id:
            n = f"projects/{project}/locations/{env.region}/templates/{short(it.params.template_id)}"
            if n not in tmpls:
                tmpls.append(n)
    return replace(env, staged_extensions=exts, staged_templates=tmpls)


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
    if sp.staged_extension:
        notes.append(f"uses {short(sp.extension)}, which an earlier item in this cart creates (run that first; the "
                     "bundle orders it so)")
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


def _tf_project(project: str, env: RenderEnv) -> str:
    return "local.gateway_project" if project == env.gw_project else (
        "var.project_id" if project == env.project else hcl.q(project))


def _tf_where(b: hcl.Block, project: str, env: RenderEnv, bundle: bool) -> None:
    if bundle:
        b.attr("project", _tf_project(project, env))
        b.attr("location", "var.region")
    else:
        b.s("project", project)
        b.s("location", env.region)


def _depends(b: hcl.Block, deps: Optional[list[str]]) -> None:
    if deps:
        b.blank()
        b.attr("depends_on", "[" + ", ".join(deps) + "]")


def tf_ma(sp: MaSpec, env: RenderEnv, name: str, bundle: bool, deps: Optional[list[str]] = None) -> str:
    b = hcl.Block(f'resource "google_network_security_authz_policy" "{name}"')
    if bundle:
        b.attr("project", _tf_project(sp.project, env))
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
    _depends(b, deps)
    text = b.render()
    if sp.op == "on":
        return text
    return (hcl.comment_lines(
        "Model Armor off: Terraform deletes the authz policy when its resource is removed. Delete this block from "
        "your configuration and run `terraform apply`. If the policy was created outside Terraform, use the "
        "gcloud, REST or Python tab instead.") + "#\n" + hcl.commented(text))


# ====================================================================== Model Armor setup
def py_obj(v: Any, ind: int = 0) -> str:
    """Python literal for JSON data (True/False/None), indented like json.dumps(indent=4)."""
    pad, inner = "    " * ind, "    " * (ind + 1)
    if isinstance(v, dict):
        if not v:
            return "{}"
        return "{\n" + "".join(f"{inner}{py_str(k)}: {py_obj(x, ind + 1)},\n" for k, x in v.items()) + pad + "}"
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[\n" + "".join(f"{inner}{py_obj(x, ind + 1)},\n" for x in v) + pad + "]"
    if isinstance(v, bool):
        return "True" if v else "False"
    if v is None:
        return "None"
    if isinstance(v, str):
        return py_str(v)
    return json.dumps(v)


def ma_template_url(sp: TemplateSpec, with_id: bool) -> str:
    base = f"{ma_mod.modelarmor(sp.region)}/projects/{sp.project}/locations/{sp.region}/templates"
    return f"{base}?templateId={sp.template_id}" if with_id else f"{base}/{sp.template_id}"


def ext_url(sp: ExtSpec, with_id: bool) -> str:
    base = f"https://networkservices.googleapis.com/v1/projects/{sp.project}/locations/{sp.region}/authzExtensions"
    return f"{base}?authzExtensionId={sp.ext_id}" if with_id else f"{base}/{sp.ext_id}"


def template_anatomy(sp: TemplateSpec) -> Anatomy:
    notes = ["resource: a Model Armor template, a named set of filters in one region "
             f"(API host modelarmor.{sp.region}.rep.googleapis.com)",
             "a template does nothing on its own: an authz extension names it, and an authz policy attaches the "
             "extension to a gateway"]
    if sp.op == "create":
        notes += [f"filter: {line}" for line in sp.summary]
        notes.append("templateMetadata: the custom error code / message is what callers see when a request or "
                     "response is blocked; logging of sanitize operations helps you tune the filters")
    else:
        notes.append("delete: fails while an authz extension still uses the template; delete the extension first")
    return Anatomy(resource=sp.name, role="Model Armor template (filters)",
                   member="(used by a Model Armor authz extension)", notes=notes)


def gcloud_template(sp: TemplateSpec) -> str:
    env_line = f"CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR=https://modelarmor.{sp.region}.rep.googleapis.com/"
    head = ("# gcloud model-armor talks to the regional endpoint, set here for this one command. Flags checked against\n"
            "# `gcloud model-armor templates create --help`; the REST tab sends the identical body.\n")
    if sp.op == "delete":
        return head + cont([f"{env_line} gcloud model-armor templates delete {sp.template_id}",
                            f"--project={sp.project}", f"--location={sp.region}", "--quiet"])
    fc = sp.body["filterConfig"]
    md = sp.body["templateMetadata"]
    flags = [f"{env_line} gcloud model-armor templates create {sp.template_id}", f"--project={sp.project}",
             f"--location={sp.region}"]
    pi = fc.get("piAndJailbreakFilterSettings")
    if pi:
        flags += ["--pi-and-jailbreak-filter-settings-enforcement=enabled",
                  "--pi-and-jailbreak-filter-settings-confidence-level="
                  + pi["confidenceLevel"].lower().replace("_", "-")]
    sdp = fc.get("sdpSettings") or {}
    if "basicConfig" in sdp:
        flags.append("--basic-config-filter-enforcement=enabled")
    if "advancedConfig" in sdp:
        flags.append(f"--advanced-config-inspect-template={shq(sdp['advancedConfig']['inspectTemplate'])}")
    if "maliciousUriFilterSettings" in fc:
        flags.append("--malicious-uri-filter-settings-enforcement=enabled")
    rai = (fc.get("raiSettings") or {}).get("raiFilters")
    if rai:
        flags.append("--rai-settings-filters=" + shq(json.dumps(
            [{"confidenceLevel": r["confidenceLevel"], "filterType": r["filterType"]} for r in rai],
            separators=(",", ":"))))
    if md.get("customPromptSafetyErrorMessage"):
        flags += ["--template-metadata-custom-prompt-safety-error-code=403",
                  f"--template-metadata-custom-prompt-safety-error-message={shq(md['customPromptSafetyErrorMessage'])}",
                  "--template-metadata-custom-llm-response-safety-error-code=403",
                  "--template-metadata-custom-llm-response-safety-error-message="
                  + shq(md["customLlmResponseSafetyErrorMessage"])]
    flags += ["--template-metadata-log-operations", "--template-metadata-log-sanitize-operations"]
    return head + cont(flags)


def rest_template(sp: TemplateSpec) -> str:
    if sp.op == "delete":
        return curl("DELETE", ma_template_url(sp, False))
    return ("# Returns the template (not a long-running operation).\n"
            + curl("POST", ma_template_url(sp, True), body=json.dumps(sp.body, separators=(",", ":"))))


PY_TEMPLATE_HELPERS = """import json

from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1  # pip install google-cloud-modelarmor


def _model_armor(region):
    # Model Armor is regional: the client must use the region's endpoint.
    return modelarmor_v1.ModelArmorClient(
        client_options=ClientOptions(api_endpoint=f"modelarmor.{region}.rep.googleapis.com"))


def create_template(project, region, template_id, body):
    \"\"\"Create a Model Armor template from its REST body (the same JSON as the REST tab).\"\"\"
    template = modelarmor_v1.Template.from_json(json.dumps(body))
    created = _model_armor(region).create_template(
        parent=f"projects/{project}/locations/{region}", template_id=template_id, template=template)
    print("created", created.name)
    return created


def delete_template(project, region, template_id):
    _model_armor(region).delete_template(name=f"projects/{project}/locations/{region}/templates/{template_id}")
    print("deleted", template_id)
"""


def python_template_call(sp: TemplateSpec) -> str:
    if sp.op == "delete":
        return f"delete_template({py_str(sp.project)}, {py_str(sp.region)}, {py_str(sp.template_id)})"
    return (f"create_template(\n    {py_str(sp.project)},\n    {py_str(sp.region)},\n    {py_str(sp.template_id)},\n"
            f"    {py_obj(sp.body, 1)},\n)")


def tf_template(sp: TemplateSpec, env: RenderEnv, name: str, bundle: bool) -> str:
    b = hcl.Block(f'resource "google_model_armor_template" "{name}"')
    _tf_where(b, sp.project, env, bundle)
    b.s("template_id", sp.template_id)
    fc = sp.body.get("filterConfig") or {}
    md = sp.body.get("templateMetadata") or {}
    b.blank()
    f = b.block("filter_config")
    if fc.get("piAndJailbreakFilterSettings"):
        pi = f.block("pi_and_jailbreak_filter_settings")
        pi.s("filter_enforcement", "ENABLED")
        pi.s("confidence_level", fc["piAndJailbreakFilterSettings"]["confidenceLevel"])
    sdp = fc.get("sdpSettings") or {}
    if "basicConfig" in sdp:
        f.block("sdp_settings").block("basic_config").s("filter_enforcement", "ENABLED")
    if "advancedConfig" in sdp:
        f.block("sdp_settings").block("advanced_config").s("inspect_template",
                                                           sdp["advancedConfig"]["inspectTemplate"])
    if "maliciousUriFilterSettings" in fc:
        f.block("malicious_uri_filter_settings").s("filter_enforcement", "ENABLED")
    rai = (fc.get("raiSettings") or {}).get("raiFilters") or []
    if rai:
        rb = f.block("rai_settings")
        for r in rai:
            x = rb.block("rai_filters")
            x.s("filter_type", r["filterType"])
            x.s("confidence_level", r["confidenceLevel"])
    if md:
        b.blank()
        m = b.block("template_metadata")
        for key, tf_key in (("customPromptSafetyErrorCode", "custom_prompt_safety_error_code"),
                            ("customPromptSafetyErrorMessage", "custom_prompt_safety_error_message"),
                            ("customLlmResponseSafetyErrorCode", "custom_llm_response_safety_error_code"),
                            ("customLlmResponseSafetyErrorMessage", "custom_llm_response_safety_error_message"),
                            ("logSanitizeOperations", "log_sanitize_operations"),
                            ("logTemplateOperations", "log_template_operations")):
            if key in md:
                m.attr(tf_key, hcl.obj(md[key], 2))
    text = b.render()
    if sp.op == "create":
        return text
    return (hcl.comment_lines(
        "Delete the template: remove its google_model_armor_template block and run `terraform apply`. If it was "
        "created outside Terraform, use the gcloud, REST or Python tab.") + "#\n" + hcl.commented(text))


def ext_anatomy(sp: ExtSpec) -> Anatomy:
    notes = [f"resource: a Network Services authz extension; service modelarmor.{sp.region}.rep.googleapis.com "
             "makes it a Model Armor extension",
             "metadata.model_armor_settings: a JSON string naming the template for requests and for responses",
             "failOpen false: if Model Armor can't be reached, traffic is blocked rather than let through unscreened",
             "timeout 5s: how long the gateway waits for Model Armor's verdict",
             "the extension is attached to a gateway by a CONTENT_AUTHZ authz policy (Model Armor on)",
             "a long-running operation"]
    if sp.staged_template:
        notes.append(f"uses template {short(sp.template)}, which an earlier item in this cart creates")
    if sp.op == "delete":
        notes = ["delete: fails while an authz policy (Model Armor on) still uses the extension; turn Model Armor "
                 "off first", "a long-running operation"]
    return Anatomy(resource=sp.name, role=f"service modelarmor.{sp.region}.rep.googleapis.com",
                   member=sp.template or "(deleted)", notes=notes)


def ext_yaml(sp: ExtSpec) -> str:
    return (f"name: {sp.ext_id}\n"
            f"service: {sp.body['service']}\n"
            "failOpen: false\n"
            f"timeout: {sp.body['timeout']}\n"
            "metadata:\n"
            f"  model_armor_settings: '{sp.body['metadata']['model_armor_settings']}'\n")


def gcloud_ext(sp: ExtSpec) -> str:
    if sp.op == "delete":
        return cont([f"gcloud service-extensions authz-extensions delete {sp.ext_id}", f"--location={sp.region}",
                     f"--project={sp.project}", "--quiet"])
    f = f"{sp.ext_id}.yaml"
    return (f"cat > {f} <<'EOF'\n{ext_yaml(sp)}EOF\n"
            + cont([f"gcloud service-extensions authz-extensions import {sp.ext_id}", f"--source={f}",
                    f"--location={sp.region}", f"--project={sp.project}"]))


def rest_ext(sp: ExtSpec) -> str:
    if sp.op == "delete":
        return "# Long-running operation.\n" + curl("DELETE", ext_url(sp, False))
    return ("# Long-running operation: poll the returned operation name.\n"
            + curl("POST", ext_url(sp, True), body=json.dumps(sp.body, separators=(",", ":"))))


PY_EXT_HELPERS = """import json

from google.cloud import network_services_v1  # pip install google-cloud-network-services

dep = network_services_v1.DepServiceClient()


def create_authz_extension(project, region, name, body):
    \"\"\"Create an authz extension from its REST body (long-running).\"\"\"
    parent = f"projects/{project}/locations/{region}"
    ext = network_services_v1.AuthzExtension.from_json(
        json.dumps({"name": f"{parent}/authzExtensions/{name}", **body}))
    op = dep.create_authz_extension(parent=parent, authz_extension_id=name, authz_extension=ext)
    return op.result(timeout=900)


def delete_authz_extension(project, region, name):
    op = dep.delete_authz_extension(name=f"projects/{project}/locations/{region}/authzExtensions/{name}")
    return op.result(timeout=900)
"""


def python_ext_call(sp: ExtSpec) -> str:
    if sp.op == "delete":
        return f"delete_authz_extension({py_str(sp.project)}, {py_str(sp.region)}, {py_str(sp.ext_id)})"
    return (f"create_authz_extension(\n    {py_str(sp.project)},\n    {py_str(sp.region)},\n    {py_str(sp.ext_id)},\n"
            f"    {py_obj(sp.body, 1)},\n)")


def tf_ext(sp: ExtSpec, env: RenderEnv, name: str, bundle: bool, deps: Optional[list[str]] = None) -> str:
    b = hcl.Block(f'resource "google_network_services_authz_extension" "{name}"')
    _tf_where(b, sp.project, env, bundle)
    b.s("name", sp.ext_id)
    b.s("service", sp.body.get("service") or f"modelarmor.{sp.region}.rep.googleapis.com")
    b.s("timeout", sp.body.get("timeout") or "5s")
    b.attr("fail_open", "false")
    settings = [{"request_template_id": sp.template, "response_template_id": sp.template}]
    b.attr("metadata", "{\n    model_armor_settings = jsonencode(" + hcl.obj(settings, 2) + ")\n  }")
    _depends(b, deps)
    text = b.render()
    if sp.op == "create":
        return text
    return (hcl.comment_lines(
        "Delete the extension: remove its google_network_services_authz_extension block and run `terraform apply`. "
        "If it was created outside Terraform, use the gcloud, REST or Python tab.") + "#\n" + hcl.commented(text))


def proj_iam_anatomy(sp: ProjIamSpec) -> Anatomy:
    notes = ["resource: the project that holds the Model Armor template (project-level IAM)",
             "roles/modelarmor.calloutUser: lets the gateway call Model Armor as a service extension",
             "roles/modelarmor.user: lets it use the template to screen content",
             "roles/serviceusage.serviceUsageConsumer: lets it use the Model Armor API in this project",
             "member: the gateway's service agent, the identity the gateway uses for extension callouts "
             "(agentGatewayCard.serviceExtensionsServiceAccount; for ingress gateways also the Agent Runtime "
             "service agent, verified in one project: check yours)",
             "read-modify-write of the project IAM policy with its etag; other bindings are untouched"]
    if sp.op == "remove":
        notes.append("remove: takes the member out of these roles' unconditional bindings only")
    return Anatomy(resource=f"projects/{sp.project}", role=", ".join(sp.roles), member=sp.member, notes=notes)


def gcloud_proj_iam(sp: ProjIamSpec) -> str:
    verb = "add-iam-policy-binding" if sp.op == "add" else "remove-iam-policy-binding"
    return "\n".join(cont([f"gcloud projects {verb} {sp.project}", f"--member={shq(sp.member)}", f"--role={r}",
                           "--condition=None"]) for r in sp.roles)


def rest_proj_iam(sp: ProjIamSpec) -> str:
    jq = JQ_ADD if sp.op == "add" else JQ_REMOVE
    lines = [f"RESOURCE={shq(f'https://cloudresourcemanager.googleapis.com/v1/projects/{sp.project}')}",
             f"MEMBER={shq(sp.member)}",
             "TITLE=''",
             "EXPR=''",
             "",
             f"# Read-modify-write per role: get the project policy, {'add' if sp.op == 'add' else 'remove'} the "
             "member with jq, set it back (the etag guards against concurrent edits).",
             f"for ROLE in {' '.join(sp.roles)}; do",
             "  " + cont(['curl -sS --fail-with-body -X POST "$RESOURCE:getIamPolicy"',
                          '-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"',
                          "-d '{\"options\":{\"requestedPolicyVersion\":3}}'"], "    ") + " \\",
             '  | jq --arg role "$ROLE" --arg member "$MEMBER" --arg title "$TITLE" --arg expr "$EXPR" \'',
             jq + "' \\",
             "  " + cont(['| curl -sS --fail-with-body -X POST "$RESOURCE:setIamPolicy"',
                          '-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json"', "-d @-"],
                         "    "),
             "done"]
    return "\n".join(lines)


PY_PROJECT_IAM_HELPERS = """from google.cloud import resourcemanager_v3  # pip install google-cloud-resource-manager
from google.iam.v1 import iam_policy_pb2, options_pb2, policy_pb2

crm = resourcemanager_v3.ProjectsClient()


def _project_policy(project):
    return crm.get_iam_policy(request=iam_policy_pb2.GetIamPolicyRequest(
        resource=f"projects/{project}", options=options_pb2.GetPolicyOptions(requested_policy_version=3)))


def _has(policy, member, role):
    return any(b.role == role and member in b.members and not b.condition.expression for b in policy.bindings)


def grant_project_roles(project, member, roles):
    \"\"\"Add member to each role (unconditional) on the project; read-modify-write with the etag.\"\"\"
    policy = _project_policy(project)
    added = [r for r in roles if not _has(policy, member, r)]
    for role in added:
        policy.bindings.append(policy_pb2.Binding(role=role, members=[member]))
    if added:
        policy.version = 3
        crm.set_iam_policy(request=iam_policy_pb2.SetIamPolicyRequest(resource=f"projects/{project}", policy=policy))
    print(f"granted {added or 'nothing (already granted)'} to {member} on {project}")


def revoke_project_roles(project, member, roles):
    \"\"\"Remove member from the unconditional bindings of these roles; other bindings are kept.\"\"\"
    policy = _project_policy(project)
    kept, removed = [], []
    for b in policy.bindings:
        members = list(b.members)
        if b.role in roles and member in members and not b.condition.expression:
            members.remove(member)
            removed.append(b.role)
        if members:
            nb = policy_pb2.Binding(role=b.role, members=members)
            if b.HasField("condition"):
                nb.condition.CopyFrom(b.condition)
            kept.append(nb)
    if removed:
        policy.ClearField("bindings")
        policy.bindings.extend(kept)
        policy.version = 3
        crm.set_iam_policy(request=iam_policy_pb2.SetIamPolicyRequest(resource=f"projects/{project}", policy=policy))
    print(f"removed {removed or 'nothing'} from {member} on {project}")
"""


def python_proj_iam_call(sp: ProjIamSpec) -> str:
    fn = "grant_project_roles" if sp.op == "add" else "revoke_project_roles"
    return (f"{fn}(\n    {py_str(sp.project)},\n    {py_str(sp.member)},\n    {py_obj(sp.roles, 1)},\n)")


def tf_proj_iam(sp: ProjIamSpec, env: RenderEnv, name: str, bundle: bool) -> str:
    b = hcl.Block(f'resource "google_project_iam_member" "{name}"')
    b.attr("for_each", "toset(" + hcl.obj(sp.roles, 1) + ")")
    b.blank()
    b.attr("project", _tf_project(sp.project, env) if bundle else hcl.q(sp.project))
    b.attr("role", "each.value")
    b.s("member", sp.member)
    text = b.render()
    if sp.op == "add":
        return text
    return (hcl.comment_lines(
        "Remove the roles: delete this google_project_iam_member block and run `terraform apply`. If they were "
        "granted outside Terraform, use the gcloud, REST or Python tab.") + "#\n" + hcl.commented(text))


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
    elif isinstance(spec, TemplateSpec):
        base = f"ma_template_{spec.template_id}"
    elif isinstance(spec, ExtSpec):
        base = f"ma_extension_{spec.ext_id}"
    elif isinstance(spec, ProjIamSpec):
        base = f"ma_roles_{spec.member.split(':', 1)[-1].split('@', 1)[0]}"
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
    if k == "model_armor_template":
        sp = template_spec(intent, env, warnings)
        name = tf_name or _tf_name(intent, sp)
        return _assemble(intent.id, k, intent_english(intent), template_anatomy(sp), sp, gcloud_template(sp),
                         rest_template(sp), PY_TEMPLATE_HELPERS, python_template_call(sp),
                         tf_template(sp, env, name, bundle=False), name, warnings)
    if k == "model_armor_extension":
        sp = ext_spec(intent, env, warnings)
        name = tf_name or _tf_name(intent, sp)
        return _assemble(intent.id, k, intent_english(intent), ext_anatomy(sp), sp, gcloud_ext(sp), rest_ext(sp),
                         PY_EXT_HELPERS, python_ext_call(sp), tf_ext(sp, env, name, bundle=False), name, warnings)
    if k == "iam_project_grant":
        sp = proj_iam_spec(intent, env, warnings)
        name = tf_name or _tf_name(intent, sp)
        return _assemble(intent.id, k, intent_english(intent), proj_iam_anatomy(sp), sp, gcloud_proj_iam(sp),
                         rest_proj_iam(sp), PY_PROJECT_IAM_HELPERS, python_proj_iam_call(sp),
                         tf_proj_iam(sp, env, name, bundle=False), name, warnings)
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
    # Resources created in this bundle that later ones depend on (Model Armor setup before Model Armor on).
    tmpl_ref = {r.spec.name: f"google_model_armor_template.{r.tf_name}" for r in rendered
                if isinstance(r.spec, TemplateSpec) and r.spec.op == "create"}
    ext_ref = {r.spec.name: f"google_network_services_authz_extension.{r.tf_name}" for r in rendered
               if isinstance(r.spec, ExtSpec) and r.spec.op == "create"}
    iam_refs = {r.spec.project: [] for r in rendered if isinstance(r.spec, ProjIamSpec)}
    for r in rendered:
        if isinstance(r.spec, ProjIamSpec) and r.spec.op == "add":
            iam_refs[r.spec.project].append(f"google_project_iam_member.{r.tf_name}")
    for r in rendered:
        out.append("\n")
        out.append(f"# {r.item.english}\n")
        if isinstance(r.spec, IamSpec):
            out.append(tf_iam(r.spec, env, r.tf_name, bundle=True))
        elif isinstance(r.spec, BindSpec):
            out.append(tf_bind(r.spec, env, r.tf_name, bundle=True))
        elif isinstance(r.spec, TemplateSpec):
            out.append(tf_template(r.spec, env, r.tf_name, bundle=True))
        elif isinstance(r.spec, ExtSpec):
            dep = tmpl_ref.get(r.spec.template)
            out.append(tf_ext(r.spec, env, r.tf_name, bundle=True, deps=[dep] if dep else None))
        elif isinstance(r.spec, ProjIamSpec):
            out.append(tf_proj_iam(r.spec, env, r.tf_name, bundle=True))
        else:
            deps = []
            if r.spec.op == "on" and r.spec.extension in ext_ref:
                deps = [ext_ref[r.spec.extension]] + iam_refs.get(project_of(r.spec.extension) or "", [])
            out.append(tf_ma(r.spec, env, r.tf_name, bundle=True, deps=deps))
    return re.sub(r"\n{3,}", "\n\n", "".join(out)).rstrip("\n") + "\n"


def _shell_header(env: RenderEnv, what: str) -> str:
    return ("#!/usr/bin/env bash\n"
            f"# {what} generated by Policy Studio for project {env.project} ({env.number}), region {env.region}"
            + (f", gateway project {env.gw_project}" if env.gw_project != env.project else "") + ".\n"
            "# Review before running. Order: gateway bindings, Model Armor setup (template, extension, service\n"
            "# agent roles), Model Armor on/off, then grants.\n"
            "set -euo pipefail\n")


def _section(n: int, total: int, english: str) -> str:
    return f"\n# ---- [{n}/{total}] {english}\n"


def order_key(r: _Rendered) -> int:
    if getattr(r.spec, "op", "") in ("delete", "remove") and r.kind in DELETE_ORDER:
        return DELETE_ORDER[r.kind]
    return ORDER.get(r.kind, 9)


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
    ordered = sorted(merged, key=order_key)
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
    env = with_staged(replace(env, staged_egress=set(env.staged_egress) | staged), intents)
    touched: dict[str, list[str]] = {}
    items: list[RenderItem] = []
    from .preflight import duplicates      # (imports render; local import avoids the cycle)
    dups = duplicates(intents)
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
            msg = str(ex) if isinstance(ex, Blocked) else f"{type(ex).__name__}: {ex}"
            items.append(RenderItem(intent_id=it.id, english=english, error=msg[:600]))
            continue
        if it.id in dups:
            r.item.warnings.append(f"Same change as item {dups[it.id]} earlier in the cart: left out of the bundle "
                                   "(it's applied once).")
            items.append(r.item)
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
