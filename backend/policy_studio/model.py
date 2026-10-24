"""Pydantic types of the API contract (studio/docs/API.md).

Models accept extra fields (`extra="allow"`) so the frontend and backend can evolve independently.
"""
from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _M(BaseModel):
    model_config = ConfigDict(extra="allow")


class _In(BaseModel):
    """Request-side models: unknown (client-only) fields are ignored."""
    model_config = ConfigDict(extra="ignore")


# ------------------------------------------------------------------ context
class Context(_M):
    project: str = ""
    region: str = ""
    gateway_project: str = ""          # project of the egress gateway / Agent Registry (defaults to project)
    ge_app: str = ""
    ge_location: str = "us"
    project_number: str = ""           # resolved by the backend
    gateway_project_number: str = ""   # resolved by the backend

    @property
    def gw_project(self) -> str:
        return self.gateway_project or self.project

    def key(self) -> tuple[str, str, str]:
        return (self.project, self.region, self.gw_project)


# ------------------------------------------------------------------ IAM
class Condition(_M):
    title: str = ""
    expression: str = ""
    description: Optional[str] = None


class Binding(_M):
    role: str
    member: str
    member_label: str = ""
    condition: Optional[Condition] = None
    english: str = ""


class Grant(Binding):
    resource: str
    resource_kind: Literal["agent", "mcp_server", "endpoint", "registry"]
    resource_label: str = ""


# ------------------------------------------------------------------ gateways
class AuthzPolicyRef(_M):
    name: str
    profile: str = ""                   # REQUEST_AUTHZ | CONTENT_AUTHZ
    provider: Literal["iap", "model_armor", "other"] = "other"
    extension: str = ""
    enforcement: Optional[Literal["ENFORCE", "DRY_RUN"]] = None


class GatewayEnforcement(_M):
    """How the gateway's IAP REQUEST_AUTHZ check runs. The mode lives on the IAP authz extension (not the gateway):
    ENFORCE = failOpen false, no metadata.iamEnforcementMode; DRY_RUN = metadata.iamEnforcementMode DRY_RUN (and
    usually failOpen true). An extension can serve several gateways (`shared_with`)."""
    mode: Optional[Literal["ENFORCE", "DRY_RUN"]] = None
    extension: str = ""                # full name of the IAP authz extension (project id form when listed)
    policy: str = ""                   # the REQUEST_AUTHZ authz policy that points at it
    failOpen: bool = False
    shared_with: list[str] = Field(default_factory=list)   # other gateways whose IAP policy uses the same extension
    editable: bool = False
    reason: Optional[str] = None       # why it can't be changed here (no IAP policy, extension unreadable, ...)


class BoundEngine(_M):
    engine: str
    display_name: str = ""
    direction: Literal["egress", "ingress"]


class PrivateEgress(_M):
    """The gateway's way into a VPC (connectivity template, or the older inline networkConfig). Detection only."""
    source: Literal["template", "inline"]
    template: Optional[str] = None     # full name, project id form when the number is known
    network_attachment: str = ""
    vpc: Optional[str] = None          # from the attachment's network (or the DNS targetNetwork), when readable
    dns_domains: list[str] = Field(default_factory=list)
    vpc_egress: Optional[Literal["PRIVATE_RANGES_ONLY", "ALL_TRAFFIC"]] = None
    custom_trust: Optional[bool] = None   # template tlsConfig present
    error: Optional[str] = None        # "can't read details: ..." (template unreadable)


class Gateway(_M):
    name: str
    id: str
    project: str = ""
    type: Literal["egress", "ingress"]
    governed_access_path: str = ""
    registries: list[str] = Field(default_factory=list)
    authz_policies: list[AuthzPolicyRef] = Field(default_factory=list)
    bound_engines: list[BoundEngine] = Field(default_factory=list)
    create_time: str = ""
    enforcement: GatewayEnforcement = Field(default_factory=GatewayEnforcement)
    private_egress: Optional[PrivateEgress] = None   # None = public egress only
    error: Optional[str] = None


# ------------------------------------------------------------------ Model Armor
class Template(_M):
    name: str
    id: str
    filters: dict[str, Any] = Field(default_factory=dict)
    block_message: Optional[str] = None
    summary: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------------ inventory
class PscInterface(_M):
    """Agent Runtime's own private networking (pscInterfaceConfig): VPC calls that skip the gateway."""
    network_attachment: str = ""
    vpc: Optional[str] = None
    dns_domains: list[str] = Field(default_factory=list)


class Engine(_M):
    name: str
    id: str
    display_name: str = ""
    principal: str = ""
    identity_type: str = ""
    gateways: dict[str, str] = Field(default_factory=dict)      # {egress?, ingress?}
    create_time: str = ""
    bindable: bool = False
    bindable_reason: Optional[str] = None   # why it can't be bound (PSC interface, no Agent Identity, or too old)
    psc_interface: Optional[PscInterface] = None


class Skill(_M):
    id: str = ""
    name: str = ""
    description: str = ""


class Agent(_M):
    name: str
    id: str
    display_name: str = ""
    kind: Literal["runtime", "a2a"] = "a2a"
    url: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    service: Optional[str] = None      # the writable Service that projects it (None = auto-registered)
    skills: list[Skill] = Field(default_factory=list)
    engine: Optional[str] = None
    error: Optional[str] = None


class Tool(_M):
    name: str
    description: str = ""
    read_only: bool = False
    destructive: bool = False
    annotations: dict[str, Any] = Field(default_factory=dict)


class McpServer(_M):
    name: str
    id: str
    display_name: str = ""
    url: Optional[str] = None
    urls: list[str] = Field(default_factory=list)     # every interface URL (url is the first)
    service: Optional[str] = None      # the writable Agent Registry Service that projects it (None = auto-registered)
    tools: list[Tool] = Field(default_factory=list)
    error: Optional[str] = None


class Endpoint(_M):
    name: str
    id: str
    display_name: str = ""
    url: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    service: Optional[str] = None
    error: Optional[str] = None


class RegistryInterface(_M):
    url: str
    protocol_binding: Literal["JSONRPC", "GRPC", "HTTP_JSON"] = "HTTP_JSON"


class RegistryService(_M):
    """A writable Agent Registry Service (agentregistry v1 .../services). The registry projects it into a read-only
    Agent / McpServer / Endpoint (`registry_resource`, a different id); IAP grants are set on that projection."""
    name: str
    id: str
    kind: Literal["endpoint", "mcp_server", "agent"] = "endpoint"
    display_name: str = ""
    description: str = ""
    interfaces: list[RegistryInterface] = Field(default_factory=list)
    registry_resource: str = ""        # projects/N/locations/R/{endpoints|mcpServers|agents}/ID ("" until projected)
    tool_spec: Optional[dict[str, Any]] = None   # mcpServerSpec TOOL_SPEC content ({tools: [...]}), when set


class Inventory(_M):
    engines: list[Engine] = Field(default_factory=list)
    agents: list[Agent] = Field(default_factory=list)
    mcp_servers: list[McpServer] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    access: dict[str, list[Binding]] = Field(default_factory=dict)
    access_errors: dict[str, str] = Field(default_factory=dict)
    services: list[RegistryService] = Field(default_factory=list)   # writable registry Services (None read = [])
    project_agents_principal: Optional[str] = None
    errors: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------ intents
class Source(_In):
    type: Literal["engine", "project_agents", "custom"] = "custom"
    principal: str
    label: str = ""
    engine: Optional[str] = None


class Destination(_In):
    kind: Literal["agent", "mcp_server", "endpoint", "registry"]   # registry = the whole Agent Registry
    id: str
    name: str = ""
    label: str = ""
    # The id of a registry_service created earlier in the same request: the entry's id isn't known until the registry
    # projects it, so Apply fills it in after the create (and render looks it up).
    pending_service: Optional[str] = None


# MCP tool names allowed in a `toolName in [...]` condition. Tool names come from MCP servers' tool lists, so a name
# with a quote could end the CEL string literal and change the condition (e.g. make it always true) while the preview
# still looks narrow. Real tool names fit this easily (the MCP spec suggests [A-Za-z0-9_.-], 1-128 characters).
TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")


def valid_tool_name(name: str) -> bool:
    return bool(TOOL_NAME_RE.fullmatch(name or ""))


class Access(_In):
    mode: Literal["all", "read_only_hint", "tools", "custom"] = "all"
    tools: Optional[list[str]] = None
    expression: Optional[str] = None
    title: Optional[str] = None        # optional: exact condition title (e.g. when revoking an existing binding)

    @field_validator("tools")
    @classmethod
    def _tool_names(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        bad = [t for t in v or [] if t and not valid_tool_name(t)]
        if bad:
            raise ValueError(f"tool name {bad[0][:60]!r} is not allowed in a condition: tool names may contain only "
                             "letters, digits and _ . - : / (at most 128 characters)")
        return v


class GatewayRef(_In):
    name: str
    direction: Literal["egress", "ingress"] = "egress"
    extension: Optional[str] = None    # model_armor_on: Model Armor authz extension (filled in by the backend)
    policy: Optional[str] = None       # model_armor_on/off: CONTENT_AUTHZ authz policy name


IntentKind = Literal["grant", "revoke", "modify", "bind_gateway", "unbind_gateway", "model_armor_on",
                     "model_armor_off", "model_armor_template", "model_armor_extension", "iam_project_grant",
                     "set_enforcement", "dedicate_extension", "registry_service"]
SETUP_KINDS = ("model_armor_template", "model_armor_extension", "iam_project_grant")
DELETABLE_KINDS = SETUP_KINDS + ("registry_service",)     # params.delete is the inverse (undo)
ENFORCEMENT_KINDS = ("set_enforcement", "dedicate_extension")

Level = Literal["LOW_AND_ABOVE", "MEDIUM_AND_ABOVE", "HIGH", "off"]


class TemplateFilters(_In):
    """Friendly Model Armor filter choices (model_armor_template). Omitted fields use the defaults below."""
    pi_jailbreak: Level = "MEDIUM_AND_ABOVE"
    sdp: Literal["basic", "advanced", "off"] = "basic"
    rai: dict[str, Level] = Field(default_factory=lambda: {
        "HATE_SPEECH": "MEDIUM_AND_ABOVE", "HARASSMENT": "MEDIUM_AND_ABOVE",
        "SEXUALLY_EXPLICIT": "MEDIUM_AND_ABOVE", "DANGEROUS": "MEDIUM_AND_ABOVE"})
    malicious_uri: bool = True


class RegistryInterfaceIn(_In):
    url: str = ""
    protocol_binding: str = "HTTP_JSON"     # JSONRPC | GRPC | HTTP_JSON (checked by preflight)


class SetupParams(_In):
    """Parameters of the Model Armor setup kinds and registry_service. `delete: true` is the inverse (undo) of each."""
    project: Optional[str] = None          # where the template / extension / grant lives (default: gateway project)
    delete: bool = False
    # model_armor_template
    template_id: Optional[str] = None
    filters: Optional[TemplateFilters] = None
    block_message: Optional[str] = None
    inspect_template: Optional[str] = None  # sdp "advanced": Sensitive Data Protection inspect template
    # model_armor_extension
    name: Optional[str] = None
    template: Optional[str] = None          # template id or projects/P/locations/R/templates/T
    # iam_project_grant
    member: Optional[str] = None
    roles: Optional[list[str]] = None
    gateway: Optional[str] = None           # informational: the gateway whose service agent this is
    # registry_service (an Agent Registry entry: one Service, several interface URLs)
    kind: Optional[str] = None              # endpoint | mcp_server (A2A agents need an agent card: not supported)
    service_id: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    interfaces: Optional[list[RegistryInterfaceIn]] = None
    tool_spec: Optional[dict[str, Any]] = None   # mcp_server: TOOL_SPEC content (an undo re-creates it); else NO_SPEC


class Intent(_In):
    id: str
    kind: IntentKind
    source: Optional[Source] = None
    destination: Optional[Destination] = None
    access: Optional[Access] = None
    # modify: the existing binding's condition, exact (mode "custom" with its expression and title, or mode "all" when
    # it has none), as revokes carry it. `access` is the new one. Applied as one read-modify-write.
    access_from: Optional[Access] = None
    # modify with several bindings (backwards compatible: when set, these replace access_from / access):
    # access_from_list = every binding of the member removed (exact, as access_from), access_list = the bindings added.
    # The builder's "change existing access" sends N -> [one]; the "remove all" form sends N -> [] (destructive); an
    # undo sends the new binding(s) -> the removed set, so the original bindings come back exactly. Still one
    # getIamPolicy and one setIamPolicy.
    access_from_list: Optional[list[Access]] = None
    access_list: Optional[list[Access]] = None
    gateway: Optional[GatewayRef] = None
    engine: Optional[str] = None
    params: Optional[SetupParams] = None   # model_armor_template / model_armor_extension / iam_project_grant
    # set_enforcement: the IAP authz extension, the target mode and whether the change is meant for every gateway
    # that shares the extension ("shared") or only this one ("dedicated": the extension is, or is about to be, its own)
    extension: Optional[str] = None
    mode: Optional[Literal["ENFORCE", "DRY_RUN"]] = None
    scope: Optional[Literal["shared", "dedicated"]] = None
    # dedicate_extension: copy source_extension to new_name and point this gateway's IAP policy at the copy.
    # revert = the inverse (undo): point the policy back at source_extension and delete the copy new_name.
    source_extension: Optional[str] = None
    new_name: Optional[str] = None
    revert: Optional[bool] = None

    @model_validator(mode="after")
    def _modify_fields(self) -> "Intent":
        if self.kind == "modify":
            missing = [f for f in ("source", "destination") if getattr(self, f) is None]
            if self.access_from is None and self.access_from_list is None:
                missing.append("access_from")
            if self.access is None and self.access_list is None:
                missing.append("access")
            if missing:
                raise ValueError(f"modify needs {', '.join(missing)}")
            if not self.froms and not self.tos:
                raise ValueError("modify needs at least one binding to remove (access_from_list) or add (access_list)")
        return self

    @property
    def froms(self) -> list[Access]:
        """modify: the bindings removed (access_from_list, else [access_from])."""
        if self.access_from_list is not None:
            return list(self.access_from_list)
        return [self.access_from] if self.access_from is not None else []

    @property
    def tos(self) -> list[Access]:
        """modify: the bindings added (access_list, else [access]); [] = the "remove all" form."""
        if self.access_list is not None:
            return list(self.access_list)
        return [self.access] if self.access is not None else []

    @property
    def multi(self) -> bool:
        """A modify that isn't one binding -> one binding (several removed, none or several added)."""
        return self.kind == "modify" and not (len(self.froms) == 1 and len(self.tos) == 1)

    @property
    def removes_all(self) -> bool:
        """The "remove all" form of modify: bindings removed, none added."""
        return self.kind == "modify" and bool(self.froms) and not self.tos

    @property
    def is_delete(self) -> bool:
        return self.kind in DELETABLE_KINDS and bool(self.params and self.params.delete)

    @property
    def is_destructive(self) -> bool:
        """Revokes, unbinds, Model Armor off, setup and registry entry deletes, dry run (stops blocking) and reverting a dedicated
        extension (deletes it). A modify isn't (render and preflight warn when it widens access), except its "remove
        all" form, which removes every binding it names and adds none."""
        if self.kind in ("revoke", "unbind_gateway", "model_armor_off"):
            return True
        if self.kind == "modify":
            return self.removes_all
        if self.kind == "set_enforcement":
            return self.mode == "DRY_RUN"
        if self.kind == "dedicate_extension":
            return bool(self.revert)
        return self.is_delete


class Finding(_M):
    severity: Literal["high", "medium", "info"]
    title: str
    detail: str = ""
    resource: Optional[str] = None
    fix: Optional[Intent] = None
    redeploy: Optional[str] = None     # how to redeploy with Agent Identity (Python), for engines that can't be bound
    rule: Optional[str] = None         # audit rule id, for rules that have one (N1–N5: private networking)
    guidance: Optional[str] = None     # shell guidance Policy Studio doesn't apply (N3: move to a template)


# ------------------------------------------------------------------ requests / results
class IntentsRequest(_M):
    context: Context
    intents: list[dict[str, Any]] = Field(default_factory=list)   # validated per item (a bad one fails alone)


class ApplyRequest(_M):
    context: Context
    intents: list[dict[str, Any]] = Field(default_factory=list)
    confirm: dict[str, Any] = Field(default_factory=dict)       # {project, acknowledge_destructive}


class Anatomy(_M):
    resource: str = ""
    role: str = ""
    member: str = ""
    condition: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class Outputs(_M):
    terraform: str = ""
    gcloud: str = ""
    rest: str = ""
    python: str = ""


class RenderItem(_M):
    intent_id: str
    error: Optional[str] = None
    english: str = ""
    anatomy: Anatomy = Field(default_factory=Anatomy)
    outputs: Outputs = Field(default_factory=Outputs)
    warnings: list[str] = Field(default_factory=list)


class Bundle(_M):
    terraform: dict[str, str] = Field(default_factory=dict)    # {"main.tf", "variables.tf"}
    gcloud: str = ""
    rest: str = ""
    python: str = ""


class RenderResult(_M):
    items: list[RenderItem] = Field(default_factory=list)
    bundle: Bundle = Field(default_factory=Bundle)


class DiffItem(_M):
    intent_id: str
    status: Literal["add", "present", "replace", "remove", "absent"]
    current: Optional[list[Binding]] = None
    after: Optional[list[Binding]] = None      # the member's bindings on the resource after the change
    detail: str = ""
    error: Optional[str] = None
