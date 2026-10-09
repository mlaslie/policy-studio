"""Pydantic types of the API contract (studio/docs/API.md).

Models accept extra fields (`extra="allow"`) so the frontend and backend can evolve independently.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


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


class BoundEngine(_M):
    engine: str
    display_name: str = ""
    direction: Literal["egress", "ingress"]


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
class Engine(_M):
    name: str
    id: str
    display_name: str = ""
    principal: str = ""
    identity_type: str = ""
    gateways: dict[str, str] = Field(default_factory=dict)      # {egress?, ingress?}
    create_time: str = ""
    bindable: bool = False


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
    tools: list[Tool] = Field(default_factory=list)
    error: Optional[str] = None


class Endpoint(_M):
    name: str
    id: str
    display_name: str = ""
    url: Optional[str] = None
    error: Optional[str] = None


class Inventory(_M):
    engines: list[Engine] = Field(default_factory=list)
    agents: list[Agent] = Field(default_factory=list)
    mcp_servers: list[McpServer] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    access: dict[str, list[Binding]] = Field(default_factory=dict)
    access_errors: dict[str, str] = Field(default_factory=dict)
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


class Access(_In):
    mode: Literal["all", "read_only_hint", "tools", "custom"] = "all"
    tools: Optional[list[str]] = None
    expression: Optional[str] = None
    title: Optional[str] = None        # optional: exact condition title (e.g. when revoking an existing binding)


class GatewayRef(_In):
    name: str
    direction: Literal["egress", "ingress"] = "egress"
    extension: Optional[str] = None    # model_armor_on: Model Armor authz extension (filled in by the backend)
    policy: Optional[str] = None       # model_armor_on/off: CONTENT_AUTHZ authz policy name


IntentKind = Literal["grant", "revoke", "bind_gateway", "unbind_gateway", "model_armor_on", "model_armor_off"]


class Intent(_In):
    id: str
    kind: IntentKind
    source: Optional[Source] = None
    destination: Optional[Destination] = None
    access: Optional[Access] = None
    gateway: Optional[GatewayRef] = None
    engine: Optional[str] = None


class Finding(_M):
    severity: Literal["high", "medium", "info"]
    title: str
    detail: str = ""
    resource: Optional[str] = None
    fix: Optional[Intent] = None


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
