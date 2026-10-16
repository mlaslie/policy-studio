"""Agent Registry projections, writable Services, and the IAP IAM policies of the projections (read-only here).

  GET  https://agentregistry.googleapis.com/v1/projects/P/locations/R/{agents|mcpServers|endpoints}
  GET  https://agentregistry.googleapis.com/v1/projects/P/locations/R/services
  POST https://iap.googleapis.com/v1/projects/N/locations/R/iap_web/agentRegistry/{kind}/{id}:getIamPolicy
       {"options": {"requestedPolicyVersion": 3}}
  POST https://iap.googleapis.com/v1/projects/N/locations/R/iap_web/agentRegistry:getIamPolicy   (whole registry)

Services (agentregistry v1, checked against the discovery document, Oct 2026):
  A Service is the writable resource: {displayName (<= 63), description (<= 2048), interfaces[{url, protocolBinding:
  JSONRPC | GRPC | HTTP_JSON}], exactly one of endpointSpec {type: NO_SPEC} | mcpServerSpec {type: NO_SPEC |
  TOOL_SPEC, content: tools/list response, <= 10 KB} | agentSpec {type: NO_SPEC | A2A_AGENT_CARD (interfaces must be
  empty)}}; output only: name, createTime, updateTime, registryResource. create (POST .../services?serviceId=ID; ID
  4-63 characters) and delete (DELETE .../services/ID) return long-running operations. The registry projects each
  Service into a read-only Endpoint / McpServer / Agent with its own id (agentregistry-...), named by
  registryResource (filled shortly after the create); IAP grants are set on that projection, so deleting the Service
  deletes the projection and its IAP policy. An MCP server needs no tool list (NO_SPEC); tool conditions then have no
  tool attributes to match (only full access works).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional
from urllib.parse import urlsplit

from ..model import Agent, Endpoint, McpServer, RegistryInterface, RegistryService, Skill, Tool
from .rest import AGENTREGISTRY, IAP, Rest, err_text

KINDS = {"agents": "agent", "mcpServers": "mcp_server", "endpoints": "endpoint"}
COLLECTION = {v: k for k, v in KINDS.items()}
RUNTIME_REF = "agentregistry.googleapis.com/system/RuntimeReference"


def rid(name: str) -> str:
    return (name or "").rstrip("/").split("/")[-1]


def iap_resource(project_number: str, region: str, kind: str | None = None, xid: str | None = None) -> str:
    """IAP resource path (no host). kind: agent | mcp_server | endpoint (or the collection name)."""
    base = f"projects/{project_number}/locations/{region}/iap_web/agentRegistry"
    if kind and xid:
        return f"{base}/{COLLECTION.get(kind, kind)}/{xid}"
    return base


def first_url(interfaces: list[dict] | None) -> str | None:
    return next((i.get("url") for i in interfaces or [] if i.get("url")), None)


def all_urls(interfaces: list[dict] | None) -> list[str]:
    return [i["url"] for i in interfaces or [] if i.get("url")]


# ------------------------------------------------------------------ Services (the writable side)
BINDINGS = ("JSONRPC", "GRPC", "HTTP_JSON")
DEFAULT_BINDING = {"endpoint": "HTTP_JSON", "mcp_server": "JSONRPC"}
SPEC_KEY = {"endpoint": "endpointSpec", "mcp_server": "mcpServerSpec", "agent": "agentSpec"}
PROJECTION = {"endpoint": "endpoints", "mcp_server": "mcpServers", "agent": "agents"}
SERVICE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,61}[a-z0-9]$")    # 4-63; digits seen on live ids
SINGLE_REGION_RE = re.compile(r"^[a-z]+-[a-z]+\d+$")             # us-east4, europe-west4 (not us / eu / global)
TOOL_SPEC_MAX = 10 * 1024


def services_url(project: str, region: str, sid: str = "") -> str:
    return f"{AGENTREGISTRY}/projects/{project}/locations/{region}/services" + (f"/{sid}" if sid else "")


def list_services(r: Rest, project: str, region: str) -> list[dict]:
    return r.list_all(services_url(project, region), "services", params={"pageSize": 100})


def service_kind(svc: dict) -> str:
    if "mcpServerSpec" in svc:
        return "mcp_server"
    if "agentSpec" in svc:
        return "agent"
    if "endpointSpec" in svc:
        return "endpoint"
    rr = svc.get("registryResource") or ""
    return {"mcpServers": "mcp_server", "agents": "agent"}.get(rr.split("/")[-2] if rr.count("/") >= 1 else "",
                                                                 "endpoint")


def parse_service(svc: dict) -> RegistryService:
    kind = service_kind(svc)
    spec = svc.get("mcpServerSpec") or {}
    return RegistryService(
        name=svc.get("name", ""), id=rid(svc.get("name", "")), kind=kind,
        display_name=svc.get("displayName") or rid(svc.get("name", "")), description=svc.get("description", ""),
        interfaces=[RegistryInterface(url=i.get("url", ""), protocol_binding=i.get("protocolBinding") or "HTTP_JSON")
                    for i in svc.get("interfaces") or [] if i.get("url")
                    and (i.get("protocolBinding") or "HTTP_JSON") in BINDINGS],
        registry_resource=svc.get("registryResource") or "",
        tool_spec=spec.get("content") if spec.get("type") == "TOOL_SPEC" and spec.get("content") else None)


def service_body(kind: str, display_name: str, interfaces: list[dict[str, str]], description: str = "",
                 tool_spec: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """The create body. interfaces: [{url, protocol_binding}]. An MCP server with a tool spec (an undo of a delete)
    keeps it; otherwise NO_SPEC (no tool list needed)."""
    body: dict[str, Any] = {"displayName": (display_name or "")[:63]}
    if description:
        body["description"] = description[:2048]
    body["interfaces"] = [{"url": i["url"], "protocolBinding": i.get("protocol_binding") or DEFAULT_BINDING.get(
        kind, "HTTP_JSON")} for i in interfaces]
    if kind == "mcp_server":
        body["mcpServerSpec"] = {"type": "TOOL_SPEC", "content": tool_spec} if tool_spec else {"type": "NO_SPEC"}
    else:
        body["endpointSpec"] = {"type": "NO_SPEC"}
    return body


def same_interfaces(a: list[dict] | None, b: list[dict] | None) -> bool:
    """Read-back: the same (url, protocolBinding) pairs, in any order."""
    key = lambda xs: sorted((norm_url(i.get("url", "")), i.get("protocolBinding") or "") for i in xs or [])  # noqa: E731
    return key(a) == key(b)


# ------------------------------------------------------------------ URL checks (pure)
def norm_url(url: str) -> str:
    """For duplicate checks: scheme and host lowercased, a trailing slash dropped."""
    u = (url or "").strip()
    try:
        p = urlsplit(u)
    except ValueError:
        return u
    if not p.scheme or not p.netloc:
        return u.rstrip("/")
    path = p.path.rstrip("/")
    return f"{p.scheme.lower()}://{p.netloc.lower()}{path}" + (f"?{p.query}" if p.query else "")


def host_of(url: str) -> str:
    try:
        return (urlsplit((url or "").strip()).hostname or "").lower()
    except ValueError:
        return ""


def url_problem(url: str) -> Optional[str]:
    """Why a URL can't be registered (None = fine): https only, no wildcard, a host."""
    u = (url or "").strip()
    if not u:
        return "the URL is empty"
    if "*" in u:
        return f"{u} has a wildcard: the gateway matches registered hostnames exactly, so register each URL"
    try:
        p = urlsplit(u)
    except ValueError:
        return f"{u} isn't a valid URL"
    if p.scheme.lower() != "https":
        return f"{u} isn't https (the gateway only calls registered https URLs)"
    if not p.hostname:
        return f"{u} has no host name"
    if any(c.isspace() for c in u):
        return f"{u} contains spaces"
    return None


RUN_APP_NUMBER = re.compile(r"^[a-z0-9-]+-\d+\.[a-z0-9-]+\.run\.app$")   # SERVICE-PROJECT_NUMBER.REGION.run.app
RUN_APP_HASH = re.compile(r"^[a-z0-9-]+-[a-z0-9]+-[a-z]{2}\.a\.run\.app$")  # SERVICE-HASH-XX.a.run.app


def run_app_form(url: str) -> Optional[str]:
    """"number" | "hash" for the two Cloud Run URL forms, "other" for another run.app host, None otherwise."""
    h = host_of(url)
    if not h.endswith(".run.app"):
        return None
    if RUN_APP_NUMBER.match(h):
        return "number"
    if RUN_APP_HASH.match(h):
        return "hash"
    return "other"


def run_app_hint(urls: list[str]) -> Optional[str]:
    """A warning when the URLs use only one of Cloud Run's two URL forms (the gateway matches hostnames exactly, so
    a call to the other form isn't registered)."""
    forms = {f for f in (run_app_form(u) for u in urls) if f in ("number", "hash")}
    if len(forms) != 1:
        return None
    have = "SERVICE-PROJECT_NUMBER.REGION.run.app" if forms == {"number"} else "SERVICE-HASH-XX.a.run.app"
    return (f"Only one of Cloud Run's two URL forms is registered ({have}). A Cloud Run service answers on both, and "
            "the gateway matches hostnames exactly: also register the other run.app URL shown on the Cloud Run page.")


def _runtime_ref(x: dict) -> str:
    return (((x.get("attributes") or {}).get(RUNTIME_REF) or {}).get("uri")) or ""


def engine_of(a: dict) -> str | None:
    """Engine resource behind an auto-registered Agent Runtime agent, if any."""
    ref = _runtime_ref(a)
    if "/reasoningEngines/" in ref:
        return ref.split("//", 1)[-1].split("/", 1)[-1] if ref.startswith("//") else ref
    aid = a.get("agentId", "") or ""
    if "reasoningEngines:" in aid:
        parts = aid.split(":")
        try:
            i = parts.index("projects")
            return (f"projects/{parts[i + 1]}/locations/{parts[parts.index('locations') + 1]}/reasoningEngines/"
                    f"{parts[parts.index('reasoningEngines') + 1]}")
        except (ValueError, IndexError):
            return None
    return None


def parse_agent(a: dict) -> Agent:
    card = ((a.get("card") or {}).get("content")) or {}
    protos = a.get("protocols") or []
    proto = next((p for p in protos if p.get("type") == "A2A_AGENT"), protos[0] if protos else {})
    url = first_url(proto.get("interfaces")) or card.get("url")
    skills = [Skill(id=s.get("id", ""), name=s.get("name") or s.get("id", ""), description=s.get("description", ""))
              for s in (a.get("skills") or card.get("skills") or [])]
    eng = engine_of(a)
    return Agent(name=a.get("name", ""), id=rid(a.get("name", "")),
                 display_name=a.get("displayName") or card.get("name") or rid(a.get("name", "")),
                 kind="runtime" if eng else "a2a", url=url, urls=all_urls(proto.get("interfaces")) or ([url] if url else []),
                 skills=skills, engine=eng,
                 description=a.get("description", ""), location=a.get("location"))


def parse_tool(t: dict) -> Tool:
    ann = dict(t.get("annotations") or {})
    return Tool(name=t.get("name", ""), description=t.get("description", ""),
                read_only=bool(ann.get("readOnlyHint")), destructive=bool(ann.get("destructiveHint")),
                annotations=ann)


def parse_mcp(m: dict) -> McpServer:
    return McpServer(name=m.get("name", ""), id=rid(m.get("name", "")),
                     display_name=m.get("displayName") or rid(m.get("name", "")), url=first_url(m.get("interfaces")),
                     urls=all_urls(m.get("interfaces")),
                     tools=[parse_tool(t) for t in m.get("tools", []) or []], description=m.get("description", ""))


def parse_endpoint(e: dict) -> Endpoint:
    return Endpoint(name=e.get("name", ""), id=rid(e.get("name", "")),
                    display_name=e.get("displayName") or rid(e.get("name", "")), url=first_url(e.get("interfaces")),
                    urls=all_urls(e.get("interfaces")), description=e.get("description", ""))


def list_kind(r: Rest, project: str, region: str, kind: str) -> list[dict]:
    return r.list_all(f"{AGENTREGISTRY}/projects/{project}/locations/{region}/{kind}", kind,
                      params={"pageSize": 100})


def get_iam_policy(r: Rest, resource: str) -> dict:
    return r.post(f"{IAP}/{resource}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}) or {}


def fetch(r: Rest, project: str, project_number: str, region: str, workers: int = 12) -> dict[str, Any]:
    """Registry entries + the IAP IAM policy of each (and of the whole registry). Errors are per item."""
    out: dict[str, Any] = {"agents": [], "mcp_servers": [], "endpoints": [], "services": [], "policies": {},
                           "policy_errors": {}, "errors": []}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        lists = {k: pool.submit(list_kind, r, project, region, k) for k in KINDS}
        svc_f = pool.submit(list_services, r, project, region)
        parsed: list[tuple[str, Any]] = []
        for k, f in lists.items():
            try:
                raw = f.result()
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"list {k}: {err_text(e)}")
                continue
            for x in raw:
                item = {"agents": parse_agent, "mcpServers": parse_mcp, "endpoints": parse_endpoint}[k](x)
                out[{"agents": "agents", "mcpServers": "mcp_servers", "endpoints": "endpoints"}[k]].append(item)
                parsed.append((KINDS[k], item))
        try:
            out["services"] = [parse_service(x) for x in svc_f.result()]
        except Exception as e:  # noqa: BLE001  (registering and deleting entries then can't check duplicates)
            out["errors"].append(f"list services: {err_text(e)}")
        by_res = {f"{PROJECTION.get(s.kind, '')}/{rid(s.registry_resource)}": s for s in out["services"]
                  if s.registry_resource}
        for kind, item in parsed:
            svc = by_res.get(f"{COLLECTION[kind]}/{item.id}")
            if svc is not None:
                item.service = svc.name
        registry_key = f"projects/{project}/locations/{region}"
        futs = {pool.submit(get_iam_policy, r, iap_resource(project_number, region, kind, item.id)): item.name
                for kind, item in parsed}
        futs[pool.submit(get_iam_policy, r, iap_resource(project_number, region))] = registry_key
        for f, key in futs.items():
            try:
                out["policies"][key] = f.result()
            except Exception as e:  # noqa: BLE001
                out["policy_errors"][key] = err_text(e)
    for key in ("agents", "mcp_servers", "endpoints"):
        out[key].sort(key=lambda x: (x.display_name or "").lower())
    return out
