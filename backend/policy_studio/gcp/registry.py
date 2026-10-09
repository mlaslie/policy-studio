"""Agent Registry projections and their IAP IAM policies (read-only).

  GET  https://agentregistry.googleapis.com/v1/projects/P/locations/R/{agents|mcpServers|endpoints}
  POST https://iap.googleapis.com/v1/projects/N/locations/R/iap_web/agentRegistry/{kind}/{id}:getIamPolicy
       {"options": {"requestedPolicyVersion": 3}}
  POST https://iap.googleapis.com/v1/projects/N/locations/R/iap_web/agentRegistry:getIamPolicy   (whole registry)
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..model import Agent, Endpoint, McpServer, Skill, Tool
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
                 kind="runtime" if eng else "a2a", url=url, skills=skills, engine=eng,
                 description=a.get("description", ""), location=a.get("location"))


def parse_tool(t: dict) -> Tool:
    ann = dict(t.get("annotations") or {})
    return Tool(name=t.get("name", ""), description=t.get("description", ""),
                read_only=bool(ann.get("readOnlyHint")), destructive=bool(ann.get("destructiveHint")),
                annotations=ann)


def parse_mcp(m: dict) -> McpServer:
    return McpServer(name=m.get("name", ""), id=rid(m.get("name", "")),
                     display_name=m.get("displayName") or rid(m.get("name", "")), url=first_url(m.get("interfaces")),
                     tools=[parse_tool(t) for t in m.get("tools", []) or []], description=m.get("description", ""))


def parse_endpoint(e: dict) -> Endpoint:
    return Endpoint(name=e.get("name", ""), id=rid(e.get("name", "")),
                    display_name=e.get("displayName") or rid(e.get("name", "")), url=first_url(e.get("interfaces")),
                    description=e.get("description", ""))


def list_kind(r: Rest, project: str, region: str, kind: str) -> list[dict]:
    return r.list_all(f"{AGENTREGISTRY}/projects/{project}/locations/{region}/{kind}", kind,
                      params={"pageSize": 100})


def get_iam_policy(r: Rest, resource: str) -> dict:
    return r.post(f"{IAP}/{resource}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}) or {}


def fetch(r: Rest, project: str, project_number: str, region: str, workers: int = 12) -> dict[str, Any]:
    """Registry entries + the IAP IAM policy of each (and of the whole registry). Errors are per item."""
    out: dict[str, Any] = {"agents": [], "mcp_servers": [], "endpoints": [], "policies": {}, "policy_errors": {},
                           "errors": []}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        lists = {k: pool.submit(list_kind, r, project, region, k) for k in KINDS}
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
