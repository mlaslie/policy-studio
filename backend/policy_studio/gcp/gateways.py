"""Agent Gateways, authz extensions and authz policies in a region (read-only).

  agentGateways    GET https://networkservices.googleapis.com/v1/projects/P/locations/R/agentGateways
  authzExtensions  GET https://networkservices.googleapis.com/v1/projects/P/locations/R/authzExtensions
  authzPolicies    GET https://networksecurity.googleapis.com/v1/projects/P/locations/R/authzPolicies
Policies reference gateways and extensions by project number; listings use the project id, so resources are
matched on their `locations/...` tail.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..model import AuthzPolicyRef, BoundEngine, Engine, Gateway, GatewayEnforcement
from .engines import tail
from .rest import NETWORKSECURITY, NETWORKSERVICES, Rest, err_text

PATHS = {"AGENT_TO_ANYWHERE": "egress", "CLIENT_TO_AGENT": "ingress"}

NOTES = [
    "One egress (AGENT_TO_ANYWHERE) and one ingress (CLIENT_TO_AGENT) gateway per project and region can serve "
    "Agent Runtime agents.",
    "Agent Runtime agents created before 2026-04-29 can't be bound to a gateway; redeploy them first.",
    "Egress is default deny: an agent behind an egress gateway reaches only Agent Registry entries it holds "
    "roles/iap.egressor on.",
]


def _loc(project: str, region: str) -> str:
    return f"projects/{project}/locations/{region}"


def provider_of(ext: dict | None) -> str:
    svc = (ext or {}).get("service", "") or ""
    if svc == "iap.googleapis.com":
        return "iap"
    if svc.startswith("modelarmor."):
        return "model_armor"
    return "other"


def enforcement_of(ext: dict | None) -> str | None:
    if provider_of(ext) != "iap":
        return None
    md = (ext or {}).get("metadata") or {}
    return "DRY_RUN" if str(md.get("iamEnforcementMode", "")).upper() == "DRY_RUN" else "ENFORCE"


def policy_extension(p: dict) -> str:
    exts = ((p.get("customProvider") or {}).get("authzExtension") or {}).get("resources", []) or []
    return exts[0] if exts else ""


def policy_targets(p: dict) -> list[str]:
    return list((p.get("target") or {}).get("resources", []) or [])


def iap_index(raw: dict[str, Any]) -> dict[str, Any]:
    """IAP REQUEST_AUTHZ policies and extensions of the region, indexed by `tail` (project id vs number safe):
    {"extensions": {ext tail: raw}, "by_gateway": {gateway tail: [policy]}, "by_extension": {ext tail: [gateway tail]},
     "all_extensions": [ext tail of every authz extension]}. A REQUEST_AUTHZ policy whose extension isn't listed (e.g.
    unreadable) counts too: its mode is then unknown."""
    exts = {tail(x["name"]): x for x in raw["extensions"] if provider_of(x) == "iap"}
    known = {tail(x["name"]) for x in raw["extensions"]}
    by_gw: dict[str, list[dict]] = {}
    by_ext: dict[str, list[str]] = {}
    for p in raw["policies"]:
        if (p.get("policyProfile") or "REQUEST_AUTHZ") != "REQUEST_AUTHZ":
            continue
        ext = tail(policy_extension(p))
        if ext in known and ext not in exts:
            continue                       # another provider's REQUEST_AUTHZ extension
        if not ext and not (p.get("customProvider") or {}).get("cloudIap"):
            continue
        for t in policy_targets(p):
            by_gw.setdefault(tail(t), []).append(p)
            if ext in exts:
                by_ext.setdefault(ext, [])
                if tail(t) not in by_ext[ext]:
                    by_ext[ext].append(tail(t))
    return {"extensions": exts, "by_gateway": by_gw, "by_extension": by_ext, "all_extensions": sorted(known)}


def enforcement_for(gtail: str, idx: dict[str, Any], names: dict[str, str]) -> GatewayEnforcement:
    """The gateway's enforcement mode from its IAP REQUEST_AUTHZ policy -> extension. `names`: {gateway tail: name}."""
    pols = idx["by_gateway"].get(gtail) or []
    if not pols:
        return GatewayEnforcement(editable=False, reason="No IAP REQUEST_AUTHZ policy on this gateway, so nothing is "
                                                         "checked against roles/iap.egressor grants.")
    p = pols[0]
    ext_name = policy_extension(p)
    ext = idx["extensions"].get(tail(ext_name))
    if ext is None:
        return GatewayEnforcement(policy=p.get("name", ""), extension=ext_name, editable=False,
                                  reason="The IAP policy doesn't use an IAP authz extension that Policy Studio can "
                                         "read, so its mode can't be changed here.")
    shared = [names.get(g, g) for g in idx["by_extension"].get(tail(ext_name), []) if g != gtail]
    out = GatewayEnforcement(mode=enforcement_of(ext), extension=ext.get("name", ext_name), policy=p.get("name", ""),
                             failOpen=bool(ext.get("failOpen")), shared_with=shared, editable=True)
    if len(pols) > 1:
        out.reason = f"{len(pols)} IAP REQUEST_AUTHZ policies target this gateway; the first one is shown."
    return out


def list_region(r: Rest, projects: list[str], region: str) -> dict[str, Any]:
    """Raw gateways / extensions / policies of every project (tagged `_project`), plus per-call errors."""
    calls: dict[tuple[str, str], tuple[str, str]] = {}
    for p in dict.fromkeys(projects):
        calls[(p, "gateways")] = (f"{NETWORKSERVICES}/{_loc(p, region)}/agentGateways", "agentGateways")
        calls[(p, "extensions")] = (f"{NETWORKSERVICES}/{_loc(p, region)}/authzExtensions", "authzExtensions")
        calls[(p, "policies")] = (f"{NETWORKSECURITY}/{_loc(p, region)}/authzPolicies", "authzPolicies")
    out: dict[str, Any] = {"gateways": [], "extensions": [], "policies": [], "errors": []}
    with ThreadPoolExecutor(max_workers=len(calls) or 1) as pool:
        futs = {k: pool.submit(r.list_all, url, key) for k, (url, key) in calls.items()}
        for (p, kind), f in futs.items():
            try:
                out[kind] += [{**item, "_project": p} for item in f.result()]
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"list {kind} in {p}/{region}: {err_text(e)}")
    return out


def build(raw: dict[str, Any], engines: list[Engine], private: dict[str, dict | None] | None = None) -> list[Gateway]:
    """`private`: {gateway name: networking.gateway_private_egress(...)} (absent = public egress only)."""
    ext_by_tail = {(x["_project"], tail(x["name"])): x for x in raw["extensions"]}
    ext_by_tail_any = {tail(x["name"]): x for x in raw["extensions"]}
    idx = iap_index(raw)
    names = {tail(g.get("name", "")): g.get("name", "") for g in raw["gateways"]}
    gws: list[Gateway] = []
    for g in raw["gateways"]:
        name = g.get("name", "")
        gtail = tail(name)
        path = (g.get("googleManaged") or {}).get("governedAccessPath", "")
        pols: list[AuthzPolicyRef] = []
        for p in raw["policies"]:
            if not any(tail(t) == gtail for t in (p.get("target") or {}).get("resources", []) or []):
                continue
            exts = ((p.get("customProvider") or {}).get("authzExtension") or {}).get("resources", []) or []
            ext_name = exts[0] if exts else ""
            ext = ext_by_tail.get((p["_project"], tail(ext_name))) or ext_by_tail_any.get(tail(ext_name))
            provider = provider_of(ext) if ext else ("iap" if (p.get("customProvider") or {}).get("cloudIap")
                                                     else "other")
            pols.append(AuthzPolicyRef(name=p.get("name", ""), profile=p.get("policyProfile", ""), provider=provider,
                                       extension=(ext or {}).get("name", ext_name),
                                       enforcement=enforcement_of(ext)))
        bound = [BoundEngine(engine=e.name, display_name=e.display_name, direction=d)
                 for e in engines for d, gw in e.gateways.items() if tail(gw) == gtail]
        gws.append(Gateway(name=name, id=name.rsplit("/", 1)[-1], project=g["_project"],
                           type=PATHS.get(path, "egress"), governed_access_path=path,
                           registries=list(g.get("registries") or []), authz_policies=pols,
                           bound_engines=bound, create_time=g.get("createTime", ""),
                           enforcement=enforcement_for(gtail, idx, names),
                           private_egress=(private or {}).get(name)))
    gws.sort(key=lambda x: (x.type, x.name))
    return gws


def model_armor_extensions(raw: dict[str, Any], project: str | None = None) -> list[dict]:
    return [x for x in raw["extensions"] if provider_of(x) == "model_armor"
            and (project is None or x["_project"] == project)]
