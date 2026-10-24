"""Discovery views behind the GET endpoints, with a 30 s cache per context (read-only)."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import audit as audit_mod, dryrun
from .english import make_binding
from .gcp import discovery, engines as eng_mod, gateways as gw_mod, logs as logs_mod, model_armor as ma_mod, \
    networking as net_mod, paths as paths_mod, registry as reg_mod
from .gcp.rest import NETWORKSERVICES, Rest, client, err_text
from .model import Context, Engine, Gateway, Inventory, Template

TTL = 30.0


class Cache:
    def __init__(self, ttl: float = TTL):
        self.ttl = ttl
        self._data: dict[Any, tuple[float, Any]] = {}
        self._locks: dict[Any, threading.Lock] = {}
        self._lock = threading.Lock()

    def get(self, key: Any, fn: Callable[[], Any], refresh: bool = False) -> Any:
        with self._lock:
            lk = self._locks.setdefault(key, threading.Lock())
        with lk:                      # one fetch per key at a time; concurrent callers share it
            hit = self._data.get(key)
            if hit and not refresh and time.time() - hit[0] < self.ttl:
                return hit[1]
            val = fn()
            self._data[key] = (time.time(), val)
            return val

    def peek(self, key: Any) -> Any:
        hit = self._data.get(key)
        return hit[1] if hit and time.time() - hit[0] < self.ttl else None

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


cache = Cache()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rest_for(ctx: Context) -> Rest:
    return client(ctx.project or None)


def reset_credentials() -> None:
    """Forget the cached ADC clients and discovery results. gcp.rest.client() captures the credentials when it is
    built, so after a new `gcloud auth application-default login` discovery (and Apply's writer) would keep using the
    old account while /auth already reports the new one. Called on every credential re-check (auth refresh)."""
    client.cache_clear()
    cache.clear()


def resolve(ctx: Context, r: Rest | None = None) -> Context:
    """Fill project_number / gateway_project_number (errors leave them empty)."""
    r = r or rest_for(ctx)
    out = ctx.model_copy()
    for attr, proj in (("project_number", ctx.project), ("gateway_project_number", ctx.gw_project)):
        if not getattr(out, attr) and proj:
            try:
                setattr(out, attr, discovery.project_number(r, proj))
            except Exception:  # noqa: BLE001
                pass
    return out


# ------------------------------------------------------------------ context
def context_view(ctx: Context, refresh: bool = False) -> dict[str, Any]:
    def build() -> dict[str, Any]:
        r = rest_for(ctx)
        errors: list[str] = []
        c = resolve(ctx, r)
        if not c.project_number:
            try:
                discovery.project_number(r, ctx.project)
            except Exception as e:  # noqa: BLE001
                errors.append(f"project number: {err_text(e)}")
        principal = r.principal()
        try:
            apis = discovery.enabled_apis(r, ctx.project)
        except Exception as e:  # noqa: BLE001
            apis = {}
            errors.append(f"API check: {err_text(e)}")
        perms = discovery.permissions_report(r, ctx.project, principal, ctx.gw_project)
        engines, _ = region_engines(ctx)
        principal_set = _project_agents_principal(r, ctx, engines, c.project_number)
        return {"project": ctx.project, "project_number": c.project_number, "region": ctx.region,
                "principal_set": principal_set,
                "gateway_project": ctx.gw_project, "gateway_project_number": c.gateway_project_number,
                "ge_app": ctx.ge_app, "ge_location": ctx.ge_location, "principal": principal, "apis": apis,
                "permissions": perms, "can_apply": False, "errors": errors}
    return cache.get((ctx.key(), "context"), build, refresh)


# ------------------------------------------------------------------ engines / gateways
def region_engines(ctx: Context, refresh: bool = False) -> tuple[list[Engine], list[str]]:
    def build() -> tuple[list[Engine], list[str]]:
        r = rest_for(ctx)
        try:
            engines = eng_mod.list_engines(r, ctx.project, ctx.region)
        except Exception as e:  # noqa: BLE001
            return [], [f"list Agent Runtime engines: {err_text(e)}"]
        psc = [e for e in engines if e.psc_interface and e.psc_interface.network_attachment and not e.psc_interface.vpc]
        atts = attachments(ctx, [e.psc_interface.network_attachment for e in psc], refresh)
        for e in psc:
            vpc = net_mod.vpc_of_attachment(atts.get(net_mod.resource_path(e.psc_interface.network_attachment)))
            if vpc:
                e.psc_interface.vpc = vpc
        return engines, []
    return cache.get((ctx.key(), "engines"), build, refresh)


def attachments(ctx: Context, names: list[str], refresh: bool = False) -> dict[str, dict]:
    """{attachment path: network attachment} for the ones that could be read (optional: only for the VPC name, so a
    403 or 404 just leaves it out)."""
    def one(path: str) -> dict | None:
        def build() -> dict | None:
            try:
                return rest_for(ctx).get(net_mod.attachment_url(path)) or None
            except Exception:  # noqa: BLE001
                return None
        return cache.get((ctx.key(), "attachment", path), build, refresh)
    paths = list(dict.fromkeys(net_mod.resource_path(n) for n in names if n))
    if not paths:
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(paths))) as pool:
        got = dict(zip(paths, pool.map(one, paths)))
    return {k: v for k, v in got.items() if v}


def private_egress(ctx: Context, raw: dict[str, Any], refresh: bool = False) -> dict[str, dict | None]:
    """{gateway name: Gateway.private_egress}: each gateway's connectivity template (read by project id when the
    gateway's number form matches a known project) or inline networkConfig, plus its attachment for the VPC name.
    An unreadable template degrades to `error`, never a failed request."""
    def build() -> dict[str, dict | None]:
        r = rest_for(ctx)
        c = resolve(ctx, r)
        numbers = {n: p for n, p in ((c.project_number, ctx.project), (c.gateway_project_number, ctx.gw_project)) if n}
        refs = {g["name"]: net_mod.resolve_project(net_mod.template_ref(g), numbers)
                for g in raw["gateways"] if net_mod.template_ref(g)}
        templates: dict[str, dict] = {}
        errors: dict[str, str] = {}

        def read(name: str) -> None:
            try:
                t = r.get(net_mod.template_url(name, NETWORKSERVICES))
                if t:
                    templates[name] = t
                else:
                    errors[name] = "empty response"
            except Exception as e:  # noqa: BLE001
                errors[name] = err_text(e)
        names = list(dict.fromkeys(refs.values()))
        if names:
            with ThreadPoolExecutor(max_workers=min(8, len(names))) as pool:
                list(pool.map(read, names))
        atts = attachments(ctx, [net_mod.attachment_of(g, templates.get(refs.get(g["name"], "")))
                                 for g in raw["gateways"]], refresh)
        out: dict[str, dict | None] = {}
        for g in raw["gateways"]:
            ref = refs.get(g["name"], "")
            att = net_mod.resource_path(net_mod.attachment_of(g, templates.get(ref)))
            out[g["name"]] = net_mod.gateway_private_egress(g, templates.get(ref), errors.get(ref), atts.get(att),
                                                            numbers)
        return out
    return cache.get((ctx.key(), "private_egress"), build, refresh)


def gateway_raw(ctx: Context, refresh: bool = False) -> dict[str, Any]:
    return cache.get((ctx.key(), "gateway_raw"),
                     lambda: gw_mod.list_region(rest_for(ctx), [ctx.project, ctx.gw_project], ctx.region), refresh)


def gateways_view(ctx: Context, refresh: bool = False) -> dict[str, Any]:
    def build() -> dict[str, Any]:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fe = pool.submit(region_engines, ctx, refresh)
            fr = pool.submit(gateway_raw, ctx, refresh)
            engines, eerr = fe.result()
            raw = fr.result()
        gws = gw_mod.build(raw, engines, private_egress(ctx, raw, refresh))
        notes = list(gw_mod.NOTES)
        if not gws:
            notes.insert(0, f"No Agent Gateway in {ctx.region} for project {ctx.project}"
                            + (f" or {ctx.gw_project}" if ctx.gw_project != ctx.project else "") + ".")
        return {"gateways": gws, "notes": notes, "errors": [*raw["errors"], *eerr], "synced_at": now_iso()}
    return cache.get((ctx.key(), "gateways"), build, refresh)


# ------------------------------------------------------------------ Model Armor
def model_armor_view(ctx: Context, refresh: bool = False) -> dict[str, Any]:
    def build() -> dict[str, Any]:
        r = rest_for(ctx)
        gv = gateways_view(ctx, refresh)
        raw = gateway_raw(ctx)
        ext_by_name = {eng_mod.tail(x["name"]): x for x in raw["extensions"]}
        errors: list[str] = []
        templates: dict[str, Template] = {}
        tmpl_err: dict[str, str] = {}

        def load(name: str) -> None:
            if name in templates or name in tmpl_err:
                return
            try:
                t = ma_mod.get_template(r, name, ctx.region)
                if t is None:
                    tmpl_err[name] = "template not found"
                else:
                    templates[name] = ma_mod.parse_template(t)
            except Exception as e:  # noqa: BLE001
                tmpl_err[name] = err_text(e)

        for proj in dict.fromkeys([ctx.project, ctx.gw_project]):
            try:
                for t in ma_mod.list_templates(r, proj, ctx.region):
                    templates.setdefault(t["name"], ma_mod.parse_template(t))
            except Exception as e:  # noqa: BLE001
                errors.append(f"list Model Armor templates in {proj}: {err_text(e)}")
        rows: list[dict[str, Any]] = []
        for g in gv["gateways"]:
            ma = next((p for p in g.authz_policies if p.profile == "CONTENT_AUTHZ"), None)
            row: dict[str, Any] = {"gateway": g.name, "type": g.type, "enabled": bool(ma), "policy": ma.name if ma
                                   else None, "extension": ma.extension if ma else None, "template": None}
            if ma:
                ext = ext_by_name.get(eng_mod.tail(ma.extension))
                ids = ma_mod.template_ids(ext)
                if ids:
                    load(ids[0])
                    row["template"] = templates.get(ids[0])
                    if ids[0] in tmpl_err:
                        row["error"] = f"template {ids[0]}: {tmpl_err[ids[0]]}"
                elif ext is None:
                    row["error"] = "Model Armor extension not found in this region"
            else:
                exts = gw_mod.model_armor_extensions(raw, g.project)
                row["available_extensions"] = [x["name"] for x in exts]
            rows.append(row)
        extensions = [{"name": x["name"], "templates": ma_mod.template_ids(x)}
                      for x in gw_mod.model_armor_extensions(raw)]
        agents = _service_agents(r, raw, errors)
        setup = ma_mod.setup_status(region=ctx.region, templates=list(templates.values()), extensions=extensions,
                                    agents=agents, gateway_ids=[g.id for g in gv["gateways"]])
        return {"gateways": rows, "templates": list(templates.values()), "extensions": extensions, "setup": setup,
                "notes": ["Egress screening by Model Armor covers MCP traffic, not A2A (verified)."],
                "errors": errors + [f"template {k}: {v}" for k, v in tmpl_err.items()]}
    return cache.get((ctx.key(), "model_armor"), build, refresh)


def _service_agents(r: Rest, raw: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    """Gateway service agents with {role: held} for the Model Armor roles (project getIamPolicy, read-only)."""
    projects = list(dict.fromkeys(g["_project"] for g in raw["gateways"]))
    numbers: dict[str, str] = {}
    for p in projects:
        try:
            numbers[p] = discovery.project_number(r, p)
        except Exception as e:  # noqa: BLE001
            errors.append(f"project number of {p}: {err_text(e)}")
    agents = ma_mod.service_agents(raw["gateways"], numbers)
    policies: dict[str, dict | None] = {}
    for p in dict.fromkeys(a["project"] for a in agents):
        try:
            policies[p] = discovery.project_iam_policy(r, p)
        except Exception as e:  # noqa: BLE001
            policies[p] = None
            errors.append(f"read the IAM policy of {p} (service agent roles): {err_text(e)}")
    for a in agents:
        pol = policies.get(a["project"])
        if pol is None:
            a["roles"] = {role: None for role in ma_mod.MA_ROLES}
            a["error"] = "couldn't read the project IAM policy"
        else:
            a["roles"] = ma_mod.roles_of(pol, a["member"])
    return agents


# ------------------------------------------------------------------ inventory
def _project_agents_principal(r: Rest, ctx: Context, engines: list[Engine], number: str) -> str | None:
    org = next((o for o in (eng_mod.org_from_principal(e.principal) for e in engines) if o), None)
    if not org:
        try:
            org = discovery.organization_id(r, ctx.project)
        except Exception:  # noqa: BLE001
            org = None
    return eng_mod.project_agents_principal(org, number) if org and number else None


def registry_state(inv: Inventory) -> dict[str, Any]:
    """What registry_service preflight, render and diff need from the inventory: the Services, the bindings on each
    Service's entry, and every registered URL (normalized) with the entry that has it."""
    entries = [x for coll in (inv.agents, inv.mcp_servers, inv.endpoints) for x in coll]
    grants: dict[str, int] = {}
    urls: dict[str, str] = {}
    for x in entries:
        if x.service:
            grants[x.service] = len(inv.access.get(x.name, []))
        for u in x.urls or ([x.url] if x.url else []):
            urls.setdefault(reg_mod.norm_url(u), f"{x.display_name} ({x.id})")
    for svc in inv.services:
        for i in svc.interfaces:
            urls[reg_mod.norm_url(i.url)] = f"{svc.display_name} ({svc.id})"
    listed = not any(e.startswith("list services") for e in inv.errors)
    return {"services": list(inv.services) if listed else None, "grants": grants, "urls": urls}


def inventory_view(ctx: Context, refresh: bool = False) -> Inventory:
    def build() -> Inventory:
        r = rest_for(ctx)
        c = resolve(ctx, r)
        engines, eerr = region_engines(ctx, refresh)
        errors = list(eerr)
        gn = c.gateway_project_number
        if not gn:
            errors.append(f"could not resolve the project number of {ctx.gw_project}; IAP policies not read")
        reg = reg_mod.fetch(r, ctx.gw_project, gn or ctx.gw_project, ctx.region)
        errors += reg["errors"]
        names = {e.principal: e.display_name for e in engines if e.principal}
        by_id = {e.id: e.name for e in engines}
        for a in reg["agents"]:                 # one engine name format everywhere: projects/<NUMBER>/...
            if a.engine:
                eid = a.engine.rsplit("/", 1)[-1]
                a.engine = by_id.get(eid) or (f"projects/{c.project_number}/locations/{ctx.region}/reasoningEngines/"
                                              f"{eid}" if c.project_number else a.engine)
        labels: dict[str, tuple[str, str]] = {}
        for kind, items in (("agent", reg["agents"]), ("mcp_server", reg["mcp_servers"]),
                            ("endpoint", reg["endpoints"])):
            for it in items:
                labels[it.name] = (it.display_name, kind)
        labels[f"projects/{ctx.gw_project}/locations/{ctx.region}"] = ("Agent Registry (all entries)", "registry")
        access: dict[str, list] = {}
        for key, pol in reg["policies"].items():
            lbl, kind = labels.get(key, (key, "registry"))
            access[key] = [make_binding(b.get("role", ""), m, b.get("condition"), lbl, kind, names)
                           for b in pol.get("bindings", []) or [] for m in b.get("members", []) or []]
        for coll in (reg["agents"], reg["mcp_servers"], reg["endpoints"]):
            for it in coll:
                if it.name in reg["policy_errors"]:
                    it.error = f"IAP policy: {reg['policy_errors'][it.name]}"
        return Inventory(engines=engines, agents=reg["agents"], mcp_servers=reg["mcp_servers"],
                         endpoints=reg["endpoints"], access=access, access_errors=reg["policy_errors"],
                         services=reg["services"],
                         project_agents_principal=_project_agents_principal(r, ctx, engines, c.project_number),
                         errors=errors, synced_at=now_iso())
    return cache.get((ctx.key(), "inventory"), build, refresh)


# ------------------------------------------------------------------ audit
def audit_view(ctx: Context, refresh: bool = False) -> dict[str, Any]:
    def build() -> dict[str, Any]:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fi = pool.submit(inventory_view, ctx, refresh)
            fg = pool.submit(gateways_view, ctx, refresh)
            inv: Inventory = fi.result()
            gws: list[Gateway] = fg.result()["gateways"]
        res = audit_mod.audit(inv, gws, ctx)
        res["synced_at"] = now_iso()
        return res
    return cache.get((ctx.key(), "audit"), build, refresh)


# ------------------------------------------------------------------ gateway request logs
def _callers(r: Rest, ctx: Context, projects: list[str], gid: str, since_ts: str,
             bound: list[Engine]) -> dict[str, Any]:
    """{client cert fingerprint: Engine} for the bound engines (only needed when there is more than one)."""
    if len(bound) < 2:
        return {}
    try:
        csince = (datetime.fromisoformat(since_ts.replace("Z", "+00:00")) - timedelta(hours=2)) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        fps = logs_mod.fetch_callers(r, projects, gid, csince, [e.id for e in bound])
    except Exception:  # noqa: BLE001  (attribution is best effort; the entries still load)
        return {}
    by_id = {e.id: e for e in bound}
    return {fp: by_id[eid] for fp, eid in fps.items() if eid in by_id}


def gateway_logs_view(ctx: Context, gateway: str, since: str = "24h", limit: int = 200,
                      refresh: bool = False) -> dict[str, Any]:
    """GET /gateway-logs: recent request log entries of one gateway. Logged decisions are allowed / denied; on an
    egress gateway in dry run, allowed entries are checked against the caller's current grants (dryrun.py) and
    become would_deny / allowed / unknown with a reason (platform for the agent runtime's own unregistered calls; a
    second, platform-free query covers the window when the newest `limit` entries don't). `gateway` is an id or a
    full name (its project is then where the logs are read)."""
    gid = gateway.rstrip("/").split("/")[-1]
    projects = [gateway.split("/")[1]] if gateway.startswith("projects/") else \
        list(dict.fromkeys([ctx.gw_project, ctx.project]))

    def build() -> dict[str, Any]:
        r = rest_for(ctx)
        errors: list[str] = []
        inv: Inventory | None = None
        try:
            inv = inventory_view(ctx)
        except Exception as e:  # noqa: BLE001
            errors.append(f"read the inventory (grants): {err_text(e)}")
        labels: dict[str, str] = {}
        for coll in ((inv.agents, inv.mcp_servers, inv.endpoints) if inv else ()):
            for x in coll:
                labels[eng_mod.tail(x.name)] = x.display_name
        g = None
        engines: list[Engine] = []
        try:
            g = next((x for x in gateways_view(ctx)["gateways"] if x.id == gid), None)
            engines = region_engines(ctx)[0]
        except Exception as e:  # noqa: BLE001
            errors.append(f"read the gateway: {err_text(e)}")
        by_name = {e.name: e for e in engines}
        bound = [by_name[b.engine] for b in (g.bound_engines if g else []) if b.direction == g.type
                 and b.engine in by_name]
        dry = bool(g and g.type == "egress" and g.enforcement and g.enforcement.mode == "DRY_RUN")
        out = logs_mod.fetch(r, projects, gid, since, limit, labels, checked=dry)
        extra = out.pop("checked_extra", 0)
        fps = _callers(r, ctx, projects, gid, out["since"], bound)
        for e in out["entries"]:
            eng, how = fps.get(e.get("client_cert") or ""), "mtls"
            if eng is None and len(bound) == 1:
                eng, how = bound[0], "only_bound_agent"
            caller = dryrun.Caller(engine=eng.name, display_name=eng.display_name, principal=eng.principal,
                                   how=how) if eng else None
            e["agent"] = caller.display_name if caller else None
            e["agent_inferred"] = caller is not None
            e["caller"] = {"engine": caller.engine, "display_name": caller.display_name, "how": caller.how} \
                if caller else None
            e["computed"] = dry and e["decision"] == "allowed"
            e["reason"] = None
            if e["computed"]:
                e["decision"], e["reason"] = dryrun.check(e, caller, inv)
        out["counts"] = logs_mod.count(out["entries"])
        notes = ["Agent Gateway request logs don't name the caller. The agent is matched by its mTLS client "
                 "certificate (seen on its own Agent Runtime calls through the gateway), or is the only agent bound "
                 "to the gateway; either way it's inferred."]
        if dry:
            notes.append("In dry run Google logs every call as allowed (status 200, IAP result ALLOWED), including "
                         "the ones IAP would deny. Would-be-denied is computed by Policy Studio from the caller's "
                         "current roles/iap.egressor grants on the destination, not reported by Google. Grants on "
                         "the project or above aren't counted; a condition it can't evaluate gives unknown.")
        n_platform = sum(1 for e in out["entries"] if e["platform"])
        if n_platform:
            notes.append(f"{n_platform} of the entries are platform traffic (the agent runtime's own calls: "
                         "aiplatform*.googleapis.com, IP-literal hosts such as 240.0.0.2, *.google.internal). "
                         "Unregistered ones are marked platform and not checked; registered ones (an aiplatform "
                         "endpoint in Agent Registry) are checked like any destination.")
        if out["truncated"]:
            n = len(out["entries"]) - extra
            if not dry:
                notes.append(f"Only the newest {n} entries of the window are shown; older entries were left out.")
            elif out["checked_truncated"]:
                notes.append(f"The newest {n} entries of the window, plus {extra} older non-platform entries from a "
                             f"second query capped at {logs_mod.CHECK_CAP}: older entries (platform or not) were left "
                             "out, so older would-be-denied calls may be missing.")
            else:
                notes.append(f"The newest {n} entries of the window, plus {extra} older non-platform entries from a "
                             "second query that leaves out platform hosts: every non-platform entry of the window "
                             "was checked; only older platform calls (aiplatform*.googleapis.com, IPv4 hosts) "
                             "were left out.")
        out.update(notes=notes, errors=errors, synced_at=now_iso(), projects=projects, dry_run=dry)
        return out
    return cache.get((ctx.key(), "gateway_logs", gid, since, int(limit)), build, refresh)


# ------------------------------------------------------------------ destination paths (seen in traffic)
def destination_paths_view(ctx: Context, window: str = paths_mod.DEFAULT_WINDOW,
                           refresh: bool = False) -> dict[str, Any]:
    """GET /destination-paths: per registry entry, calls through the context's egress gateways that reached a private
    upstream address (httpRequest.serverIp) versus a public one, over the window (gcp/paths.py). Each gateway is read
    on its own: one it can't read (no logging.logEntries.list) gets `error`, never a failed request."""
    span = paths_mod.parse_window(window)

    def build() -> dict[str, Any]:
        r = rest_for(ctx)
        errors: list[str] = []
        gws: list[Gateway] = []
        try:
            gws = [g for g in gateways_view(ctx)["gateways"] if g.type == "egress"]
        except Exception as e:  # noqa: BLE001
            errors.append(f"read the gateways: {err_text(e)}")
        names: dict[str, str] = {}
        try:
            inv = inventory_view(ctx)
            for coll in (inv.agents, inv.mcp_servers, inv.endpoints):
                for x in coll:
                    names[eng_mod.tail(x.name)] = x.name
        except Exception as e:  # noqa: BLE001  (keys stay the logged registry resources)
            errors.append(f"read the inventory (entry names): {err_text(e)}")

        def one(g: Gateway) -> dict[str, Any]:
            row: dict[str, Any] = {"gateway": g.name, "id": g.id, "private_egress": g.private_egress is not None,
                                   "scanned": 0, "truncated": False}
            try:
                got = paths_mod.fetch(r, [g.project or ctx.gw_project], g.id, span)
            except Exception as e:  # noqa: BLE001  (403 without logging.logEntries.list, ...)
                row["error"] = f"can't read the request logs: {err_text(e)}"
                return {"row": row, "destinations": {}}
            row.update(scanned=got["scanned"], truncated=got["truncated"], console_url=got["console_url"])
            return {"row": row, "destinations": got["destinations"], "since": got["since"]}
        results: list[dict[str, Any]] = []
        if gws:
            with ThreadPoolExecutor(max_workers=min(8, len(gws))) as pool:
                results = list(pool.map(one, gws))
        merged = paths_mod.merge([x["destinations"] for x in results])
        rows = [x["row"] for x in results]
        since = next((x["since"] for x in results if x.get("since")),
                     (datetime.now(timezone.utc) - span).strftime("%Y-%m-%dT%H:%M:%SZ"))
        notes = ["From the gateway request logs: httpRequest.serverIp is the address the gateway connected to. Private "
                 "(10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) means the call went through the gateway's private "
                 "egress. Only calls that were made count: denied ones have no serverIp."]
        if any(m["path"] == "mixed" for m in merged.values()):
            notes.append("Mixed paths: a destination reached at both private and public addresses. It usually has "
                         "several hostnames (only some resolve into the VPC) or its DNS changed inside the window.")
        failed = [x for x in rows if x.get("error")]
        if failed:
            errors += [f"{x['id']}: {x['error']}" for x in failed]
            notes.append("Some gateways' request logs couldn't be read, so their destinations have no label. Reading "
                         "them needs logging.logEntries.list (roles/logging.viewer) on the gateway's project.")
        truncated = any(x["truncated"] for x in rows)
        if truncated:
            notes.append(f"Only the newest {paths_mod.CAP} calls per gateway were counted; older ones in the window "
                         "were left out.")
        return {"window": paths_mod.window_text(span), "since": since, "gateways": rows,
                "destinations": {names.get(k, k): v for k, v in merged.items()}, "truncated": truncated,
                "notes": notes, "errors": errors, "synced_at": now_iso()}
    return cache.get((ctx.key(), "destination_paths", paths_mod.window_text(span)), build, refresh)


# ------------------------------------------------------------------ credentials (P3)
def auth_view(project: str, gateway_project: str = "", refresh: bool = False) -> dict[str, Any]:
    """GET /api/studio/auth: run mode, ADC, gcloud and write-permission checks for the target project."""
    from . import settings
    from .gcp import auth as auth_mod

    ctx = Context(project=project, gateway_project=gateway_project)
    if refresh:                    # "Re-check" after a re-login, and /apply: never keep a client on old credentials
        reset_credentials()

    def build() -> dict[str, Any]:
        return auth_mod.report(project, mode=settings.current_mode(), runtime=settings.runtime(),
                               generate_reason=settings.generate_reason(), gateway_project=gateway_project,
                               rest_factory=lambda: rest_for(ctx))
    return cache.get(("auth", project, gateway_project or project, settings.current_mode()), build, refresh)
