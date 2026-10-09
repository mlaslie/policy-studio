"""Policy Studio API router, mounted at /api/studio (another app can `include_router(router)`)."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from . import __version__, service, settings
from .apply import Applier, check_confirm
from . import preflight as pf
from .diff import diff as diff_intents
from .gcp import gateways as gw_mod
from .gcp.discovery import defaults as discovery_defaults
from .gcp.engines import tail
from .gcp.rest import err_text
from .model import (SETUP_KINDS, ApplyRequest, Context, DiffItem, Intent, IntentsRequest, Inventory, RenderItem,
                    RenderResult)
from .render import RenderEnv, gateway_full, render as render_intents, with_staged

router = APIRouter(prefix="/api/studio", tags=["policy-studio"])


def make_context(project: str = "", region: str = "", gateway_project: str = "", ge_app: str = "",
                 ge_location: str = "us") -> Context:
    if not project or not region:
        d = discovery_defaults()
        project = project or d["project"]
        region = region or d["region"]
    if not project:
        raise HTTPException(400, "project is required (no STUDIO_PROJECT and no gcloud default project)")
    return Context(project=project.strip(), region=region.strip(), gateway_project=gateway_project.strip(),
                   ge_app=ge_app.strip(), ge_location=(ge_location or "us").strip())


def _ctx(project: str, region: str, gateway_project: str, ge_app: str, ge_location: str) -> Context:
    return make_context(project, region, gateway_project, ge_app, ge_location)


def _guard(fn, *args: Any) -> Any:
    try:
        return fn(*args)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001  (credentials missing, network down, ...)
        raise HTTPException(502, err_text(e)) from e


@router.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "version": __version__}


@router.get("/defaults")
def defaults() -> dict[str, str]:
    return discovery_defaults()


@router.get("/context")
def context(project: str = "", region: str = "", gateway_project: str = "", ge_app: str = "",
            ge_location: str = "us", refresh: int = 0) -> dict[str, Any]:
    ctx = _ctx(project, region, gateway_project, ge_app, ge_location)
    out = dict(_guard(service.context_view, ctx, bool(refresh)))
    out.update(ge_app=ctx.ge_app, ge_location=ctx.ge_location, **apply_state(ctx, bool(refresh)))
    return out


def apply_state(ctx: Context, refresh: bool = False) -> dict[str, Any]:
    """{mode, can_apply, can_apply_reason} for /context (never fails it)."""
    mode = settings.current_mode()
    if mode != "apply":
        return {"mode": mode, "can_apply": False, "can_apply_reason": settings.generate_reason()}
    try:
        a = service.auth_view(ctx.project, ctx.gateway_project, refresh)
        return {"mode": mode, "can_apply": a["can_apply"], "can_apply_reason": a["can_apply_reason"]}
    except Exception as e:  # noqa: BLE001
        return {"mode": mode, "can_apply": False, "can_apply_reason": f"credential check failed: {err_text(e)}"}


@router.get("/auth")
def auth(project: str = "", gateway_project: str = "", refresh: int = 0) -> dict[str, Any]:
    project = (project or discovery_defaults()["project"]).strip()
    if not project:
        raise HTTPException(400, "project is required (no STUDIO_PROJECT and no gcloud default project)")
    return _guard(service.auth_view, project, gateway_project.strip(), bool(refresh))


@router.get("/gateways")
def gateways(project: str = "", region: str = "", gateway_project: str = "", ge_app: str = "",
             ge_location: str = "us", refresh: int = 0) -> dict[str, Any]:
    ctx = _ctx(project, region, gateway_project, ge_app, ge_location)
    return _guard(service.gateways_view, ctx, bool(refresh))


@router.get("/model-armor")
def model_armor(project: str = "", region: str = "", gateway_project: str = "", ge_app: str = "",
                ge_location: str = "us", refresh: int = 0) -> dict[str, Any]:
    ctx = _ctx(project, region, gateway_project, ge_app, ge_location)
    return _guard(service.model_armor_view, ctx, bool(refresh))


@router.get("/inventory")
def inventory(project: str = "", region: str = "", gateway_project: str = "", ge_app: str = "",
              ge_location: str = "us", refresh: int = 0) -> Inventory:
    ctx = _ctx(project, region, gateway_project, ge_app, ge_location)
    return _guard(service.inventory_view, ctx, bool(refresh))


@router.get("/audit")
def audit(project: str = "", region: str = "", gateway_project: str = "", ge_app: str = "",
          ge_location: str = "us", refresh: int = 0) -> dict[str, Any]:
    ctx = _ctx(project, region, gateway_project, ge_app, ge_location)
    return _guard(service.audit_view, ctx, bool(refresh))


# ------------------------------------------------------------------ render / diff
def _request_context(c: Context) -> Context:
    return make_context(c.project, c.region, c.gateway_project, c.ge_app, c.ge_location).model_copy(
        update={"project_number": c.project_number, "gateway_project_number": c.gateway_project_number})


def build_env(ctx: Context, intents: list[Intent], notes: Optional[list[str]] = None) -> RenderEnv:
    """Resolve numbers and pull what discovery knows (best effort, cached). Never fails."""
    notes = notes if notes is not None else []
    try:
        ctx = service.resolve(ctx)
    except Exception as e:  # noqa: BLE001
        notes.append(f"project number lookup failed: {err_text(e)}")
    env = RenderEnv(ctx=ctx)
    kinds = {i.kind for i in intents}
    try:
        engines, _ = service.region_engines(ctx)
        env.engines = {e.name: dict(e.gateways) for e in engines}
        env.engine_info = {e.name: {"display_name": e.display_name, "bindable": e.bindable,
                                    "bindable_reason": e.bindable_reason} for e in engines}
    except Exception as e:  # noqa: BLE001
        notes.append(f"engine lookup failed: {err_text(e)}")
    inv: Optional[Inventory] = service.cache.peek((ctx.key(), "inventory"))
    if inv is not None:
        env.mcp_tools = {m.id: [{"name": t.name, "read_only": t.read_only} for t in m.tools] for m in inv.mcp_servers}
    # An extension staged in the same cart wins over discovery (render picks it up via with_staged).
    staged_ext = any(i.kind == "model_armor_extension" and not i.is_delete for i in intents)
    if kinds & {"model_armor_on", "model_armor_off"}:
        try:
            raw = service.gateway_raw(ctx)
            gws = gw_mod.build(raw, [])
            env.known_extensions = [x["name"] for x in gw_mod.model_armor_extensions(raw)]
            for it in intents:
                if it.kind not in ("model_armor_on", "model_armor_off") or not it.gateway:
                    continue
                full = gateway_full(env, it.gateway.name, it.gateway.direction)
                g = next((x for x in gws if tail(x.name) == tail(full)), None)
                proj = g.project if g else None
                if it.kind == "model_armor_on" and not it.gateway.extension and not staged_ext:
                    exts = gw_mod.model_armor_extensions(raw, proj) or gw_mod.model_armor_extensions(raw)
                    if exts:
                        it.gateway.extension = exts[0]["name"]
                if it.kind == "model_armor_off" and not it.gateway.policy and g:
                    ma = next((p for p in g.authz_policies if p.profile == "CONTENT_AUTHZ"), None)
                    if ma:
                        it.gateway.policy = ma.name.rsplit("/", 1)[-1]
        except Exception as e:  # noqa: BLE001
            notes.append(f"Model Armor lookup failed: {err_text(e)}")
    return with_staged(env, intents)


def parse_intents(raw: list[dict[str, Any]]) -> tuple[list[Intent], dict[int, tuple[str, str]]]:
    """Valid intents, plus {position: (intent id, error)} for the ones that don't validate."""
    good: list[Intent] = []
    bad: dict[int, tuple[str, str]] = {}
    for n, item in enumerate(raw):
        try:
            good.append(Intent.model_validate(item))
        except ValidationError as e:
            msg = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
            bad[n] = (str(item.get("id", f"#{n}")) if isinstance(item, dict) else f"#{n}", f"invalid intent: {msg}"[:400])
    return good, bad


def _merge(good: list[Any], bad: dict[int, Any], total: int) -> list[Any]:
    it = iter(good)
    return [bad[n] if n in bad else next(it) for n in range(total)]


@router.post("/render")
def render(req: IntentsRequest) -> RenderResult:
    ctx = _request_context(req.context)
    intents, bad = parse_intents(req.intents)
    notes: list[str] = []
    env = build_env(ctx, intents, notes)
    res = render_intents(intents, env)
    if notes:
        for it in res.items:
            it.warnings += [f"(lookup) {n}" for n in notes]
    res.items = _merge(res.items, {n: RenderItem(intent_id=i, error=e) for n, (i, e) in bad.items()},
                       len(req.intents))
    res.context = env.ctx.model_dump()          # echo the resolved context (project_number, ...)
    return res


@router.post("/diff")
def diff(req: IntentsRequest) -> dict[str, list[DiffItem]]:
    ctx = _request_context(req.context)
    intents, bad = parse_intents(req.intents)
    env = build_env(ctx, intents)
    inv = _guard(service.inventory_view, ctx, False)
    gws = _guard(service.gateways_view, ctx, False)["gateways"]
    ma: Optional[dict[str, Any]] = None
    if any(i.kind in SETUP_KINDS for i in intents):
        try:
            ma = service.model_armor_view(ctx)
        except Exception:  # noqa: BLE001  (diff says "unknown" instead)
            ma = None
    items = diff_intents(intents, inv, gws, env, ma)
    errs = {n: DiffItem(intent_id=i, status="absent", error=e, detail=e) for n, (i, e) in bad.items()}
    return {"items": _merge(items, errs, len(req.intents))}


# ------------------------------------------------------------------ apply (P3, apply mode only)
@router.post("/apply")
def apply(req: ApplyRequest) -> StreamingResponse:
    mode = settings.current_mode()
    if mode != "apply":                                   # no write client is ever constructed in generate mode
        raise HTTPException(403, settings.generate_reason())
    ctx = _request_context(req.context)
    a = _guard(service.auth_view, ctx.project, ctx.gateway_project, True)
    if not a["can_apply"]:
        raise HTTPException(403, a["can_apply_reason"] or "Apply is not available")
    problem = check_confirm(ctx, req.intents, req.confirm)
    if problem:
        raise HTTPException(400, problem)
    from .gcp.writer import Writer                       # imported and constructed only here, in apply mode

    intents, bad = parse_intents(req.intents)
    env = build_env(ctx, intents)
    rest = service.rest_for(ctx)
    applier = Applier(env, rest, Writer(rest), account=a["adc"].get("account", ""),
                      on_finish=service.cache.clear)       # discovery must not keep serving pre-apply state
    service.cache.clear()                                 # discovery must not serve pre-apply state
    return StreamingResponse(applier.stream(intents, bad, a.get("writable")), media_type="application/x-ndjson")


@router.post("/preflight")
def preflight(req: IntentsRequest) -> dict[str, Any]:
    """Read-only: which staged intents are duplicates or would certainly fail, and why (the same checks /apply
    enforces). {items: [{intent_id, status: ok|blocked|duplicate|invalid, reason?, fix?, duplicate_of?}]}"""
    ctx = _request_context(req.context)
    intents, bad = parse_intents(req.intents)
    env = build_env(ctx, intents)
    writable: Optional[dict[str, Any]] = None
    if settings.current_mode() == "apply":
        try:
            writable = service.auth_view(ctx.project, ctx.gateway_project).get("writable")
        except Exception:  # noqa: BLE001  (the Apply step shows credential problems separately)
            writable = None
    dups = pf.duplicates(intents)
    blocked = pf.blockers([i for i in intents if i.id not in dups], env, writable)
    items: list[dict[str, Any]] = []
    for it in intents:
        if it.id in dups:
            items.append({"intent_id": it.id, "status": "duplicate", "duplicate_of": dups[it.id],
                          "reason": f"Same change as {dups[it.id]}; applied once."})
        elif it.id in blocked:
            items.append({"intent_id": it.id, "status": "blocked", **blocked[it.id]})
        else:
            items.append({"intent_id": it.id, "status": "ok"})
    errs = [{"intent_id": i, "status": "invalid", "reason": e} for i, e in bad.values()]
    return {"items": _merge(items, dict(zip(bad.keys(), errs)), len(req.intents))}
