"""Compare staged intents with the current state: add / present / replace / remove / absent."""
from __future__ import annotations

from typing import Any, Optional

from .conditions import EGRESSOR, condition_for, same_condition
from .english import condition_english, make_binding
from .gcp.engines import tail
from .model import Binding, Condition, DiffItem, Gateway, Intent, Inventory
from .gcp import model_armor as ma_mod
from .render import RenderEnv, engine_full, ext_spec, gateway_full, proj_iam_spec, short, template_spec


def _resource_key(intent: Intent, inv: Inventory, env: RenderEnv) -> Optional[str]:
    d = intent.destination
    if not d:
        return None
    if d.name and d.name in inv.access:
        return d.name
    if d.kind == "registry":
        return f"projects/{env.gw_project}/locations/{env.region}"
    names = [x.name for coll in (inv.agents, inv.mcp_servers, inv.endpoints) for x in coll]
    rid = d.id or short(d.name)
    return next((n for n in names if short(n) == rid), None)


def _new_binding(intent: Intent, want: Optional[Condition], label: str, kind: str, inv: Inventory) -> Binding:
    names = {e.principal: e.display_name for e in inv.engines if e.principal}
    return make_binding(EGRESSOR, intent.source.principal if intent.source else "",
                        want.model_dump(exclude_none=True) if want else None, label, kind, names)


def _diff_iam(intent: Intent, inv: Inventory, env: RenderEnv) -> DiffItem:
    key = _resource_key(intent, inv, env)
    member = intent.source.principal if intent.source else ""
    want = condition_for(intent.access)
    d = intent.destination
    label = (d.label or d.name or d.id) if d else ""
    kind = d.kind if d else "mcp_server"
    if key is None or key not in inv.access:
        err = inv.access_errors.get(key or "", "")
        detail = (f"current IAM policy unavailable ({err})" if err else
                  "destination not found in this region's Agent Registry")
        grant = intent.kind == "grant"
        return DiffItem(intent_id=intent.id, status="add" if grant else "absent", current=None,
                        after=[_new_binding(intent, want, label, kind, inv)] if grant else None, detail=detail)
    mine: list[Binding] = [b for b in inv.access[key] if b.member == member and b.role == EGRESSOR]
    same = [b for b in mine if same_condition(b.condition, want)]
    others = [b for b in mine if not same_condition(b.condition, want)]
    if intent.kind == "grant":
        if same:
            return DiffItem(intent_id=intent.id, status="present", current=mine, after=mine,
                            detail="already granted with the same condition")
        after = mine + [_new_binding(intent, want, label, kind, inv)]
        if mine:
            had = "; ".join(condition_english(b.condition) for b in mine)
            return DiffItem(intent_id=intent.id, status="replace", current=mine, after=after,
                            detail=(f"the member already has: {had}. IAM ORs bindings, so the grant adds a second "
                                    "binding; revoke the old one to replace it rather than widen it."))
        return DiffItem(intent_id=intent.id, status="add", current=mine, after=after, detail="will add a new binding")
    if same:
        return DiffItem(intent_id=intent.id, status="remove", current=mine, after=others,
                        detail="will remove this binding")
    if mine:
        return DiffItem(intent_id=intent.id, status="absent", current=mine, after=mine,
                        detail="no binding with this exact condition (the member has other bindings)")
    return DiffItem(intent_id=intent.id, status="absent", current=mine, after=mine, detail="no such binding")


def _diff_bind(intent: Intent, inv: Inventory, env: RenderEnv) -> DiffItem:
    engine = engine_full(env, intent.engine or "")
    eng = next((e for e in inv.engines if e.name == engine or e.id == short(engine)), None)
    direction = intent.gateway.direction if intent.gateway else "egress"
    gw = gateway_full(env, intent.gateway.name if intent.gateway else "", direction)
    if eng is None:
        return DiffItem(intent_id=intent.id, status="add" if intent.kind == "bind_gateway" else "absent",
                        detail="engine not found in this region")
    cur = eng.gateways.get(direction)
    if intent.kind == "bind_gateway":
        if cur and tail(cur) == tail(gw):
            return DiffItem(intent_id=intent.id, status="present", detail=f"already bound to {short(gw)}")
        if cur:
            return DiffItem(intent_id=intent.id, status="replace", detail=f"currently bound to {short(cur)}")
        return DiffItem(intent_id=intent.id, status="add", detail=f"not bound for {direction} today")
    if cur:
        return DiffItem(intent_id=intent.id, status="remove", detail=f"currently bound to {short(cur)}")
    return DiffItem(intent_id=intent.id, status="absent", detail=f"not bound for {direction}")


def _diff_ma(intent: Intent, gateways: list[Gateway], env: RenderEnv) -> DiffItem:
    direction = intent.gateway.direction if intent.gateway else "egress"
    gw_name = gateway_full(env, intent.gateway.name if intent.gateway else "", direction)
    gw = next((g for g in gateways if tail(g.name) == tail(gw_name)), None)
    if gw is None:
        return DiffItem(intent_id=intent.id, status="add" if intent.kind == "model_armor_on" else "absent",
                        detail="gateway not found in this region")
    ma = next((p for p in gw.authz_policies if p.profile == "CONTENT_AUTHZ"), None)
    if intent.kind == "model_armor_on":
        return (DiffItem(intent_id=intent.id, status="present", detail=f"policy {short(ma.name)} already attached")
                if ma else DiffItem(intent_id=intent.id, status="add", detail="no Model Armor policy today"))
    return (DiffItem(intent_id=intent.id, status="remove", detail=f"will delete {short(ma.name)}") if ma
            else DiffItem(intent_id=intent.id, status="absent", detail="Model Armor isn't on for this gateway"))


def _diff_setup(intent: Intent, env: RenderEnv, ma: Optional[dict[str, Any]]) -> DiffItem:
    """Model Armor setup kinds against GET /model-armor (templates, extensions, service agent roles)."""
    delete = intent.is_delete
    if ma is None:
        return DiffItem(intent_id=intent.id, status="remove" if delete else "add",
                        detail="current Model Armor state unavailable")
    if intent.kind == "model_armor_template":
        sp = template_spec(intent, env, [])
        have = any((t.name if hasattr(t, "name") else t.get("name")) == sp.name for t in ma.get("templates") or [])
        what = f"template {sp.template_id}"
    elif intent.kind == "model_armor_extension":
        sp = ext_spec(intent, env, [])
        have = any(tail(x.get("name", "")) == tail(sp.name) for x in ma.get("extensions") or [])
        what = f"extension {sp.ext_id}"
    else:
        sp = proj_iam_spec(intent, env, [])
        agent = next((a for a in (ma.get("setup") or {}).get("service_agents") or []
                      if a.get("member") == sp.member and a.get("project") == sp.project), None)
        roles = (agent or {}).get("roles") or {}
        if agent is None or any(roles.get(r) is None for r in sp.roles if r in ma_mod.MA_ROLES):
            return DiffItem(intent_id=intent.id, status="remove" if delete else "add",
                            detail="the member's current project roles are unknown")
        held = [r for r in sp.roles if roles.get(r)]
        if delete:
            return (DiffItem(intent_id=intent.id, status="remove", detail=f"will remove {', '.join(held)}") if held
                    else DiffItem(intent_id=intent.id, status="absent", detail="the member holds none of these roles"))
        todo = [r for r in sp.roles if not roles.get(r)]
        return (DiffItem(intent_id=intent.id, status="add", detail=f"will grant {', '.join(todo)}") if todo
                else DiffItem(intent_id=intent.id, status="present", detail="already holds every role"))
    if delete:
        return (DiffItem(intent_id=intent.id, status="remove", detail=f"will delete {what}") if have
                else DiffItem(intent_id=intent.id, status="absent", detail=f"{what} doesn't exist"))
    return (DiffItem(intent_id=intent.id, status="present", detail=f"{what} already exists") if have
            else DiffItem(intent_id=intent.id, status="add", detail=f"will create {what}"))


def diff(intents: list[Intent], inv: Inventory, gateways: list[Gateway], env: RenderEnv,
         ma: Optional[dict[str, Any]] = None) -> list[DiffItem]:
    out = []
    for it in intents:
        if it.kind in ("grant", "revoke"):
            out.append(_diff_iam(it, inv, env))
        elif it.kind in ("bind_gateway", "unbind_gateway"):
            out.append(_diff_bind(it, inv, env))
        elif it.kind in ("model_armor_template", "model_armor_extension", "iam_project_grant"):
            out.append(_diff_setup(it, env, ma))
        else:
            out.append(_diff_ma(it, gateways, env))
    return out
