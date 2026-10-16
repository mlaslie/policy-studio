"""Compare staged intents with the current state: add / present / replace / remove / absent."""
from __future__ import annotations

from typing import Any, Optional

from .conditions import EGRESSOR, condition_for, same_condition
from .english import condition_english, make_binding, modify_change
from .gcp.engines import tail
from .model import Binding, Condition, DiffItem, Gateway, Intent, Inventory
from .gcp import model_armor as ma_mod
from .gcp import registry as reg_mod
from .render import (GRANTS_LOST, MODE_LABEL, Blocked, RenderEnv, dedicate_names, engine_full, english_list, ext_spec,
                     find_service, gateway_full, proj_iam_spec, short, template_spec)


def resource_key(intent: Intent, inv: Inventory, env: RenderEnv) -> Optional[str]:
    """The Inventory.access key of the intent's destination (None when it isn't in the inventory)."""
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
    key = resource_key(intent, inv, env)
    member = intent.source.principal if intent.source else ""
    want = condition_for(intent.access)
    d = intent.destination
    label = (d.label or d.name or d.id) if d else ""
    kind = d.kind if d else "mcp_server"
    if d and d.pending_service:
        grant = intent.kind == "grant"
        return DiffItem(intent_id=intent.id, status="add" if grant else "absent", current=[],
                        after=[_new_binding(intent, want, label, kind, inv)] if grant else None,
                        detail=f"on the new entry {d.pending_service}, registered by an earlier item in this request "
                               "(it has no grants yet)")
    if key is None or key not in inv.access:
        err = inv.access_errors.get(key or "", "")
        detail = (f"current IAM policy unavailable ({err})" if err else
                  "destination not found in this region's Agent Registry")
        grant = intent.kind == "grant"
        if intent.kind == "modify":
            detail = f"{detail}; the grant to change can't be checked" if err else detail
        return DiffItem(intent_id=intent.id, status="add" if grant else "absent", current=None,
                        after=[_new_binding(intent, want, label, kind, inv)] if grant else None, detail=detail)
    mine: list[Binding] = [b for b in inv.access[key] if b.member == member and b.role == EGRESSOR]
    if intent.kind == "modify":
        return _diff_modify(intent, mine, want, label, kind, inv)
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


def _diff_modify(intent: Intent, mine: list[Binding], want: Optional[Condition], label: str, kind: str,
                 inv: Inventory) -> DiffItem:
    """replace: the bindings matching access_from (or each of access_from_list) exactly go, the new one comes (none
    for the remove-all form: status remove), in one change. `current` is every binding of the member today."""
    olds = [condition_for(a) for a in intent.froms]
    news = [condition_for(a) for a in intent.tos]
    change = modify_change(intent)
    key = lambda c: " ".join((c.expression if c else "").split())  # noqa: E731
    if olds and {key(c) for c in olds} == {key(c) for c in news}:
        return DiffItem(intent_id=intent.id, status="present", current=mine, after=mine,
                        detail="the new access is the same as the current one")
    has = lambda c: any(same_condition(b.condition, c) for b in mine)  # noqa: E731
    missing = [c for c in olds if not has(c)]
    if missing:
        gone = [c for c in olds if not any(same_condition(c, n) for n in news)]
        if all(has(n) for n in news) and not any(has(c) for c in gone):
            what = "the new binding is there and the old one isn't" if not intent.multi else \
                "the new bindings are there and the old ones aren't"
            return DiffItem(intent_id=intent.id, status="present", current=mine, after=mine,
                            detail=f"already changed ({change}): {what}")
        return DiffItem(intent_id=intent.id, status="absent", current=mine, after=mine,
                        detail="the grant to change wasn't found: it changed since you looked; Sync and try again"
                        if not intent.multi else
                        f"{len(missing)} of the {len(olds)} grants to replace weren't found: they changed since you "
                        "looked; Sync and try again")
    rest = [b for b in mine if not any(same_condition(b.condition, c) for c in olds)]
    after = list(rest)
    for n in news:
        if not any(same_condition(b.condition, n) for b in after):
            after.append(_new_binding(intent, n, label, kind, inv))
    if not news and olds:
        return DiffItem(intent_id=intent.id, status="remove", current=mine, after=after,
                        detail=f"removes all {len(olds)} grants ({change})")
    return DiffItem(intent_id=intent.id, status="replace", current=mine, after=after, detail=change)


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


def _diff_enforcement(intent: Intent, gateways: list[Gateway], env: RenderEnv) -> DiffItem:
    """set_enforcement: current vs target mode; dedicate_extension: which extension the gateway's IAP policy uses."""
    direction = intent.gateway.direction if intent.gateway else "egress"
    gw_name = gateway_full(env, intent.gateway.name if intent.gateway else "", direction)
    gw = next((g for g in gateways if tail(g.name) == tail(gw_name)), None)
    if gw is None:
        return DiffItem(intent_id=intent.id, status="absent", detail="gateway not found in this region")
    enf = gw.enforcement
    cur_ext = enf.extension or ""
    if intent.kind == "set_enforcement":
        want = intent.mode or "ENFORCE"
        ext = intent.extension or cur_ext
        if ext and tail(ext) in env.staged_copies:
            src = env.staged_copies[tail(ext)]
            now = MODE_LABEL.get(enf.mode or "", "unknown") if tail(src) == tail(cur_ext) else "unknown"
            return DiffItem(intent_id=intent.id, status="replace" if now != MODE_LABEL[want] else "add",
                            detail=f"{gw.id}: {now} → {MODE_LABEL[want]} (on its own extension {short(ext)}, created "
                                   "by an earlier item); other gateways keep their mode", current_mode=enf.mode,
                            target_mode=want)
        if not enf.mode:
            return DiffItem(intent_id=intent.id, status="absent", detail=enf.reason or "no IAP enforcement mode on "
                            "this gateway", current_mode=None, target_mode=want)
        others = enf.shared_with if tail(ext) == tail(cur_ext) else []
        also = f"; also {english_list([short(x) for x in others])} (shared extension)" if others else ""
        if enf.mode == want:
            return DiffItem(intent_id=intent.id, status="present", detail=f"already {MODE_LABEL[want].lower()}",
                            current_mode=enf.mode, target_mode=want)
        return DiffItem(intent_id=intent.id, status="replace",
                        detail=f"{gw.id}: {MODE_LABEL[enf.mode]} → {MODE_LABEL[want]}{also}", current_mode=enf.mode,
                        target_mode=want)
    try:
        src, new = dedicate_names(intent, env)
    except Blocked as e:
        return DiffItem(intent_id=intent.id, status="absent", detail=str(e))
    if intent.revert:
        if tail(cur_ext) == tail(new):
            return DiffItem(intent_id=intent.id, status="remove",
                            detail=f"{gw.id} goes back to {short(src)}; {short(new)} is deleted")
        return DiffItem(intent_id=intent.id, status="absent", detail=f"{gw.id} doesn't use {short(new)}")
    if tail(cur_ext) == tail(new):
        return DiffItem(intent_id=intent.id, status="present", detail=f"{gw.id} already uses {short(new)}")
    if not enf.policy:
        return DiffItem(intent_id=intent.id, status="absent", detail=enf.reason or "no IAP policy on this gateway")
    return DiffItem(intent_id=intent.id, status="add",
                    detail=f"creates {short(new)} (copy of {short(cur_ext or src)}, "
                           f"{MODE_LABEL.get(enf.mode or '', 'same mode').lower()}) and points {gw.id}'s IAP policy "
                           "at it" + (f"; {english_list([short(x) for x in enf.shared_with])} keep "
                                      f"{short(cur_ext)}" if enf.shared_with else ""))


def _diff_registry(intent: Intent, inv: Inventory, env: RenderEnv) -> DiffItem:
    """registry_service against the region's Services (and, for a delete, the grants on the entry)."""
    p = intent.params
    sid = ((p.service_id if p else "") or "").strip()
    delete = intent.is_delete
    if env.registry is None:
        return DiffItem(intent_id=intent.id, status="remove" if delete else "add",
                        detail="the region's registry entries are unknown (couldn't list services)")
    svc = find_service(env, sid)
    if delete:
        if svc is None:
            return DiffItem(intent_id=intent.id, status="absent", detail=f"no registry entry {sid}")
        key = next((x.name for coll in (inv.mcp_servers, inv.endpoints, inv.agents) for x in coll
                    if x.service == svc.name), None)
        current = inv.access.get(key, []) if key else []
        n = len(current)
        urls = english_list([i.url for i in svc.interfaces])
        return DiffItem(intent_id=intent.id, status="remove", current=current or None, after=[],
                        detail=f"will delete {svc.display_name} ({sid}, {urls})"
                               + (f"; its {n} grant{'s go' if n != 1 else ' goes'} with it" if n else "")
                               + f". {GRANTS_LOST}.")
    if svc is not None:
        same = reg_mod.same_interfaces([{"url": i.url, "protocolBinding": i.protocol_binding} for i in svc.interfaces],
                                       [{"url": i.url, "protocolBinding": (i.protocol_binding or "").upper()}
                                        for i in (p.interfaces if p else None) or []])
        return DiffItem(intent_id=intent.id, status="present" if same else "absent",
                        detail=f"{sid} already exists" + ("" if same else " with other URLs: pick another id"))
    urls = [i.url for i in (p.interfaces if p else None) or [] if i.url]
    return DiffItem(intent_id=intent.id, status="add",
                    detail=f"will register {len(urls)} URL{'s' if len(urls) != 1 else ''}: {english_list(urls)}"
                           + (" (a new entry: the IAP grants of the deleted one don't come back)" if intent.id.startswith("undo-")
                              else ""))


def diff(intents: list[Intent], inv: Inventory, gateways: list[Gateway], env: RenderEnv,
         ma: Optional[dict[str, Any]] = None) -> list[DiffItem]:
    out = []
    for it in intents:
        if it.kind in ("grant", "revoke", "modify"):
            out.append(_diff_iam(it, inv, env))
        elif it.kind in ("bind_gateway", "unbind_gateway"):
            out.append(_diff_bind(it, inv, env))
        elif it.kind in ("model_armor_template", "model_armor_extension", "iam_project_grant"):
            out.append(_diff_setup(it, env, ma))
        elif it.kind in ("set_enforcement", "dedicate_extension"):
            out.append(_diff_enforcement(it, gateways, env))
        elif it.kind == "registry_service":
            out.append(_diff_registry(it, inv, env))
        else:
            out.append(_diff_ma(it, gateways, env))
    return out
