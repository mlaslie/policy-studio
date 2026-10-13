"""Checks that run before Apply (and back the POST /preflight endpoint): duplicate intents, intents that will
certainly fail (a bind of an engine that can't be bound, Model Armor on with no extension anywhere, a kind the
caller can't write, a modify of a grant that isn't there or to the same access), and friendlier text for known Google
Cloud errors. Pure functions over a RenderEnv (and the inventory, when given); no calls."""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from .conditions import EGRESSOR, compare_access_many, condition_for, same_condition
from .diff import resource_key
from .english import modify_change
from .gcp.engines import REASON_IDENTITY, tail
from .model import Intent, Inventory
from .render import (PLACEHOLDER_EXT, Blocked, RenderEnv, dedicate_names, enf_spec, engine_full, engine_info_for,
                     english_list, gateway_full, ma_spec, short)

KIND_LABEL = {"grant": "grants", "revoke": "revokes", "modify": "changing grants", "bind_gateway": "gateway binds",
              "unbind_gateway": "gateway unbinds", "model_armor_on": "turning Model Armor on",
              "model_armor_off": "turning Model Armor off", "model_armor_template": "creating Model Armor templates",
              "model_armor_extension": "creating Model Armor extensions",
              "iam_project_grant": "granting the service agent roles",
              "set_enforcement": "changing a gateway's enforcement mode",
              "dedicate_extension": "giving a gateway its own IAP extension"}


# ------------------------------------------------------------------ duplicates
def intent_key(it: Intent) -> str:
    """Two intents with the same key do the same thing (ids, labels and discovered fields don't count)."""
    g = it.gateway
    s = it.source
    d = it.destination
    a = it.access
    key: dict[str, Any] = {"kind": it.kind}
    if g:
        key["gateway"] = [short(g.name), g.direction]
    if it.engine:
        key["engine"] = short(it.engine)
    if s:
        key["source"] = s.principal
    if d:
        key["destination"] = [d.kind, d.id or short(d.name)]
    if a:
        key["access"] = [a.mode, sorted(t for t in (a.tools or []) if t), a.expression or "", a.title]
    f = it.access_from
    if f:
        key["access_from"] = [f.mode, sorted(t for t in (f.tools or []) if t), f.expression or "", f.title]
    for name in ("access_from_list", "access_list"):
        xs = getattr(it, name)
        if xs is not None:
            key[name] = sorted(json.dumps([x.mode, sorted(t for t in (x.tools or []) if t), x.expression or "",
                                           x.title]) for x in xs)
    if it.params:
        key["params"] = it.params.model_dump(exclude_none=True)
    for f in ("extension", "mode", "scope", "source_extension", "new_name"):
        v = getattr(it, f)
        if v:
            key[f] = short(v) if f in ("extension", "source_extension", "new_name") else v
    if it.revert:
        key["revert"] = True
    return json.dumps(key, sort_keys=True, default=str)


def duplicates(intents: list[Intent]) -> dict[str, str]:
    """{id of a later duplicate: id of the first intent with the same key}."""
    first: dict[str, str] = {}
    out: dict[str, str] = {}
    for it in intents:
        k = intent_key(it)
        if k in first:
            out[it.id] = first[k]
        else:
            first[k] = it.id
    return out


# ------------------------------------------------------------------ certain failures
def blockers(intents: list[Intent], env: RenderEnv, writable: Optional[dict[str, Any]] = None,
             inv: Optional[Inventory] = None) -> dict[str, dict[str, str]]:
    """{intent id: {reason, fix}} for intents that would certainly fail. `env` must include with_staged() so a
    Model Armor extension staged in the same request counts. `inv` (optional): the current inventory, to check that
    the grant a modify changes is there. fix: ma_setup | redeploy | permission | already."""
    out: dict[str, dict[str, str]] = {}
    for it in intents:
        if writable and writable.get(it.kind) is False:
            out[it.id] = {"reason": f"You don't have permission for {KIND_LABEL.get(it.kind, it.kind)} in "
                                    f"{env.project} (see the “can write” check on Context for the role to ask for).",
                          "fix": "permission"}
            continue
        if it.kind == "bind_gateway" and it.engine:
            info = engine_info_for(env, engine_full(env, it.engine))
            if info and not info.get("bindable", True):
                out[it.id] = {"reason": f"{info.get('display_name') or short(it.engine)} can't be bound to Agent "
                                        "Gateway. " + (info.get("bindable_reason") or "Redeploy it first."),
                              "fix": "redeploy"}
        if it.kind == "model_armor_on" and it.gateway and it.gateway.name:
            sp = ma_spec(it, env, [])
            known = None if env.known_extensions is None else {tail(x) for x in env.known_extensions + env.staged_extensions}
            if PLACEHOLDER_EXT in sp.extension or (known is not None and tail(sp.extension) not in known):
                what = ("there's no Model Armor authz extension for this gateway to use" if PLACEHOLDER_EXT in
                        sp.extension else f"the extension {short(sp.extension)} doesn't exist")
                out[it.id] = {"reason": f"Model Armor isn't set up in {env.region} yet: {what}, and none is staged in "
                                        "this cart. Set it up first (template, extension, service agent roles).",
                              "fix": "ma_setup"}
        if it.kind in ("set_enforcement", "dedicate_extension"):
            b = _enforcement_blocker(it, env)
            if b:
                out[it.id] = b
        if it.kind == "modify":
            b = _modify_blocker(it, env, inv)
            if b:
                out[it.id] = b
    return out


def _modify_blocker(it: Intent, env: RenderEnv, inv: Optional[Inventory]) -> Optional[dict[str, str]]:
    """The same access as today ("already"), or (with the inventory) no binding matching access_from exactly and none
    with the new access either (when the new one is there, it was already changed: apply skips it). Several bindings:
    blocked when any one of access_from_list is missing (unless the whole change is already there)."""
    olds, news = [condition_for(a) for a in it.froms], [condition_for(a) for a in it.tos]
    norm = lambda cs: {" ".join((c.expression if c else "").split()) for c in cs}  # noqa: E731
    if olds and norm(olds) == norm(news):
        return {"reason": "The new access is the same as the current one, so there is nothing to change.",
                "fix": "already"}
    if inv is None:
        return None
    key = resource_key(it, inv, env)
    if key is None or key not in inv.access:
        return None                          # unknown here (unreadable or not listed): apply checks it live
    member = it.source.principal if it.source else ""
    mine = [b for b in inv.access[key] if b.member == member and b.role == EGRESSOR]
    has = lambda c: any(same_condition(b.condition, c) for b in mine)  # noqa: E731
    if not it.multi:
        if not any(has(c) for c in (olds[0], news[0])):
            return {"reason": "The grant changed since you looked: there is no binding with this member and the old "
                              "condition any more. Sync and try again.", "fix": ""}
        return None
    missing = [c for c in olds if not has(c)]
    gone = [c for c in olds if not any(same_condition(c, n) for n in news)]
    if missing and not (all(has(n) for n in news) and not any(has(c) for c in gone)):
        n = len(missing)
        return {"reason": f"The grant changed since you looked: {n} of the {len(olds)} bindings to replace "
                          f"{'is' if n == 1 else 'are'}n't there any more. Sync and try again.", "fix": ""}
    return None


def _enforcement_blocker(it: Intent, env: RenderEnv) -> Optional[dict[str, str]]:
    """No IAP policy on the gateway, a no-op mode change ("already"), or a dedicate that can't work."""
    if not it.gateway or not it.gateway.name:
        return {"reason": "No gateway.", "fix": ""}
    gateway = gateway_full(env, it.gateway.name, it.gateway.direction)
    gid = short(gateway)
    if env.iap is None:
        return None                          # discovery unavailable: render warns, apply re-checks live
    pols = env.iap["by_gateway"].get(_tail(gateway)) or []
    if it.kind == "set_enforcement":
        ext = it.extension or ""
        if ext and _tail(ext) in env.staged_copies:
            return None                      # a copy created in this request (its mode is the source's)
        if not pols:
            return {"reason": f"{gid} has no IAP REQUEST_AUTHZ policy, so it has no enforcement mode to change "
                              "(nothing on it is checked against roles/iap.egressor grants).", "fix": ""}
        try:
            sp = enf_spec(it, env, [])
        except Blocked as e:
            return {"reason": str(e), "fix": ""}
        if sp.prev_mode and sp.prev_mode == sp.mode:
            return {"reason": f"Already {'enforcing' if sp.mode == 'ENFORCE' else 'in dry run'}: {sp.ext_id} on {gid} "
                              "is in that mode, so there is nothing to change.", "fix": "already"}
        return None
    if not pols:
        return {"reason": f"{gid} has no IAP REQUEST_AUTHZ policy to point at its own extension.", "fix": ""}
    try:
        src, new = dedicate_names(it, env)
    except Blocked as e:
        return {"reason": str(e), "fix": ""}
    if it.revert:
        return None
    if _tail(new) in set(env.iap.get("all_extensions") or []) | set(env.iap.get("extensions", {})):
        return {"reason": f"An authz extension named {short(new)} already exists in {env.region}; pick another name.",
                "fix": ""}
    targets = [t for p in pols[:1] for t in (p.get("target") or {}).get("resources") or []]
    others = [short(t) for t in targets if _tail(t) != _tail(gateway)]
    if others:
        return {"reason": f"{gid}'s IAP policy also targets {english_list(others)}; pointing it at a copy would move "
                          f"{'them' if len(others) > 1 else 'it'} too. Give {gid} its own IAP policy first.",
                "fix": ""}
    return None


def advisories(intents: list[Intent], env: RenderEnv) -> dict[str, str]:
    """{intent id: warning} for intents that are fine to apply but affect more than they name (a shared IAP
    extension), or a modify that widens access."""
    out: dict[str, str] = {}
    for it in intents:
        if it.kind == "modify":
            d = it.destination
            rid = (d.id or short(d.name)) if d else ""
            ro = {t["name"] for t in env.mcp_tools[rid] if t.get("read_only")} if env.mcp_tools.get(rid) else None
            if it.removes_all:
                out[it.id] = f"This removes all access: {modify_change(it)}."
            elif compare_access_many(it.froms, it.tos, ro) == "broader":
                out[it.id] = f"This widens access: {modify_change(it)}."
            continue
        if it.kind != "set_enforcement" or env.iap is None:
            continue
        try:
            sp = enf_spec(it, env, [])
        except Blocked:
            continue
        if sp.shared_with:
            out[it.id] = (f"{sp.ext_id} also controls {english_list(sp.shared_with)}: "
                          f"{'they' if len(sp.shared_with) > 1 else 'it'} switch"
                          f"{'' if len(sp.shared_with) > 1 else 'es'} to "
                          f"{'enforce' if sp.mode == 'ENFORCE' else 'dry run'} too.")
    return out


def _tail(resource: str) -> str:
    i = (resource or "").find("/locations/")
    return resource[i + 1:] if i >= 0 else resource


# ------------------------------------------------------------------ friendlier errors
FRIENDLY: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"must use AGENT_IDENTITY identity type", re.I), REASON_IDENTITY),
    (re.compile(r"Permission '?([\w.]+)'? denied|PERMISSION_DENIED|does not have permission", re.I),
     "Google Cloud refused the change: your credentials lack a permission it needs (see the “can write” check on "
     "Context)."),
    (re.compile(r"ALREADY_EXISTS|already exists", re.I),
     "It already exists in Google Cloud (perhaps created outside Policy Studio). Sync to see the current state."),
    (re.compile(r"concurrent policy changes|etag", re.I),
     "The policy changed while it was being updated (someone else edited it). Try again."),
    (re.compile(r"is being (updated|modified)|another operation|FAILED_PRECONDITION.*operation", re.I),
     "Another change to this resource is still running. Wait a few minutes and try again."),
    (re.compile(r"SERVICE_DISABLED|has not been used in project|it is disabled", re.I),
     "A required Google Cloud API isn't enabled in this project (see Context for which ones are on)."),
]


def friendly(err: str) -> str:
    """Plain-English text for a known Google Cloud error (the input unchanged when none matches)."""
    for pat, msg in FRIENDLY:
        if pat.search(err or ""):
            return msg
    return err

