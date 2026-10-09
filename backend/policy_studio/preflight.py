"""Checks that run before Apply (and back the POST /preflight endpoint): duplicate intents, intents that will
certainly fail (a bind of an engine that can't be bound, Model Armor on with no extension anywhere, a kind the
caller can't write), and friendlier text for known Google Cloud errors. Pure functions over a RenderEnv; no calls."""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from .gcp.engines import REASON_IDENTITY, tail
from .model import Intent
from .render import PLACEHOLDER_EXT, RenderEnv, engine_full, engine_info_for, ma_spec, short

KIND_LABEL = {"grant": "grants", "revoke": "revokes", "bind_gateway": "gateway binds",
              "unbind_gateway": "gateway unbinds", "model_armor_on": "turning Model Armor on",
              "model_armor_off": "turning Model Armor off", "model_armor_template": "creating Model Armor templates",
              "model_armor_extension": "creating Model Armor extensions",
              "iam_project_grant": "granting the service agent roles"}


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
    if it.params:
        key["params"] = it.params.model_dump(exclude_none=True)
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
def blockers(intents: list[Intent], env: RenderEnv, writable: Optional[dict[str, Any]] = None
             ) -> dict[str, dict[str, str]]:
    """{intent id: {reason, fix}} for intents that would certainly fail. `env` must include with_staged() so a
    Model Armor extension staged in the same request counts. fix: ma_setup | redeploy | permission."""
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
    return out


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

