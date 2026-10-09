"""Apply intents to GCP (apply mode only), streaming one event per step, with read-back and undo.

Uses render.py's specs (iam_spec / bind_spec / ma_spec, engine_body, ma_body, URLs) so what is applied is exactly
what the generated commands do:
  grant / revoke     IAP getIamPolicy (v3) -> add / remove the binding -> setIamPolicy with the etag (retried on an
                     etag conflict), read back. Revoke removes only member + role + matching condition.
  bind / unbind      GET the engine (live agentGatewayConfig) -> PATCH with the other direction kept. One change per
                     engine at a time. Long-running: polled in the background, then the engine is read back.
  model_armor_on/off create / delete the CONTENT_AUTHZ authz policy (long-running, ~4 min), then read back.
  Model Armor setup  model_armor_template: create (or delete) the template, read back.
                     model_armor_extension: create (or delete) the authz extension (long-running, waited for so a
                       model_armor_on later in the same request can use it), read back.
                     iam_project_grant: project getIamPolicy -> add (or remove) the member in the Model Armor roles
                       only -> setIamPolicy with the etag (retried on a conflict), read back.
                     Setup runs before everything else, deletes (undo) after Model Armor off, in reverse.

Events: {intent_id, state: running|done|verified|failed|skipped, detail, operation?, undo?}, then
{type: "done", summary}. Final results are appended to the apply log (settings.apply_log_path()).
"""
from __future__ import annotations

import copy
import json
import os
import queue
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from . import settings
from .conditions import classify, same_condition
from .gcp.engines import gateways_of, tail
from .gcp import model_armor as ma_mod
from .preflight import blockers, duplicates, friendly
from .gcp.rest import CRM, IAP, NETWORKSECURITY, NETWORKSERVICES, GcpError, aiplatform, err_text
from .model import Access, Context, GatewayRef, Intent, SetupParams
from .render import (PLACEHOLDER_EXT, RenderEnv, bind_spec, engine_body, engine_full, engine_url, ext_spec, ext_url,
                     iam_spec, ma_body, ma_spec, ma_template_url, ma_url, proj_iam_spec, short, template_spec)

DESTRUCTIVE = {"revoke", "unbind_gateway", "model_armor_off"}
SETUP_KINDS = ("model_armor_template", "model_armor_extension", "iam_project_grant")
# Run order: setup creates first (template -> extension -> roles), then everything else in cart order, then setup
# deletes (roles -> extension -> template), so Model Armor off runs before its extension is deleted.
RUN_ORDER = {"model_armor_template": 0, "model_armor_extension": 1, "iam_project_grant": 2}
DELETE_RUN_ORDER = {"iam_project_grant": 4, "model_armor_extension": 5, "model_armor_template": 6}


def run_order(it: Intent) -> int:
    if it.is_delete:
        return DELETE_RUN_ORDER[it.kind]
    return RUN_ORDER.get(it.kind, 3)


def is_destructive(raw: Any) -> bool:
    if not isinstance(raw, dict):
        return False
    if raw.get("kind") in DESTRUCTIVE:
        return True
    return raw.get("kind") in SETUP_KINDS and bool((raw.get("params") or {}).get("delete"))
MAX_ETAG_RETRIES = 3
FINAL = {"done", "verified", "failed", "skipped"}


# ------------------------------------------------------------------ request checks
def check_confirm(ctx: Context, raw_intents: list[Any], confirm: dict[str, Any] | None) -> Optional[str]:
    """None when the request may proceed, else the reason (HTTP 400)."""
    confirm = confirm or {}
    if (confirm.get("project") or "").strip() != ctx.project:
        return f"confirm.project must equal the context project ({ctx.project})"
    destructive = [str(i.get("id", "?")) for i in raw_intents if is_destructive(i)]
    if destructive and confirm.get("acknowledge_destructive") is not True:
        return ("revokes, unbinds, Model Armor off and setup deletes need confirm.acknowledge_destructive = true: "
                + ", ".join(destructive))
    return None


# ------------------------------------------------------------------ IAM policy edits (pure)
def _has(pol: dict, member: str, role: str, cond: Any) -> bool:
    return any(b.get("role") == role and member in (b.get("members") or []) and same_condition(b.get("condition"),
                                                                                                cond)
               for b in pol.get("bindings") or [])


def add_binding(pol: dict, member: str, role: str, cond: Any) -> tuple[dict, bool]:
    """Append {role, [member], condition} (as the generated jq / Python do); other bindings untouched."""
    if _has(pol, member, role, cond):
        return pol, False
    new = copy.deepcopy(pol)
    b: dict[str, Any] = {"role": role, "members": [member]}
    if cond is not None and (cond.expression or "").strip():
        b["condition"] = {"title": cond.title, "expression": cond.expression}
    new["bindings"] = list(new.get("bindings") or []) + [b]
    new["version"] = 3
    return new, True


def remove_binding(pol: dict, member: str, role: str, cond: Any) -> tuple[dict, bool, list[dict]]:
    """Remove member from bindings of role with exactly this condition (None = unconditional). Returns the
    conditions it was removed from (for undo)."""
    new = copy.deepcopy(pol)
    kept: list[dict] = []
    removed: list[dict] = []
    for b in new.get("bindings") or []:
        members = list(b.get("members") or [])
        if b.get("role") == role and member in members and same_condition(b.get("condition"), cond):
            members.remove(member)
            removed.append(b.get("condition") or {})
            b = {**b, "members": members}
        if members:
            kept.append(b)
    if not removed:
        return pol, False, []
    new["bindings"] = kept
    new["version"] = 3
    return new, True, removed


def is_etag_conflict(e: Exception) -> bool:
    if not isinstance(e, GcpError):
        return False
    m = (e.message or "").lower()
    return e.status == 409 or "aborted" in m or ("etag" in m and e.status in (400, 409, 412))


# ------------------------------------------------------------------ applier
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secs(s: float) -> str:
    s = int(s)
    return f"{s // 60}m {s % 60:02d}s" if s >= 60 else f"{s}s"


class Applier:
    def __init__(self, env: RenderEnv, rest: Any, writer: Any, *, account: str = "",
                 poll_interval: Optional[float] = None, op_timeout: float = 600.0, log_path: Optional[str] = None,
                 on_finish: Optional[Any] = None):
        self.env = env
        self.rest = rest
        self.writer = writer
        self.account = account
        self.poll_interval = float(os.environ.get("STUDIO_APPLY_POLL", "10")) if poll_interval is None \
            else poll_interval
        self.op_timeout = op_timeout
        self.log_path = log_path or settings.apply_log_path()
        self.q: queue.Queue = queue.Queue()
        self.pending: dict[str, threading.Thread] = {}    # engine / gateway -> its in-flight operation poller
        self.background: list[threading.Thread] = []
        self.final: dict[str, str] = {}
        self._log_lock = threading.Lock()
        self._intents: dict[str, Intent] = {}
        self.on_finish = on_finish
        self.failed_extensions: set[str] = set()

    # ---------------------------------------------------------- events
    def emit(self, intent_id: str, state: str, detail: str = "", **extra: Any) -> None:
        if state == "failed" and detail and not extra.get("raw_error"):
            nice = friendly(detail)
            if nice != detail:
                extra["raw_error"], detail = detail, nice
        ev: dict[str, Any] = {"intent_id": intent_id, "state": state, "detail": detail}
        ev.update({k: v for k, v in extra.items() if v is not None})
        if isinstance(ev.get("undo"), Intent):
            ev["undo"] = ev["undo"].model_dump(exclude_none=True)
        if state in FINAL and not extra.get("progress"):
            self.final[intent_id] = state
            self._log(ev)
        self.q.put(ev)

    def _log(self, ev: dict[str, Any]) -> None:
        it = self._intents.get(ev["intent_id"])
        rec = {"ts": _now(), "project": self.env.ctx.project, "region": self.env.ctx.region, "account": self.account,
               **ev, "intent": it.model_dump(exclude_none=True) if it else None}
        try:
            with self._log_lock:
                os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
        except Exception:  # noqa: BLE001  (a read-only home dir must not break Apply)
            pass

    # ---------------------------------------------------------- driver
    def stream(self, intents: list[Intent], invalid: Optional[dict[int, tuple[str, str]]] = None,
               writable: Optional[dict[str, Any]] = None) -> Iterator[str]:
        """NDJSON lines. The work runs in a worker thread, so a slow client never stalls a write half-way.
        Duplicates are skipped and certain failures (preflight.blockers) fail before any call."""
        invalid = invalid or {}
        worker = threading.Thread(target=self._run, args=(intents, invalid, writable), daemon=True)
        worker.start()
        while True:
            ev = self.q.get()
            if ev is None:
                break
            yield json.dumps(ev) + "\n"

    def events(self, intents: list[Intent], invalid: Optional[dict[int, tuple[str, str]]] = None,
               writable: Optional[dict[str, Any]] = None) -> list[dict]:
        return [json.loads(line) for line in self.stream(intents, invalid, writable)]

    def _run(self, intents: list[Intent], invalid: dict[int, tuple[str, str]],
             writable: Optional[dict[str, Any]] = None) -> None:
        try:
            for iid, err in invalid.values():
                self.emit(iid, "failed", err)
            dups = duplicates(intents)
            blocked = blockers([i for i in intents if i.id not in dups], self.env, writable)
            for it in intents:
                if it.id in dups:
                    self._intents[it.id] = it
                    self.emit(it.id, "skipped", f"Same change as {dups[it.id]} in this request; applied once.")
                elif it.id in blocked:
                    self._intents[it.id] = it
                    self.emit(it.id, "failed", "Blocked before any change: " + blocked[it.id]["reason"],
                              blocked=True, fix=blocked[it.id]["fix"])
            for it in sorted([i for i in intents if i.id not in dups and i.id not in blocked], key=run_order):
                self._intents[it.id] = it
                try:
                    handler = {"grant": self._iap, "revoke": self._iap, "bind_gateway": self._bind,
                               "unbind_gateway": self._bind, "model_armor_on": self._ma_on,
                               "model_armor_off": self._ma_off, "model_armor_template": self._template,
                               "model_armor_extension": self._extension,
                               "iam_project_grant": self._project_iam}[it.kind]
                    handler(it)
                except Exception as e:  # noqa: BLE001  one failure never stops the others
                    self.emit(it.id, "failed", err_text(e))
            for t in list(self.background):
                t.join()
            counts: dict[str, int] = {}
            for s in self.final.values():
                counts[s] = counts.get(s, 0) + 1
            summary = {"total": len(intents) + len(invalid), **counts}
            if blocked:
                summary["blocked"] = len(blocked)
            self._log({"intent_id": "", "type": "done", "summary": summary})
            self.q.put({"type": "done", "summary": summary})
        finally:
            if self.on_finish:
                try:
                    self.on_finish()
                except Exception:  # noqa: BLE001
                    pass
            self.q.put(None)

    def _serialize(self, key: str, intent_id: str) -> None:
        t = self.pending.get(key)
        if t is not None and t.is_alive():
            self.emit(intent_id, "running", f"Waiting for the previous change to {short(key)} to finish")
            t.join()

    def _background(self, key: str, fn: Any, *args: Any) -> None:
        t = threading.Thread(target=self._guarded, args=(fn, args), daemon=True)
        self.pending[key] = t
        self.background.append(t)
        t.start()

    def _guarded(self, fn: Any, args: tuple) -> None:
        try:
            fn(*args)
        except Exception as e:  # noqa: BLE001
            self.emit(args[0], "failed", f"Verification failed: {err_text(e)}")

    def _poll(self, intent_id: str, op: dict, op_url: str, what: str) -> tuple[Optional[bool], str]:
        """(True, '') done, (False, error) failed, (None, msg) still running at the timeout."""
        start = time.monotonic()
        while not op.get("done"):
            elapsed = time.monotonic() - start
            if elapsed >= self.op_timeout:
                return None, f"{what} still running after {_secs(elapsed)}; check the operation later"
            self.emit(intent_id, "done", f"{what}: operation running ({_secs(elapsed)})",
                      operation=op.get("name"), progress=True)
            time.sleep(self.poll_interval)
            op = self.rest.get(op_url) or {}
        if op.get("error"):
            e = op["error"]
            return False, f"{what} failed: {e.get('message') or e}"
        return True, ""

    # ---------------------------------------------------------- IAP grant / revoke
    def _iap(self, it: Intent) -> None:
        if not it.source or not it.source.principal:
            return self.emit(it.id, "failed", "No source principal")
        if not it.destination:
            return self.emit(it.id, "failed", "No destination")
        sp = iam_spec(it, self.env, [])
        if "PROJECT_NUMBER" in sp.resource:
            return self.emit(it.id, "failed", "Couldn't resolve the project number of the Agent Registry project")
        url = f"{IAP}/{sp.resource}"
        self.emit(it.id, "running", f"{'Granting' if sp.op == 'add' else 'Revoking'} {sp.role} on {sp.dest_label}")
        removed: list[dict] = []
        for attempt in range(MAX_ETAG_RETRIES + 1):
            pol = self.rest.post(f"{url}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}) or {}
            if sp.op == "add":
                new, changed = add_binding(pol, sp.member, sp.role, sp.condition)
            else:
                new, changed, removed = remove_binding(pol, sp.member, sp.role, sp.condition)
            if not changed:
                return self.emit(it.id, "skipped", "Already granted" if sp.op == "add" else
                                 "Not granted (no binding with this member, role and condition)")
            try:
                self.writer.set_iam_policy(url, new)
                break
            except GcpError as e:
                if is_etag_conflict(e) and attempt < MAX_ETAG_RETRIES:
                    self.emit(it.id, "running", f"The policy changed meanwhile (etag conflict); retrying "
                                                f"({attempt + 1}/{MAX_ETAG_RETRIES})")
                    continue
                raise
        undo = self._iap_undo(it, sp, removed)
        self.emit(it.id, "done", "Policy updated", undo=undo)
        back = self.rest.post(f"{url}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}) or {}
        present = _has(back, sp.member, sp.role, sp.condition)
        if present == (sp.op == "add"):
            self.emit(it.id, "verified", "Read back: the binding is " + ("there" if present else "gone"), undo=undo)
        else:
            self.emit(it.id, "failed", "Read back: the binding is " + ("still there" if present else "missing"),
                      undo=undo)

    def _iap_undo(self, it: Intent, sp: Any, removed: list[dict]) -> Intent:
        if sp.op == "add":
            acc = (it.access or Access()).model_copy()
            if sp.condition is not None:
                acc.title = sp.condition.title
            return it.model_copy(update={"id": f"undo-{it.id}", "kind": "revoke", "access": acc})
        cond = removed[0] if removed else None
        acc = classify(cond) if cond else Access(mode="all")
        return it.model_copy(update={"id": f"undo-{it.id}", "kind": "grant", "access": acc})

    # ---------------------------------------------------------- engine bind / unbind
    def _bind(self, it: Intent) -> None:
        if not it.engine:
            return self.emit(it.id, "failed", "No engine")
        if not it.gateway or not it.gateway.name:
            return self.emit(it.id, "failed", "No gateway")
        engine = engine_full(self.env, it.engine)
        if "PROJECT_NUMBER" in engine:
            return self.emit(it.id, "failed", "Couldn't resolve the project number")
        self._serialize(engine, it.id)
        region = engine.split("/locations/", 1)[1].split("/", 1)[0] if "/locations/" in engine else self.env.region
        self.emit(it.id, "running", f"Reading the current gateway bindings of {short(engine)}")
        live = self.rest.get(f"{aiplatform(region)}/{engine}") or {}
        cur = gateways_of(live)
        env = replace(self.env, engines={**self.env.engines, engine: cur},
                      ctx=self.env.ctx.model_copy(update={"region": region}))
        sp = bind_spec(it, env, [])
        if {d: tail(g) for d, g in cur.items()} == {d: tail(g) for d, g in sp.new.items()}:
            return self.emit(it.id, "skipped", f"Already bound to {short(sp.gateway)} ({sp.direction})"
                             if sp.op == "bind" else f"No {sp.direction} gateway bound")
        prev = cur.get(sp.direction)
        if sp.op == "bind" and prev and tail(prev) != tail(sp.gateway):
            undo = it.model_copy(update={"id": f"undo-{it.id}", "kind": "bind_gateway",
                                         "gateway": GatewayRef(name=prev, direction=sp.direction)})
        elif sp.op == "bind":
            undo = it.model_copy(update={"id": f"undo-{it.id}", "kind": "unbind_gateway",
                                         "gateway": GatewayRef(name=sp.gateway, direction=sp.direction)})
        else:
            undo = it.model_copy(update={"id": f"undo-{it.id}", "kind": "bind_gateway",
                                         "gateway": GatewayRef(name=prev or sp.gateway, direction=sp.direction)})
        self.emit(it.id, "running", f"PATCH {short(engine)} agentGatewayConfig (keeps the other direction)")
        op = self.writer.patch_engine(engine_url(env, engine), engine_body(sp.new)) or {}
        self.emit(it.id, "done", "Engine update started; it redeploys (several minutes)", operation=op.get("name"),
                  undo=undo)
        self._background(engine, self._finish_bind, it.id, op, region, engine, sp.new, undo)

    def _finish_bind(self, intent_id: str, op: dict, region: str, engine: str, want: dict[str, str],
                     undo: Intent) -> None:
        name = op.get("name") or ""
        ok, msg = self._poll(intent_id, op, f"{aiplatform(region)}/{name}", "Engine update") if name or \
            op.get("done") else (True, "")
        if ok is None:
            return self.emit(intent_id, "done", msg, operation=name or None, undo=undo)
        if ok is False:
            return self.emit(intent_id, "failed", msg, operation=name or None, undo=undo)
        got = gateways_of(self.rest.get(f"{aiplatform(region)}/{engine}") or {})
        if {d: tail(g) for d, g in got.items()} == {d: tail(g) for d, g in want.items()}:
            self.emit(intent_id, "verified", "Read back: agentGatewayConfig is " + (
                ", ".join(f"{d} → {short(g)}" for d, g in sorted(got.items())) or "empty"),
                operation=name or None, undo=undo)
        else:
            self.emit(intent_id, "failed", f"Read back: agentGatewayConfig is {got or '{}'}, expected {want or '{}'}",
                      operation=name or None, undo=undo)

    # ---------------------------------------------------------- Model Armor
    def _existing_ma(self, project: str, region: str, gateway: str) -> Optional[dict]:
        try:
            pols = self.rest.list_all(f"{NETWORKSECURITY}/projects/{project}/locations/{region}/authzPolicies",
                                      "authzPolicies")
        except Exception:  # noqa: BLE001  (create still fails cleanly if the name exists)
            return None
        for p in pols:
            if p.get("policyProfile") == "CONTENT_AUTHZ" and any(
                    tail(r) == tail(gateway) for r in (p.get("target") or {}).get("resources") or []):
                return p
        return None

    def _ma_on(self, it: Intent) -> None:
        if not it.gateway or not it.gateway.name:
            return self.emit(it.id, "failed", "No gateway")
        sp = ma_spec(it, self.env, [])
        if not sp.extension or PLACEHOLDER_EXT in sp.extension or "AUTHZ_EXTENSION" == sp.extension:
            return self.emit(it.id, "failed", f"Model Armor isn't set up in {self.env.region} yet (no Model Armor authz "
                                              "extension). Stage the setup (template, extension, service agent "
                                              "roles) with this item, then apply again.")
        if sp.staged_extension and sp.extension in self.failed_extensions:
            return self.emit(it.id, "skipped", f"Not attempted: the extension {short(sp.extension)} wasn't created")
        key = tail(sp.gateway)
        self._serialize(key, it.id)
        ex = self._existing_ma(sp.project, self.env.region, sp.gateway)
        if ex:
            return self.emit(it.id, "skipped", f"Model Armor is already on ({short(ex.get('name', ''))})")
        self.emit(it.id, "running", f"Creating authz policy {sp.policy} (CONTENT_AUTHZ → {short(sp.extension)})")
        op = self.writer.create_authz_policy(ma_url(sp, self.env, True), ma_body(sp)) or {}
        undo = it.model_copy(update={"id": f"undo-{it.id}", "kind": "model_armor_off", "gateway": GatewayRef(
            name=sp.gateway, direction=it.gateway.direction, policy=sp.policy, extension=sp.extension)})
        self.emit(it.id, "done", "Authz policy creation started (about 4 minutes)", operation=op.get("name"),
                  undo=undo)
        self._background(key, self._finish_ma, it.id, op, sp, True, undo)

    def _ma_off(self, it: Intent) -> None:
        if not it.gateway or not it.gateway.name:
            return self.emit(it.id, "failed", "No gateway")
        sp = ma_spec(it, self.env, [])
        key = tail(sp.gateway)
        self._serialize(key, it.id)
        url = ma_url(sp, self.env, False)
        pol = self.rest.get(url, ok404=True)
        if not pol:
            return self.emit(it.id, "skipped", f"No authz policy named {sp.policy}")
        if pol.get("policyProfile") != "CONTENT_AUTHZ":
            return self.emit(it.id, "failed", f"{sp.policy} is a {pol.get('policyProfile') or 'non-Model Armor'} "
                                              "policy, not CONTENT_AUTHZ; not deleting it")
        ext = (((pol.get("customProvider") or {}).get("authzExtension") or {}).get("resources") or [""])[0]
        self.emit(it.id, "running", f"Deleting authz policy {sp.policy}")
        op = self.writer.delete_authz_policy(url) or {}
        undo = it.model_copy(update={"id": f"undo-{it.id}", "kind": "model_armor_on", "gateway": GatewayRef(
            name=sp.gateway, direction=it.gateway.direction, policy=sp.policy, extension=ext or None)})
        self.emit(it.id, "done", "Authz policy deletion started", operation=op.get("name"), undo=undo)
        self._background(key, self._finish_ma, it.id, op, sp, False, undo)

    def _finish_ma(self, intent_id: str, op: dict, sp: Any, on: bool, undo: Intent) -> None:
        name = op.get("name") or ""
        ok, msg = self._poll(intent_id, op, f"{NETWORKSECURITY}/{name}", "Authz policy " + (
            "creation" if on else "deletion")) if name or op.get("done") else (True, "")
        if ok is None:
            return self.emit(intent_id, "done", msg, operation=name or None, undo=undo)
        if ok is False:
            return self.emit(intent_id, "failed", msg, operation=name or None, undo=undo)
        pol = self.rest.get(ma_url(sp, self.env, False), ok404=True)
        if on and pol and pol.get("policyProfile") == "CONTENT_AUTHZ":
            self.emit(intent_id, "verified", f"Read back: {sp.policy} is attached to {short(sp.gateway)}",
                      operation=name or None, undo=undo)
        elif not on and not pol:
            self.emit(intent_id, "verified", f"Read back: {sp.policy} is gone", operation=name or None, undo=undo)
        else:
            self.emit(intent_id, "failed", f"Read back: {sp.policy} is " + ("missing" if on else "still there"),
                      operation=name or None, undo=undo)


    # ---------------------------------------------------------- Model Armor setup
    def _setup_undo(self, it: Intent, **params: Any) -> Intent:
        p = (it.params or SetupParams()).model_copy(update={"delete": not it.is_delete, **params})
        return it.model_copy(update={"id": f"undo-{it.id}", "params": p})

    def _template(self, it: Intent) -> None:
        sp = template_spec(it, self.env, [])
        if not it.params or not it.params.template_id:
            return self.emit(it.id, "failed", "No template id")
        url = ma_template_url(sp, False)
        exists = self.rest.get(url, ok404=True)
        if sp.op == "create":
            if exists:
                return self.emit(it.id, "skipped", f"Template {sp.template_id} already exists")
            if "INSPECT_TEMPLATE" in json.dumps(sp.body):
                return self.emit(it.id, "failed", "Sensitive data “advanced” needs an inspect template")
            self.emit(it.id, "running", f"Creating Model Armor template {sp.template_id} in {sp.region}")
            self.writer.create_template(ma_template_url(sp, True), sp.body)
            undo = self._setup_undo(it)
            self.emit(it.id, "done", "Template created", undo=undo)
            back = self.rest.get(url, ok404=True)
            if back and back.get("filterConfig") is not None:
                return self.emit(it.id, "verified", f"Read back: template {sp.template_id} exists ("
                                 + "; ".join(ma_mod.parse_template(back).summary[:2]) + ")", undo=undo)
            return self.emit(it.id, "failed", f"Read back: template {sp.template_id} is missing", undo=undo)
        if not exists:
            return self.emit(it.id, "skipped", f"No template named {sp.template_id}")
        self.emit(it.id, "running", f"Deleting Model Armor template {sp.template_id}")
        self.writer.delete_template(url)
        md = exists.get("templateMetadata") or {}
        undo = self._setup_undo(it, block_message=md.get("customPromptSafetyErrorMessage"))
        undo.params.filters = _filters_of(exists)
        self.emit(it.id, "done", "Template deleted", undo=undo)
        if self.rest.get(url, ok404=True):
            return self.emit(it.id, "failed", f"Read back: template {sp.template_id} is still there", undo=undo)
        self.emit(it.id, "verified", f"Read back: template {sp.template_id} is gone", undo=undo)

    def _extension(self, it: Intent) -> None:
        sp = ext_spec(it, self.env, [])
        if not it.params or not it.params.name:
            return self.emit(it.id, "failed", "No extension name")
        url = ext_url(sp, False)
        exists = self.rest.get(url, ok404=True)
        if sp.op == "create":
            if exists:
                return self.emit(it.id, "skipped", f"Extension {sp.ext_id} already exists")
            if not it.params.template:
                self.failed_extensions.add(sp.name)
                return self.emit(it.id, "failed", "No template")
            self.emit(it.id, "running", f"Creating authz extension {sp.ext_id} (Model Armor, template "
                                        f"{short(sp.template)})")
            try:
                op = self.writer.create_authz_extension(ext_url(sp, True), sp.body) or {}
            except Exception:
                self.failed_extensions.add(sp.name)
                raise
            undo = self._setup_undo(it)
        else:
            if not exists:
                return self.emit(it.id, "skipped", f"No authz extension named {sp.ext_id}")
            if not str(exists.get("service", "")).startswith("modelarmor."):
                return self.emit(it.id, "failed", f"{sp.ext_id} isn't a Model Armor extension; not deleting it")
            ids = ma_mod.template_ids(exists)
            self.emit(it.id, "running", f"Deleting authz extension {sp.ext_id}")
            op = self.writer.delete_authz_extension(url) or {}
            undo = self._setup_undo(it, template=ids[0] if ids else None)
        self.emit(it.id, "done", "Authz extension " + ("creation" if sp.op == "create" else "deletion")
                  + " started", operation=op.get("name"), undo=undo)
        # Waited for here (not in the background): a model_armor_on later in this request needs the extension.
        name = op.get("name") or ""
        ok, msg = self._poll(it.id, op, f"{NETWORKSERVICES}/{name}", "Authz extension " + (
            "creation" if sp.op == "create" else "deletion")) if name or op.get("done") else (True, "")
        if ok is not True:
            if sp.op == "create":
                self.failed_extensions.add(sp.name)
            return self.emit(it.id, "failed" if ok is False else "done", msg, operation=name or None, undo=undo)
        back = self.rest.get(url, ok404=True)
        if sp.op == "create" and back and sp.template in ma_mod.template_ids(back):
            return self.emit(it.id, "verified", f"Read back: {sp.ext_id} screens with {short(sp.template)}",
                             operation=name or None, undo=undo)
        if sp.op == "delete" and not back:
            return self.emit(it.id, "verified", f"Read back: {sp.ext_id} is gone", operation=name or None, undo=undo)
        if sp.op == "create":
            self.failed_extensions.add(sp.name)
        self.emit(it.id, "failed", f"Read back: {sp.ext_id} is " + ("missing or names another template"
                                                                      if sp.op == "create" else "still there"),
                  operation=name or None, undo=undo)

    def _project_iam(self, it: Intent) -> None:
        sp = proj_iam_spec(it, self.env, [])
        if not it.params or not it.params.member:
            return self.emit(it.id, "failed", "No member")
        other = [r for r in sp.roles if r not in ma_mod.MA_ROLES]
        if other:
            return self.emit(it.id, "failed", f"Only the Model Armor roles can be granted here, not {', '.join(other)}")
        url = f"{CRM}/projects/{sp.project}"
        add = sp.op == "add"
        self.emit(it.id, "running", f"{'Granting' if add else 'Removing'} {', '.join(sp.roles)} "
                                    f"{'to' if add else 'from'} {sp.member} on {sp.project}")
        changed: list[str] = []
        for attempt in range(MAX_ETAG_RETRIES + 1):
            pol = self.rest.post(f"{url}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}) or {}
            new, changed = pol, []
            for role in sp.roles:
                if add:
                    new, c = add_binding(new, sp.member, role, None)
                else:
                    new, c, _ = remove_binding(new, sp.member, role, None)
                if c:
                    changed.append(role)
            if not changed:
                return self.emit(it.id, "skipped", "Already holds every role" if add else "Holds none of these roles")
            try:
                self.writer.set_project_iam_policy(url, pol, new)
                break
            except GcpError as e:
                if is_etag_conflict(e) and attempt < MAX_ETAG_RETRIES:
                    self.emit(it.id, "running", f"The policy changed meanwhile (etag conflict); retrying "
                                                f"({attempt + 1}/{MAX_ETAG_RETRIES})")
                    continue
                raise
        undo = self._setup_undo(it, roles=changed)
        self.emit(it.id, "done", "Project policy updated", undo=undo)
        back = self.rest.post(f"{url}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}) or {}
        held = ma_mod.roles_of(back, sp.member)
        bad = [r for r in changed if held.get(r) != add]
        if bad:
            return self.emit(it.id, "failed", f"Read back: {', '.join(bad)} " + ("missing" if add else "still there"),
                             undo=undo)
        self.emit(it.id, "verified", f"Read back: {sp.member.split(':', 1)[-1]} "
                  + ("holds " if add else "no longer holds ") + ", ".join(changed), undo=undo)


def _filters_of(template: dict) -> Any:
    """TemplateFilters from a template's REST JSON (for the undo of a delete)."""
    from .model import TemplateFilters
    fc = template.get("filterConfig") or {}
    pi = fc.get("piAndJailbreakFilterSettings") or {}
    sdp = fc.get("sdpSettings") or {}
    return TemplateFilters(
        pi_jailbreak=pi.get("confidenceLevel", "MEDIUM_AND_ABOVE") if pi.get("filterEnforcement", "ENABLED") ==
        "ENABLED" and pi else "off",
        sdp="advanced" if sdp.get("advancedConfig") else ("basic" if sdp.get("basicConfig") else "off"),
        rai={r.get("filterType", ""): r.get("confidenceLevel", "MEDIUM_AND_ABOVE")
             for r in (fc.get("raiSettings") or {}).get("raiFilters") or []},
        malicious_uri=bool(fc.get("maliciousUriFilterSettings")))
