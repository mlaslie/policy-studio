"""Apply intents to GCP (apply mode only), streaming one event per step, with read-back and undo.

Uses render.py's specs (iam_spec / bind_spec / ma_spec, engine_body, ma_body, URLs) so what is applied is exactly
what the generated commands do:
  grant / revoke     IAP getIamPolicy (v3) -> add / remove the binding -> setIamPolicy with the etag (retried on an
                     etag conflict), read back. Revoke removes only member + role + matching condition.
  bind / unbind      GET the engine (live agentGatewayConfig) -> PATCH with the other direction kept. One change per
                     engine at a time. Long-running: polled in the background, then the engine is read back.
  model_armor_on/off create / delete the CONTENT_AUTHZ authz policy (long-running, ~4 min), then read back.

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
from .gcp.rest import IAP, NETWORKSECURITY, GcpError, aiplatform, err_text
from .model import Access, Context, GatewayRef, Intent
from .render import (RenderEnv, bind_spec, engine_body, engine_full, engine_url, iam_spec, ma_body, ma_spec, ma_url,
                     short)

DESTRUCTIVE = {"revoke", "unbind_gateway", "model_armor_off"}
MAX_ETAG_RETRIES = 3
FINAL = {"done", "verified", "failed", "skipped"}


# ------------------------------------------------------------------ request checks
def check_confirm(ctx: Context, raw_intents: list[Any], confirm: dict[str, Any] | None) -> Optional[str]:
    """None when the request may proceed, else the reason (HTTP 400)."""
    confirm = confirm or {}
    if (confirm.get("project") or "").strip() != ctx.project:
        return f"confirm.project must equal the context project ({ctx.project})"
    destructive = [str(i.get("id", "?")) for i in raw_intents if isinstance(i, dict) and i.get("kind") in DESTRUCTIVE]
    if destructive and confirm.get("acknowledge_destructive") is not True:
        return ("revokes, unbinds and Model Armor off need confirm.acknowledge_destructive = true: "
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

    # ---------------------------------------------------------- events
    def emit(self, intent_id: str, state: str, detail: str = "", **extra: Any) -> None:
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
    def stream(self, intents: list[Intent], invalid: Optional[dict[int, tuple[str, str]]] = None) -> Iterator[str]:
        """NDJSON lines. The work runs in a worker thread, so a slow client never stalls a write half-way."""
        invalid = invalid or {}
        worker = threading.Thread(target=self._run, args=(intents, invalid), daemon=True)
        worker.start()
        while True:
            ev = self.q.get()
            if ev is None:
                break
            yield json.dumps(ev) + "\n"

    def events(self, intents: list[Intent], invalid: Optional[dict[int, tuple[str, str]]] = None) -> list[dict]:
        return [json.loads(line) for line in self.stream(intents, invalid)]

    def _run(self, intents: list[Intent], invalid: dict[int, tuple[str, str]]) -> None:
        try:
            for iid, err in invalid.values():
                self.emit(iid, "failed", err)
            for it in intents:
                self._intents[it.id] = it
                try:
                    handler = {"grant": self._iap, "revoke": self._iap, "bind_gateway": self._bind,
                               "unbind_gateway": self._bind, "model_armor_on": self._ma_on,
                               "model_armor_off": self._ma_off}[it.kind]
                    handler(it)
                except Exception as e:  # noqa: BLE001  one failure never stops the others
                    self.emit(it.id, "failed", err_text(e))
            for t in list(self.background):
                t.join()
            counts: dict[str, int] = {}
            for s in self.final.values():
                counts[s] = counts.get(s, 0) + 1
            summary = {"total": len(intents) + len(invalid), **counts}
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
        if not sp.extension or "MODEL_ARMOR_EXTENSION" in sp.extension or "AUTHZ_EXTENSION" == sp.extension:
            return self.emit(it.id, "failed", "No Model Armor authz extension found in this region; create one first")
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

