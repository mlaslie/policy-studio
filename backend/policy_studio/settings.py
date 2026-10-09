"""Run mode: `generate` (no write path at all) or `apply` (writes with Application Default Credentials).

  STUDIO_MODE=generate|apply     explicit choice
  (unset)                        generate on Cloud Run (K_SERVICE is set), apply locally
  STUDIO_ALLOW_APPLY_ON_CLOUD_RUN=1   required for STUDIO_MODE=apply on Cloud Run (otherwise: logged, generate)

Resolved from the environment on every call (cheap), so tests and embedding apps can change it.
"""
from __future__ import annotations

import logging
import os
from typing import Literal, Mapping, Optional

log = logging.getLogger("policy_studio")

Mode = Literal["generate", "apply"]
MODES = ("generate", "apply")
_logged: set[str] = set()


def runtime(env: Optional[Mapping[str, str]] = None) -> Literal["cloud_run", "local"]:
    env = os.environ if env is None else env
    return "cloud_run" if env.get("K_SERVICE") else "local"


def resolve_mode(env: Optional[Mapping[str, str]] = None) -> tuple[Mode, str]:
    """(mode, why). Never raises: an invalid or refused STUDIO_MODE falls back to generate."""
    env = os.environ if env is None else env
    rt = runtime(env)
    raw = (env.get("STUDIO_MODE") or "").strip().lower()
    if raw and raw not in MODES:
        return "generate", f"STUDIO_MODE={raw!r} is not one of generate|apply; using generate"
    if not raw:
        return ("generate", "default on Cloud Run") if rt == "cloud_run" else ("apply", "default when run locally")
    if raw == "apply" and rt == "cloud_run" and env.get("STUDIO_ALLOW_APPLY_ON_CLOUD_RUN") != "1":
        return "generate", ("STUDIO_MODE=apply refused on Cloud Run (set STUDIO_ALLOW_APPLY_ON_CLOUD_RUN=1 to allow); "
                            "using generate")
    return raw, f"STUDIO_MODE={raw}"  # type: ignore[return-value]


def current_mode() -> Mode:
    mode, why = resolve_mode()
    key = f"{mode}:{why}"
    if key not in _logged:
        _logged.add(key)
        (log.warning if "refused" in why or "not one of" in why else log.info)("Policy Studio mode: %s (%s)", mode, why)
    return mode


def generate_reason(env: Optional[Mapping[str, str]] = None) -> str:
    """Why Apply is off in generate mode (for can_apply_reason)."""
    _, why = resolve_mode(env)
    if runtime(env) == "cloud_run":
        return "Generate-only mode (Cloud Run service account)" + (f": {why}" if "refused" in why else "")
    return f"Generate-only mode ({why})"


def apply_log_path() -> str:
    return os.environ.get("STUDIO_APPLY_LOG") or os.path.join(os.path.expanduser("~"), ".policy-studio",
                                                               "apply-log.jsonl")
