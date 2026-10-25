"""Run mode: `generate` (no write path at all) or `apply` (writes with Application Default Credentials).

  STUDIO_MODE=generate|apply     explicit choice
  (unset)                        generate on Cloud Run (K_SERVICE is set) and in the container image
                                 (STUDIO_CONTAINER=1, set by the Dockerfile: it listens on 0.0.0.0), apply locally
  STUDIO_ALLOW_APPLY_ON_CLOUD_RUN=1   required for STUDIO_MODE=apply on Cloud Run (otherwise: logged, generate)
  STUDIO_APPLY_MEMBERS           Cloud Run with apply: the IAP-verified emails that may apply (comma-separated,
                                 `user:` optional). Unset or empty: nobody can apply on Cloud Run.

On Cloud Run the service account reads whatever project a request names, so requests are limited to the projects
the deployment is configured for: STUDIO_PROJECT, STUDIO_GATEWAY_PROJECT and STUDIO_ALLOWED_PROJECTS
(comma-separated). With none of them set there is no limit. Locally there is none either (your own credentials).

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
        if rt == "cloud_run":
            return "generate", "default on Cloud Run"
        if env.get("STUDIO_CONTAINER") == "1":
            return "generate", "default in the container image; set STUDIO_MODE=apply to allow writes"
        return "apply", "default when run locally"
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


def _csv(raw: Optional[str]) -> list[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def allowed_projects(env: Optional[Mapping[str, str]] = None) -> Optional[list[str]]:
    """The projects requests may name on Cloud Run (None = no limit: local, or none configured)."""
    env = os.environ if env is None else env
    if runtime(env) != "cloud_run":
        return None
    out = list(dict.fromkeys([*_csv(env.get("STUDIO_PROJECT")), *_csv(env.get("STUDIO_GATEWAY_PROJECT")),
                              *_csv(env.get("STUDIO_ALLOWED_PROJECTS"))]))
    return out or None


def project_problem(projects: list[str], env: Optional[Mapping[str, str]] = None,
                    numbers: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Why a request naming these projects is refused on Cloud Run (403), or None. `numbers` (project id -> number,
    the ones already resolved) lets an allowed project's number through too (a resource name can carry either)."""
    allowed = allowed_projects(env)
    if allowed is None:
        return None
    ok = set(allowed) | {n for pid, n in (numbers or {}).items() if pid in allowed}
    for p in dict.fromkeys(x.strip() for x in projects if x and x.strip()):
        if p not in ok:
            return (f"Project {p[:80]!r} isn't one this deployment reads: on Cloud Run Policy Studio reads only "
                    f"{', '.join(allowed)} (STUDIO_PROJECT, STUDIO_GATEWAY_PROJECT, STUDIO_ALLOWED_PROJECTS).")
    return None


def apply_members(env: Optional[Mapping[str, str]] = None) -> list[str]:
    env = os.environ if env is None else env
    return [m.split(":", 1)[1].lower() if m.lower().startswith("user:") else m.lower()
            for m in _csv(env.get("STUDIO_APPLY_MEMBERS"))]


def apply_member_problem(email: Optional[str], env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """On Cloud Run, why this IAP-verified user may not apply (403), or None. Locally: None (your own credentials)."""
    env = os.environ if env is None else env
    if runtime(env) != "cloud_run":
        return None
    members = apply_members(env)
    if not members:
        return ("Apply on Cloud Run needs STUDIO_APPLY_MEMBERS: the emails (as IAP verifies them) of the people "
                "who may apply. None is set, so nobody can.")
    if not email:
        return "Apply on Cloud Run needs the IAP-verified user, and this request has none."
    if email.strip().lower() not in members:
        return f"{email} isn't in STUDIO_APPLY_MEMBERS, so it can't apply on this deployment."
    return None


def apply_log_path() -> str:
    return os.environ.get("STUDIO_APPLY_LOG") or os.path.join(os.path.expanduser("~"), ".policy-studio",
                                                               "apply-log.jsonl")
