"""The only write path in Policy Studio. Constructed only in `apply` mode (see settings.py).

Every write is checked against an allowlist of exactly the calls Apply makes:
  POST   https://iap.googleapis.com/v1/projects/N/locations/R/iap_web/agentRegistry[/{kind}/{id}]:setIamPolicy
  PATCH  https://R-aiplatform.googleapis.com/v1/projects/X/locations/R/reasoningEngines/ID
           ?updateMask=spec.deploymentSpec.agentGatewayConfig
  POST   https://networksecurity.googleapis.com/v1/projects/P/locations/R/authzPolicies?authzPolicyId=NAME
  DELETE https://networksecurity.googleapis.com/v1/projects/P/locations/R/authzPolicies/NAME
  Model Armor setup:
  POST   https://modelarmor.R.rep.googleapis.com/v1/projects/P/locations/R/templates?templateId=T
  DELETE https://modelarmor.R.rep.googleapis.com/v1/projects/P/locations/R/templates/T
  POST   https://networkservices.googleapis.com/v1/projects/P/locations/R/authzExtensions?authzExtensionId=NAME
  DELETE https://networkservices.googleapis.com/v1/projects/P/locations/R/authzExtensions/NAME
  Enforcement mode (IAP enforce / dry run):
  PATCH  https://networkservices.googleapis.com/v1/projects/P/locations/R/authzExtensions/NAME
           ?updateMask=metadata,failOpen     (body: only metadata and failOpen)
  PATCH  https://networksecurity.googleapis.com/v1/projects/P/locations/R/authzPolicies/NAME
           ?updateMask=customProvider.authzExtension.resources     (body: only that field; dedicate / revert)
  POST   https://cloudresourcemanager.googleapis.com/v1/projects/P:setIamPolicy  (guarded: only through
           set_project_iam_policy, and only when the change adds or removes members of the Model Armor roles)
Reads (getIamPolicy, GET engine / operation / policy) go through the read-only Rest client.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

from .. import settings
from .model_armor import MA_ROLES
from .rest import Rest

_SEG = r"[A-Za-z0-9._~-]+"
ALLOWED: list[tuple[str, re.Pattern[str]]] = [
    ("POST", re.compile(rf"^https://iap\.googleapis\.com/v1/projects/\d+/locations/{_SEG}/iap_web/agentRegistry"
                        rf"(/(agents|mcpServers|endpoints)/{_SEG})?:setIamPolicy$")),
    ("PATCH", re.compile(rf"^https://{_SEG}-aiplatform\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                         rf"reasoningEngines/{_SEG}\?updateMask=spec\.deploymentSpec\.agentGatewayConfig$")),
    ("POST", re.compile(rf"^https://networksecurity\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                        rf"authzPolicies\?authzPolicyId={_SEG}$")),
    ("DELETE", re.compile(rf"^https://networksecurity\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                          rf"authzPolicies/{_SEG}$")),
    ("POST", re.compile(rf"^https://modelarmor\.{_SEG}\.rep\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                        rf"templates\?templateId={_SEG}$")),
    ("DELETE", re.compile(rf"^https://modelarmor\.{_SEG}\.rep\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                          rf"templates/{_SEG}$")),
    ("POST", re.compile(rf"^https://networkservices\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                        rf"authzExtensions\?authzExtensionId={_SEG}$")),
    ("DELETE", re.compile(rf"^https://networkservices\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                          rf"authzExtensions/{_SEG}$")),
    ("PATCH", re.compile(rf"^https://networkservices\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                         rf"authzExtensions/{_SEG}\?updateMask=metadata,failOpen$")),
    ("PATCH", re.compile(rf"^https://networksecurity\.googleapis\.com/v1/projects/{_SEG}/locations/{_SEG}/"
                         rf"authzPolicies/{_SEG}\?updateMask=customProvider\.authzExtension\.resources$")),
]
# Allowed only through Writer.set_project_iam_policy, which checks the policy change itself.
GUARDED: list[tuple[str, re.Pattern[str]]] = [
    ("POST", re.compile(rf"^https://cloudresourcemanager\.googleapis\.com/v1/projects/{_SEG}:setIamPolicy$")),
]


def _members(policy: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    """{(role, condition expression): members}."""
    out: dict[tuple[str, str], set[str]] = {}
    for b in policy.get("bindings") or []:
        key = (b.get("role", ""), ((b.get("condition") or {}).get("expression") or ""))
        out.setdefault(key, set()).update(b.get("members") or [])
    return out


def check_project_policy_change(old: dict[str, Any], new: dict[str, Any]) -> None:
    """Raise unless `new` differs from `old` only by members added to / removed from unconditional bindings of the
    Model Armor roles (MA_ROLES). Everything else (other roles, conditions, audit configs, etag) must be identical."""
    for k in set(old) | set(new):
        if k in ("bindings", "version"):
            continue
        if old.get(k) != new.get(k):
            raise ValueError(f"policy_studio writer: project setIamPolicy may not change {k!r}")
    a, b = _members(old), _members(new)
    for key in set(a) | set(b):
        if a.get(key, set()) == b.get(key, set()):
            continue
        role, cond = key
        if role not in MA_ROLES or cond:
            raise ValueError(f"policy_studio writer: project setIamPolicy may only change the Model Armor roles "
                             f"({', '.join(MA_ROLES)}); it would change {role}" + (" (conditional)" if cond else ""))


class WriteDisabled(RuntimeError):
    """Raised when something tries to construct a Writer outside apply mode."""


def allowed(method: str, url: str) -> bool:
    return any(m == method and p.match(url) for m, p in ALLOWED)


class Writer:
    def __init__(self, rest: Rest, transport: Optional[Callable[..., Any]] = None):
        mode = settings.current_mode()
        if mode != "apply":
            raise WriteDisabled(f"Policy Studio is in {mode} mode: writes are disabled")
        self.rest = rest
        self._send = transport or rest._request   # noqa: SLF001  (same session and error handling as reads)

    def _write(self, method: str, url: str, body: Any = None, guarded: bool = False) -> Any:
        ok = allowed(method, url) or (guarded and any(m == method and p.match(url) for m, p in GUARDED))
        if not ok:
            raise ValueError(f"policy_studio writer: {method} {url} is not an allowed write")
        return self._send(method, url, json=body)

    def set_iam_policy(self, resource_url: str, policy: dict[str, Any]) -> Any:
        return self._write("POST", f"{resource_url}:setIamPolicy", {"policy": policy})

    def patch_engine(self, url: str, body: dict[str, Any]) -> Any:
        return self._write("PATCH", url, body)

    def create_authz_policy(self, url: str, body: dict[str, Any]) -> Any:
        return self._write("POST", url, body)

    def delete_authz_policy(self, url: str) -> Any:
        return self._write("DELETE", url)

    def create_template(self, url: str, body: dict[str, Any]) -> Any:
        return self._write("POST", url, body)

    def delete_template(self, url: str) -> Any:
        return self._write("DELETE", url)

    def create_authz_extension(self, url: str, body: dict[str, Any]) -> Any:
        return self._write("POST", url, body)

    def delete_authz_extension(self, url: str) -> Any:
        return self._write("DELETE", url)

    def patch_authz_extension(self, url: str, body: dict[str, Any]) -> Any:
        """Enforcement mode: only metadata and failOpen of an authz extension."""
        if set(body) - {"metadata", "failOpen"} or not isinstance(body.get("metadata", {}), dict):
            raise ValueError("policy_studio writer: an authz extension PATCH may only change metadata and failOpen")
        return self._write("PATCH", url, body)

    def patch_authz_policy(self, url: str, body: dict[str, Any]) -> Any:
        """Dedicated extension: only customProvider.authzExtension.resources of an authz policy (one extension)."""
        res = ((body.get("customProvider") or {}).get("authzExtension") or {}).get("resources")
        if set(body) != {"customProvider"} or set(body["customProvider"]) != {"authzExtension"} or \
                set(body["customProvider"]["authzExtension"]) != {"resources"} or not isinstance(res, list) or \
                len(res) != 1:
            raise ValueError("policy_studio writer: an authz policy PATCH may only set "
                             "customProvider.authzExtension.resources to one extension")
        return self._write("PATCH", url, body)

    def set_project_iam_policy(self, project_url: str, current: dict[str, Any], policy: dict[str, Any]) -> Any:
        """Project setIamPolicy, only for adding / removing members of the Model Armor roles (see
        check_project_policy_change). `current` is the policy as read (with its etag)."""
        check_project_policy_change(current, policy)
        return self._write("POST", f"{project_url}:setIamPolicy", {"policy": policy}, guarded=True)
