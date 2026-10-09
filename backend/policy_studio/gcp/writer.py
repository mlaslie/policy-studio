"""The only write path in Policy Studio. Constructed only in `apply` mode (see settings.py).

Every write is checked against an allowlist of exactly the calls Apply makes:
  POST   https://iap.googleapis.com/v1/projects/N/locations/R/iap_web/agentRegistry[/{kind}/{id}]:setIamPolicy
  PATCH  https://R-aiplatform.googleapis.com/v1/projects/X/locations/R/reasoningEngines/ID
           ?updateMask=spec.deploymentSpec.agentGatewayConfig
  POST   https://networksecurity.googleapis.com/v1/projects/P/locations/R/authzPolicies?authzPolicyId=NAME
  DELETE https://networksecurity.googleapis.com/v1/projects/P/locations/R/authzPolicies/NAME
Reads (getIamPolicy, GET engine / operation / policy) go through the read-only Rest client.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

from .. import settings
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
]


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

    def _write(self, method: str, url: str, body: Any = None) -> Any:
        if not allowed(method, url):
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
