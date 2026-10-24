"""IAP signed-header check on Cloud Run: every /api/* request must carry a valid `x-goog-iap-jwt-assertion`.

deploy.sh puts the service behind IAP (`--iap`, `--no-allow-unauthenticated`), so IAP has already checked the user.
The app checks IAP's signed header too, so a request that reaches the container some other way (a misconfigured
ingress, IAP turned off, a forged `x-goog-authenticated-user-*` header) gets 401 instead of the API.

  token     x-goog-iap-jwt-assertion (ES256, signed by IAP)
  keys      https://www.gstatic.com/iap/verify/public_key (cached for an hour)
  issuer    https://cloud.google.com/iap
  audience  STUDIO_IAP_AUDIENCE, else IAP directly on Cloud Run:
            /projects/<PROJECT_NUMBER>/locations/<REGION>/services/<K_SERVICE> (number and region from the metadata
            server, read once). Behind a load balancer with IAP set STUDIO_IAP_AUDIENCE to
            /projects/<PROJECT_NUMBER>/global/backendServices/<BACKEND_SERVICE_ID>.

Only on Cloud Run (K_SERVICE set, checked per request); /api/studio/health and the static UI are not checked.
The verified email is in `request.state.iap_email` (scope["state"]).
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Awaitable, Callable, Mapping, Optional

ISSUER = "https://cloud.google.com/iap"
CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
HEADER = "x-goog-iap-jwt-assertion"
METADATA = "http://metadata.google.internal/computeMetadata/v1"
OPEN_PATHS = ("/api/studio/health",)
CERTS_TTL = 3600.0

_audience: Optional[str] = None
_lock = threading.Lock()


class IapError(Exception):
    pass


def enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if env is None else env
    return bool(env.get("K_SERVICE"))


# ------------------------------------------------------------------ machine-facing pieces (replaced in tests)
def metadata_get(path: str) -> str:
    import requests
    r = requests.get(f"{METADATA}/{path}", headers={"Metadata-Flavor": "Google"}, timeout=5)
    r.raise_for_status()
    return r.text.strip()


def verify_token(token: str, audience: str) -> Mapping[str, Any]:
    from google.oauth2 import id_token
    return id_token.verify_token(token, _certs_request(), audience=audience, certs_url=CERTS_URL)


class _CachingRequest:
    """google.auth transport Request that caches the IAP public keys (verify_token fetches them on every call)."""
    def __init__(self) -> None:
        from google.auth.transport.requests import Request
        self._inner = Request()
        self._cache: dict[str, tuple[float, Any]] = {}

    def __call__(self, url: str, method: str = "GET", **kwargs: Any) -> Any:
        hit = self._cache.get(url)
        if method == "GET" and hit and time.time() - hit[0] < CERTS_TTL:
            return hit[1]
        resp = self._inner(url, method=method, **kwargs)
        if method == "GET" and resp.status == 200:
            self._cache[url] = (time.time(), resp)
        return resp


_request: Optional[_CachingRequest] = None


def _certs_request() -> _CachingRequest:
    global _request
    if _request is None:
        _request = _CachingRequest()
    return _request


# ------------------------------------------------------------------ audience / verification
def audience(env: Optional[Mapping[str, str]] = None) -> str:
    """STUDIO_IAP_AUDIENCE, else /projects/NUM/locations/REGION/services/K_SERVICE from the metadata server (cached)."""
    global _audience
    env = os.environ if env is None else env
    explicit = (env.get("STUDIO_IAP_AUDIENCE") or "").strip()
    if explicit:
        return explicit
    with _lock:
        if _audience is None:
            try:
                number = metadata_get("project/numeric-project-id")
                region = metadata_get("instance/region").rsplit("/", 1)[-1]   # projects/NUM/regions/REGION
            except Exception as e:  # noqa: BLE001
                raise IapError(f"can't determine the IAP audience from the metadata server ({type(e).__name__}); "
                               "set STUDIO_IAP_AUDIENCE") from e
            if not number or not region:
                raise IapError("can't determine the IAP audience from the metadata server; set STUDIO_IAP_AUDIENCE")
            _audience = f"/projects/{number}/locations/{region}/services/{env.get('K_SERVICE', '')}"
        return _audience


def reset() -> None:
    """Forget the cached audience (tests)."""
    global _audience
    _audience = None


def verify(token: str, env: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
    """The verified IAP claims, or IapError."""
    if not token:
        raise IapError(f"missing {HEADER} header: Policy Studio on Cloud Run must be reached through IAP")
    aud = audience(env)
    try:
        claims = dict(verify_token(token, aud))
    except Exception as e:  # noqa: BLE001  (bad signature, expired, wrong audience, keys unreachable)
        raise IapError(f"invalid IAP assertion: {str(e)[:200]}") from e
    if claims.get("iss") != ISSUER:
        raise IapError(f"invalid IAP assertion: issuer {claims.get('iss')!r} is not {ISSUER}")
    return claims


# ------------------------------------------------------------------ ASGI middleware
Scope = dict[str, Any]
App = Callable[[Scope, Callable, Callable], Awaitable[None]]


class IapMiddleware:
    """401 JSON for /api/* requests without a valid IAP assertion, when running on Cloud Run."""
    def __init__(self, app: App):
        self.app = app

    async def __call__(self, scope: Scope, receive: Callable, send: Callable) -> None:
        path = scope.get("path", "")
        if scope.get("type") != "http" or not enabled() or not path.startswith("/api/") or path in OPEN_PATHS \
                or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        token = ""
        for k, v in scope.get("headers") or []:
            if k.decode("latin-1").lower() == HEADER:
                token = v.decode("latin-1")
                break
        try:
            claims = verify(token)
        except IapError as e:
            body = json.dumps({"detail": str(e)}).encode()
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        scope.setdefault("state", {})["iap_email"] = claims.get("email", "")
        await self.app(scope, receive, send)
