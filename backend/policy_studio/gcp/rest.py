"""Read-only REST client over google-auth's AuthorizedSession (Application Default Credentials).

Policy Studio P1/P2 only issues list / get / getIamPolicy / testIamPermissions calls. `Rest.post` is
therefore restricted to an allowlist of read-only RPC suffixes, so a write can't slip in by accident.
"""
from __future__ import annotations

import threading
from functools import lru_cache
from typing import Any

import google.auth
from google.auth.transport.requests import AuthorizedSession

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

NETWORKSERVICES = "https://networkservices.googleapis.com/v1"
NETWORKSECURITY = "https://networksecurity.googleapis.com/v1"
AGENTREGISTRY = "https://agentregistry.googleapis.com/v1"
IAP = "https://iap.googleapis.com/v1"
CRM = "https://cloudresourcemanager.googleapis.com/v1"
SERVICEUSAGE = "https://serviceusage.googleapis.com/v1"
TOKENINFO = "https://oauth2.googleapis.com/tokeninfo"
LOGGING = "https://logging.googleapis.com/v2"

# POST is only used for these read-only RPCs (Cloud Logging's entries:list is a read that uses POST).
READ_ONLY_POSTS = (":getIamPolicy", ":testIamPermissions", ":getAncestry", "/v2/entries:list")


def aiplatform(region: str) -> str:
    return f"https://{region}-aiplatform.googleapis.com/v1"


def modelarmor(region: str) -> str:
    return f"https://modelarmor.{region}.rep.googleapis.com/v1"


class GcpError(Exception):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.url = url

    @property
    def not_found(self) -> bool:
        return self.status == 404


def err_text(e: Exception) -> str:
    """Short, user-facing error text."""
    if isinstance(e, GcpError):
        return f"HTTP {e.status}: {e.message}"[:400]
    return f"{type(e).__name__}: {e}"[:400]


class Rest:
    def __init__(self, credentials: Any = None, quota_project: str | None = None, timeout: float = 30):
        if credentials is None:
            credentials, _ = google.auth.default(scopes=SCOPES)
            if quota_project and hasattr(credentials, "with_quota_project") \
                    and not getattr(credentials, "quota_project_id", None):
                try:
                    credentials = credentials.with_quota_project(quota_project)
                except Exception:  # noqa: BLE001
                    pass
        self.credentials = credentials
        self.timeout = timeout
        self._local = threading.local()

    @property
    def session(self) -> AuthorizedSession:
        s = getattr(self._local, "s", None)
        if s is None:
            s = self._local.s = AuthorizedSession(self.credentials)
        return s

    def _request(self, method: str, url: str, *, json: Any = None, params: dict | None = None,
                 ok404: bool = False) -> Any:
        r = self.session.request(method, url, json=json, params=params, timeout=self.timeout)
        if r.status_code == 404 and ok404:
            return None
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", {}).get("message") or r.text
            except Exception:  # noqa: BLE001
                msg = r.text
            raise GcpError(r.status_code, str(msg)[:1000], url)
        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            return r.text

    def get(self, url: str, params: dict | None = None, ok404: bool = False) -> Any:
        return self._request("GET", url, params=params, ok404=ok404)

    def post(self, url: str, json: Any = None, ok404: bool = False) -> Any:
        if not url.split("?")[0].endswith(READ_ONLY_POSTS):
            raise ValueError(f"policy_studio is read-only; refusing POST {url}")
        return self._request("POST", url, json=json if json is not None else {}, ok404=ok404)

    def list_all(self, url: str, key: str, params: dict | None = None, max_pages: int = 50) -> list[dict]:
        out: list[dict] = []
        p = dict(params or {})
        for _ in range(max_pages):
            r = self.get(url, params=p) or {}
            out += r.get(key, []) or []
            tok = r.get("nextPageToken")
            if not tok:
                break
            p["pageToken"] = tok
        return out

    def principal(self) -> str:
        """The identity behind the credentials (email), best effort."""
        email = getattr(self.credentials, "service_account_email", None)
        if email and email != "default":
            return email
        try:
            if not getattr(self.credentials, "token", None) or not self.credentials.valid:
                from google.auth.transport.requests import Request
                self.credentials.refresh(Request())
            r = self.session.get(TOKENINFO, params={"access_token": self.credentials.token}, timeout=10)
            if r.ok:
                return r.json().get("email", "") or ""
        except Exception:  # noqa: BLE001
            pass
        return email or ""


@lru_cache(maxsize=8)
def client(quota_project: str | None = None) -> Rest:
    """Process-wide client per quota project (ADC)."""
    return Rest(quota_project=quota_project or None)
