"""IAP signed-header check on Cloud Run (iap.py). verify_token and the metadata server are faked: no network."""
import pytest
from fastapi.testclient import TestClient

import fakegcp as F
from policy_studio import iap, service
from policy_studio.app import create_app

AUD = "/projects/123/locations/us-east4/services/policy-studio"


@pytest.fixture
def seen(monkeypatch):
    rest = F.FakeRest()
    monkeypatch.setattr(service, "rest_for", lambda ctx: rest)
    monkeypatch.setenv("STUDIO_PROJECT", F.P)
    monkeypatch.setenv("STUDIO_REGION", F.R)
    monkeypatch.setenv("K_SERVICE", "policy-studio")
    monkeypatch.delenv("STUDIO_IAP_AUDIENCE", raising=False)
    iap.reset()
    calls: dict = {"verify": [], "metadata": []}

    def verify_token(token, aud):
        calls["verify"].append((token, aud))
        if token == "good":
            return {"iss": iap.ISSUER, "aud": aud, "email": "alice@example.com"}
        if token == "other-issuer":
            return {"iss": "https://accounts.google.com", "aud": aud, "email": "alice@example.com"}
        raise ValueError("Token has wrong audience")

    def metadata_get(path):
        calls["metadata"].append(path)
        return {"project/numeric-project-id": "123", "instance/region": "projects/123/regions/us-east4"}[path]

    monkeypatch.setattr(iap, "verify_token", verify_token)
    monkeypatch.setattr(iap, "metadata_get", metadata_get)
    yield calls
    iap.reset()


def test_api_needs_a_valid_assertion_on_cloud_run(seen):
    c = TestClient(create_app())
    r = c.get("/api/studio/defaults")
    assert r.status_code == 401 and "x-goog-iap-jwt-assertion" in r.json()["detail"]
    r = c.get("/api/studio/defaults", headers={iap.HEADER: "forged"})
    assert r.status_code == 401 and "invalid IAP assertion" in r.json()["detail"]
    r = c.get("/api/studio/defaults", headers={iap.HEADER: "other-issuer"})
    assert r.status_code == 401 and "issuer" in r.json()["detail"]
    r = c.get("/api/studio/defaults", headers={iap.HEADER: "good"})
    assert r.status_code == 200 and r.json()["project"] == F.P
    assert seen["verify"][-1] == ("good", AUD)


def test_forged_user_header_alone_is_refused(seen):
    r = TestClient(create_app()).get("/api/studio/defaults",
                                     headers={"x-goog-authenticated-user-email": "accounts.google.com:x@example.com"})
    assert r.status_code == 401


def test_audience_from_metadata_is_cached(seen):
    c = TestClient(create_app())
    for _ in range(3):
        assert c.get("/api/studio/defaults", headers={iap.HEADER: "good"}).status_code == 200
    assert seen["metadata"] == ["project/numeric-project-id", "instance/region"]     # read once


def test_audience_env_override(seen, monkeypatch):
    monkeypatch.setenv("STUDIO_IAP_AUDIENCE", "/projects/123/global/backendServices/987")
    assert TestClient(create_app()).get("/api/studio/defaults", headers={iap.HEADER: "good"}).status_code == 200
    assert seen["verify"][-1][1] == "/projects/123/global/backendServices/987" and not seen["metadata"]


def test_metadata_failure_is_401(seen, monkeypatch):
    def down(path):
        raise ConnectionError("no metadata server")
    monkeypatch.setattr(iap, "metadata_get", down)
    r = TestClient(create_app()).get("/api/studio/defaults", headers={iap.HEADER: "good"})
    assert r.status_code == 401 and "STUDIO_IAP_AUDIENCE" in r.json()["detail"]


def test_health_and_ui_are_open(seen, tmp_path, monkeypatch):
    (tmp_path / "index.html").write_text("<html>studio</html>")
    monkeypatch.setenv("STUDIO_FRONTEND_DIST", str(tmp_path))
    c = TestClient(create_app())
    assert c.get("/api/studio/health").json()["ok"] is True
    assert c.get("/").text == "<html>studio</html>"
    assert not seen["verify"]


def test_not_checked_off_cloud_run(seen, monkeypatch):
    monkeypatch.delenv("K_SERVICE")
    assert TestClient(create_app()).get("/api/studio/defaults").status_code == 200
    assert not seen["verify"]


def test_verify_token_uses_iap_keys(monkeypatch):
    from google.oauth2 import id_token
    got = {}

    def fake(token, request, audience=None, certs_url=None):
        got.update(token=token, audience=audience, certs_url=certs_url, request=request)
        return {"iss": iap.ISSUER}
    monkeypatch.setattr(id_token, "verify_token", fake)
    assert iap.verify_token("t", AUD) == {"iss": iap.ISSUER}
    assert got["audience"] == AUD and got["certs_url"] == "https://www.gstatic.com/iap/verify/public_key"
    assert callable(got["request"])
