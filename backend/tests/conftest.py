import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))


@pytest.fixture(autouse=True)
def _clear_cache():
    from policy_studio import service

    service.cache.clear()
    yield
    service.cache.clear()


@pytest.fixture(autouse=True)
def _hermetic_credentials(monkeypatch, tmp_path):
    """No real ADC, gcloud or apply log in tests; local (apply) mode unless a test says otherwise."""
    from google.auth.exceptions import DefaultCredentialsError

    from policy_studio.gcp import auth

    def no_adc():
        raise DefaultCredentialsError("Your default credentials were not found (test).")

    monkeypatch.setattr(auth, "load_adc", no_adc)
    monkeypatch.setattr(auth, "gcloud_info", lambda: {"available": False, "account": "", "project": ""})
    monkeypatch.setattr(auth, "tokeninfo_email", lambda creds: "")
    for var in ("K_SERVICE", "STUDIO_MODE", "STUDIO_ALLOW_APPLY_ON_CLOUD_RUN", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("STUDIO_APPLY_LOG", str(tmp_path / "apply-log.jsonl"))
