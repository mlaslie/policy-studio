"""Context discovery: defaults, project number, API enablement and the caller's permissions (read-only)."""
from __future__ import annotations

import configparser
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

from .rest import CRM, SERVICEUSAGE, GcpError, Rest, err_text

APIS = [
    "networkservices.googleapis.com",
    "networksecurity.googleapis.com",
    "agentregistry.googleapis.com",
    "iap.googleapis.com",
    "aiplatform.googleapis.com",
    "modelarmor.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
]

# (permission, needed_for, role that grants it, write?)
PERMISSIONS: list[tuple[str, str, str, bool]] = [
    ("resourcemanager.projects.get", "look up the project number", "roles/browser", False),
    ("serviceusage.services.list", "check which APIs are enabled", "roles/serviceusage.serviceUsageViewer", False),
    ("networkservices.agentGateways.list", "list Agent Gateways", "roles/networkservices.viewer", False),
    ("networkservices.authzExtensions.list", "list authz extensions (IAP, Model Armor)",
     "roles/networkservices.viewer", False),
    ("networksecurity.authzPolicies.list", "list authz policies attached to gateways",
     "roles/networksecurity.viewer", False),
    ("aiplatform.reasoningEngines.list", "list Agent Runtime agents and their gateway bindings",
     "roles/aiplatform.viewer", False),
    ("agentregistry.agents.list", "list A2A / Runtime agents in Agent Registry", "roles/agentregistry.viewer", False),
    ("agentregistry.mcpServers.list", "list MCP servers in Agent Registry", "roles/agentregistry.viewer", False),
    ("agentregistry.endpoints.list", "list API endpoints in Agent Registry", "roles/agentregistry.viewer", False),
    ("iap.webServiceVersions.getIamPolicy", "read who may reach each Agent Registry entry (IAP IAM)",
     "roles/iap.admin", False),
    ("modelarmor.templates.list", "read Model Armor templates and filters", "roles/modelarmor.viewer", False),
    # Writes (Apply, apply mode only). The Apply checks are in auth.py (WRITE_PERMISSIONS).
    ("iap.webServiceVersions.setIamPolicy", "apply grants / revokes", "roles/iap.admin", True),
    ("aiplatform.reasoningEngines.update", "bind / unbind agents to gateways",
     "roles/aiplatform.user", True),
    ("networksecurity.authzPolicies.create", "turn Model Armor on", "roles/networksecurity.editor",
     True),
    ("networksecurity.authzPolicies.delete", "turn Model Armor off", "roles/networksecurity.editor",
     True),
]

_numbers: dict[str, str] = {}
_lock = threading.Lock()


# ------------------------------------------------------------------ defaults
def _gcloud_config_dir() -> Path:
    env = os.environ.get("CLOUDSDK_CONFIG")
    return Path(env) if env else Path.home() / ".config" / "gcloud"


def gcloud_defaults() -> dict[str, str]:
    """{project, region} from the active gcloud configuration (file read; `gcloud config` as fallback)."""
    out = {"project": "", "region": ""}
    d = _gcloud_config_dir()
    try:
        name = os.environ.get("CLOUDSDK_ACTIVE_CONFIG_NAME") or (d / "active_config").read_text().strip() or "default"
        cp = configparser.ConfigParser()
        cp.read(d / "configurations" / f"config_{name}")
        out["project"] = cp.get("core", "project", fallback="") or ""
        out["region"] = cp.get("compute", "region", fallback="") or ""
    except Exception:  # noqa: BLE001
        pass
    if not out["project"] and shutil.which("gcloud"):
        for key, prop in (("project", "core/project"), ("region", "compute/region")):
            try:
                out[key] = subprocess.run(["gcloud", "config", "get-value", prop], capture_output=True, text=True,
                                          timeout=15).stdout.strip()
            except Exception:  # noqa: BLE001
                pass
    return out


def defaults() -> dict[str, str]:
    g = gcloud_defaults()
    return {"project": os.environ.get("STUDIO_PROJECT") or g["project"],
            "region": os.environ.get("STUDIO_REGION") or g["region"] or "us-central1"}


# ------------------------------------------------------------------ project
def project_number(r: Rest, project: str) -> str:
    if project.isdigit():
        return project
    with _lock:
        if project in _numbers:
            return _numbers[project]
    num = str(r.get(f"{CRM}/projects/{project}")["projectNumber"])
    with _lock:
        _numbers[project] = num
    return num


def organization_id(r: Rest, project: str) -> str | None:
    res = r.post(f"{CRM}/projects/{project}:getAncestry")
    for a in res.get("ancestor", []):
        if a.get("resourceId", {}).get("type") == "organization":
            return a["resourceId"]["id"]
    return None


def enabled_apis(r: Rest, project: str) -> dict[str, bool]:
    items = r.list_all(f"{SERVICEUSAGE}/projects/{project}/services", "services",
                       params={"filter": "state:ENABLED", "pageSize": 200})
    on = {s.get("config", {}).get("name") for s in items}
    return {a: a in on for a in APIS}


def test_permissions(r: Rest, project: str, perms: list[str]) -> dict[str, bool | None]:
    """{permission: granted}; a permission the API rejects as unknown maps to None (not checked)."""
    url = f"{CRM}/projects/{project}:testIamPermissions"
    try:
        got = set(r.post(url, json={"permissions": perms}).get("permissions", []))
        return {p: p in got for p in perms}
    except GcpError as e:
        if e.status != 400:
            raise
    out: dict[str, bool | None] = {}
    for p in perms:                     # one bad permission name fails the batch: test individually
        try:
            out[p] = p in set(r.post(url, json={"permissions": [p]}).get("permissions", []))
        except GcpError as e:
            if e.status != 400:
                raise
            out[p] = None
    return out


def fix_command(project: str, principal: str, role: str) -> str:
    member = principal if ":" in principal else (
        f"serviceAccount:{principal}" if principal.endswith("gserviceaccount.com") else f"user:{principal or 'YOU@EXAMPLE.COM'}")
    return f"gcloud projects add-iam-policy-binding {project} --member='{member}' --role={role}"


def permissions_report(r: Rest, project: str, principal: str, gateway_project: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    projects = [project] + ([gateway_project] if gateway_project and gateway_project != project else [])
    for proj in projects:
        perms = [p for p, *_ in PERMISSIONS]
        try:
            res = test_permissions(r, proj, perms)
            err = None
        except Exception as e:  # noqa: BLE001
            res, err = {}, err_text(e)
        for perm, needed, role, write in PERMISSIONS:
            granted = res.get(perm)
            item: dict[str, Any] = {"permission": perm, "granted": granted, "needed_for": needed,
                                    "role": role, "write": write, "project": proj,
                                    "fix": None if granted else fix_command(proj, principal, role)}
            if granted is None:
                item["error"] = err or "permission not recognized by testIamPermissions"
            out.append(item)
    return out
