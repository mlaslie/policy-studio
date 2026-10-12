"""Credential checks for Apply (GET /api/studio/auth). Read-only: nothing is written, no login is started.

  ADC         google.auth.default(): type, account (tokeninfo / service_account_email), quota project, project,
              source (GOOGLE_APPLICATION_CREDENTIALS / well-known file / metadata server), token refresh
  gcloud      `gcloud config get-value account|project` when the CLI is installed (never fails the request)
  can_write   testIamPermissions on the target project(s) for the write permissions of each intent kind

The pieces that touch the machine (load_adc, refresh, tokeninfo_email, gcloud_info) are module functions so tests
can replace them.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Optional

from .discovery import test_permissions
from .rest import SCOPES, TOKENINFO, err_text

ADC_LOGIN = "gcloud auth application-default login"

# intent kinds -> (write permissions, any_of?, which project: "gateway" | "project" | "both")
# IAP on Agent Registry entries: which of the iap.* setIamPolicy permissions IAP checks for the agentRegistry
# resource isn't documented; roles/iap.admin has all of them, so any one counts.
IAP_SET = ["iap.web.setIamPolicy", "iap.webTypes.setIamPolicy", "iap.webServices.setIamPolicy",
           "iap.webServiceVersions.setIamPolicy"]
WRITE_PERMISSIONS: dict[str, tuple[list[str], bool, str, str]] = {
    "grant": (IAP_SET, True, "gateway", "roles/iap.admin"),
    "revoke": (IAP_SET, True, "gateway", "roles/iap.admin"),
    "modify": (IAP_SET, True, "gateway", "roles/iap.admin"),
    "bind_gateway": (["aiplatform.reasoningEngines.update"], False, "project", "roles/aiplatform.user"),
    "unbind_gateway": (["aiplatform.reasoningEngines.update"], False, "project", "roles/aiplatform.user"),
    "model_armor_on": (["networksecurity.authzPolicies.create"], False, "both", "roles/networksecurity.editor"),
    "model_armor_off": (["networksecurity.authzPolicies.delete"], False, "both", "roles/networksecurity.editor"),
    "model_armor_template": (["modelarmor.templates.create"], False, "both", "roles/modelarmor.admin"),
    "model_armor_extension": (["networkservices.authzExtensions.create"], False, "both",
                              "roles/networkservices.admin"),
    "iam_project_grant": (["resourcemanager.projects.setIamPolicy"], False, "both",
                          "roles/resourcemanager.projectIamAdmin"),
    "set_enforcement": (["networkservices.authzExtensions.update"], False, "both", "roles/networkservices.admin"),
    "dedicate_extension": (["networkservices.authzExtensions.create", "networksecurity.authzPolicies.update"], False,
                           "both", "roles/networkservices.admin roles/networksecurity.editor"),
}
KIND_LABEL = {"grant": "grants", "revoke": "revokes", "modify": "grant changes", "bind_gateway": "gateway binds",
              "unbind_gateway": "gateway unbinds", "model_armor_on": "Model Armor on",
              "model_armor_off": "Model Armor off", "model_armor_template": "Model Armor templates",
              "model_armor_extension": "Model Armor extensions",
              "iam_project_grant": "service agent role grants",
              "set_enforcement": "enforcement mode changes", "dedicate_extension": "dedicated IAP extensions"}


# ------------------------------------------------------------------ machine-facing pieces (replaced in tests)
def load_adc() -> tuple[Any, Optional[str]]:
    """google.auth.default(); raises google.auth.exceptions.DefaultCredentialsError when there is no ADC."""
    import google.auth
    return google.auth.default(scopes=SCOPES)


def refresh(creds: Any) -> None:
    from google.auth.transport.requests import Request
    creds.refresh(Request())


def tokeninfo_email(creds: Any) -> str:
    import requests
    r = requests.get(TOKENINFO, params={"access_token": creds.token}, timeout=10)
    return (r.json().get("email") or "") if r.ok else ""


GCLOUD_CANDIDATES = ["~/google-cloud-sdk/bin/gcloud", "~/Downloads/google-cloud-sdk/bin/gcloud",
                     "/opt/homebrew/bin/gcloud", "/usr/local/bin/gcloud", "/usr/bin/gcloud", "/snap/bin/gcloud"]


def gcloud_binary() -> Optional[str]:
    """$GCLOUD / $STUDIO_GCLOUD, then PATH, then $CLOUDSDK_ROOT_DIR/bin/gcloud, then common install locations."""
    cands = [os.environ.get("GCLOUD"), os.environ.get("STUDIO_GCLOUD"), shutil.which("gcloud")]
    root = os.environ.get("CLOUDSDK_ROOT_DIR")
    if root:
        cands.append(str(Path(root) / "bin" / "gcloud"))
    cands += [str(Path(c).expanduser()) for c in GCLOUD_CANDIDATES]
    for c in cands:
        if c and (shutil.which(c) or (os.path.isfile(c) and os.access(c, os.X_OK))):
            return shutil.which(c) or c
    return None


def _gcloud_get(binary: str, prop: str) -> str:
    try:
        out = subprocess.run([binary, "config", "get-value", prop], capture_output=True, text=True, timeout=15)
        v = out.stdout.strip().splitlines()
        return v[-1].strip() if v and v[-1].strip() != "(unset)" else ""
    except Exception:  # noqa: BLE001  (timeout, broken install): never fail the request
        return ""


def gcloud_info() -> dict[str, Any]:
    b = gcloud_binary()
    if not b:
        return {"available": False, "account": "", "project": ""}
    with ThreadPoolExecutor(max_workers=2) as pool:
        fa = pool.submit(_gcloud_get, b, "account")
        fp = pool.submit(_gcloud_get, b, "project")
        return {"available": True, "account": fa.result(), "project": fp.result()}


# ------------------------------------------------------------------ ADC
def cred_type(creds: Any) -> str:
    def isa(mod: str, cls: str) -> bool:
        try:
            m = __import__(mod, fromlist=[cls])
            return isinstance(creds, getattr(m, cls))
        except Exception:  # noqa: BLE001
            return False
    if isa("google.auth.impersonated_credentials", "Credentials"):
        return "impersonated"
    if isa("google.oauth2.service_account", "Credentials"):
        return "service_account"
    if isa("google.auth.compute_engine", "Credentials"):
        return "compute_engine"
    if isa("google.auth.external_account", "Credentials") or \
            isa("google.auth.external_account_authorized_user", "Credentials"):
        return "external_account"
    if isa("google.oauth2.credentials", "Credentials"):
        return "user"
    return "unknown"


def well_known_file() -> Path:
    d = os.environ.get("CLOUDSDK_CONFIG")
    return (Path(d) if d else Path.home() / ".config" / "gcloud") / "application_default_credentials.json"


def _tilde(p: str) -> str:
    home = str(Path.home())
    return "~" + p[len(home):] if p.startswith(home + os.sep) else p


def adc_source(ctype: str) -> str:
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if gac:
        return f"GOOGLE_APPLICATION_CREDENTIALS={_tilde(gac)}"
    if ctype == "compute_engine":
        return "metadata server"
    wk = well_known_file()
    if wk.is_file():
        return _tilde(str(wk))
    return "metadata server" if os.environ.get("K_SERVICE") else "unknown"


def adc_info() -> tuple[dict[str, Any], Any]:
    """({ok, type, account, quota_project, adc_project, source, error, present, valid}, credentials or None)."""
    from google.auth.exceptions import DefaultCredentialsError

    out: dict[str, Any] = {"ok": False, "type": "unknown", "account": "", "quota_project": "", "adc_project": "",
                           "source": "", "error": None, "present": False, "valid": False}
    try:
        creds, project = load_adc()
    except DefaultCredentialsError as e:
        out["error"] = f"No Application Default Credentials: {str(e).splitlines()[0][:300]}"
        return out, None
    except Exception as e:  # noqa: BLE001
        out["error"] = f"Loading Application Default Credentials failed: {err_text(e)}"
        return out, None
    out["present"] = True
    ctype = cred_type(creds)
    out.update(type=ctype, adc_project=project or "", source=adc_source(ctype),
               quota_project=getattr(creds, "quota_project_id", None) or "")
    try:
        refresh(creds)
        out["valid"] = True
    except Exception as e:  # noqa: BLE001
        out["error"] = f"The credentials don't refresh: {err_text(e)}"
        return out, creds
    email = getattr(creds, "service_account_email", None)
    if not email or email == "default":
        try:
            email = tokeninfo_email(creds) or ""
        except Exception:  # noqa: BLE001
            email = ""
    out["account"] = email or ""
    out["ok"] = True
    return out, creds


# ------------------------------------------------------------------ write permissions
def writable_kinds(rest: Any, project: str, gateway_project: str = "") -> tuple[dict[str, bool | None], list[str],
                                                                                dict[str, dict[str, bool | None]]]:
    """({kind: writable (None = unknown)}, errors, {project: {permission: granted}})."""
    gw = gateway_project or project
    projects = list(dict.fromkeys([project, gw]))
    perms = sorted({p for ps, *_ in WRITE_PERMISSIONS.values() for p in ps})
    granted: dict[str, dict[str, bool | None]] = {}
    errors: list[str] = []
    for proj in projects:
        try:
            granted[proj] = test_permissions(rest, proj, perms)
        except Exception as e:  # noqa: BLE001
            errors.append(f"testIamPermissions on {proj}: {err_text(e)}")
    out: dict[str, bool | None] = {}
    for kind, (ps, any_of, where, _role) in WRITE_PERMISSIONS.items():
        targets = {"gateway": [gw], "project": [project], "both": projects}[where]
        vals: list[bool | None] = []
        for proj in targets:
            if proj not in granted:
                vals.append(None)
                continue
            g = [granted[proj].get(p) for p in ps]
            vals.append(any(x is True for x in g) if any_of else (all(x is True for x in g) if None not in g
                                                                   else None))
        out[kind] = False if False in vals else (None if None in vals else True)
    return out, errors, granted


# ------------------------------------------------------------------ report
def _check(cid: str, status: str, title: str, detail: str = "", fix: Optional[str] = None) -> dict[str, Any]:
    return {"id": cid, "status": status, "title": title, "detail": detail, "fix": fix}


def _member(account: str, ctype: str) -> str:
    if not account:
        return "user:YOU@EXAMPLE.COM"
    return f"serviceAccount:{account}" if ctype in ("service_account", "impersonated", "compute_engine") \
        or account.endswith("gserviceaccount.com") else f"user:{account}"


def report(target: str, *, mode: str, runtime: str, generate_reason: str, gateway_project: str = "",
           rest_factory: Optional[Callable[[], Any]] = None) -> dict[str, Any]:
    adc, creds = adc_info()
    gc = gcloud_info()
    checks: list[dict[str, Any]] = []

    # ADC present / valid
    if not adc["present"]:
        checks.append(_check("adc_present", "error", "No Application Default Credentials",
                             (adc["error"] or "") + " Apply calls Google APIs with ADC, separate from your gcloud "
                             "CLI login.", ADC_LOGIN))
    else:
        checks.append(_check("adc_present", "ok", "Application Default Credentials found",
                             f"{adc['type']} credentials from {adc['source'] or 'unknown source'}."))
        if adc["valid"]:
            checks.append(_check("adc_valid", "ok", "Credentials are valid", "The access token refreshes."))
        else:
            checks.append(_check("adc_valid", "error", "Credentials don't refresh",
                                 (adc["error"] or "") + " They may have expired or been revoked.", ADC_LOGIN))

    if adc["ok"]:
        # account vs gcloud
        acct, gacct = adc["account"], gc.get("account", "")
        if not gc["available"]:
            checks.append(_check("account_matches_gcloud", "ok", "Acting as " + (acct or "an unknown account"),
                                 "The gcloud CLI isn't installed here, so ADC is the only identity in play."))
        elif not gacct or not acct:
            checks.append(_check("account_matches_gcloud", "warn", "Couldn't compare ADC with gcloud",
                                 f"ADC account: {acct or 'unknown'}; gcloud account: {gacct or 'not set'}."))
        elif acct.lower() != gacct.lower():
            checks.append(_check("account_matches_gcloud", "warn", "ADC and gcloud use different accounts",
                                 f"Apply acts as {acct} (ADC), but gcloud is logged in as {gacct}. Changes and audit "
                                 "logs will show the ADC account.", ADC_LOGIN))
        else:
            checks.append(_check("account_matches_gcloud", "ok", f"Acting as {acct}",
                                 "ADC and gcloud use the same account."))

        # quota project
        qp, fix_q = adc["quota_project"], f"gcloud auth application-default set-quota-project {target}"
        user_like = adc["type"] in ("user", "external_account")
        if not qp and user_like:
            checks.append(_check("quota_project", "warn", "No quota project on your ADC",
                                 f"Some APIs reject user credentials without a quota project. Policy Studio sends "
                                 f"{target} as the quota project, but setting it on ADC avoids surprises.", fix_q))
        elif not qp:
            checks.append(_check("quota_project", "ok", "Quota project: the service account's own project",
                                 "Service account credentials bill and rate-limit against their own project."))
        elif qp != target:
            checks.append(_check("quota_project", "warn", f"Quota project is {qp}, not {target}",
                                 f"API calls are billed and rate-limited against {qp}, and its enabled APIs apply.",
                                 fix_q if user_like else None))
        else:
            checks.append(_check("quota_project", "ok", f"Quota project is {target}"))

    # project match (ADC project and gcloud project vs target)
    seen = [(k, v) for k, v in (("ADC", adc.get("adc_project", "")), ("gcloud", gc.get("project", ""))) if v]
    off = [(k, v) for k, v in seen if v != target]
    fix_p = f"gcloud config set project {target}"
    if not seen:
        checks.append(_check("project_matches", "ok", f"Target project {target}",
                             "No default project is configured to compare with; Apply always names the target "
                             "project explicitly."))
    elif off:
        checks.append(_check("project_matches", "warn", f"Your default project isn't {target}",
                             "; ".join(f"{k} project: {v}" for k, v in off) + f". Apply always targets {target} "
                             "explicitly, but check you're working in the project you mean.", fix_p))
    else:
        checks.append(_check("project_matches", "ok", f"Working in {target}",
                             " and ".join(k for k, _ in seen) + " default project matches."))

    writable: dict[str, bool | None] = {}
    if adc["ok"]:
        try:
            rest = rest_factory() if rest_factory else None
            writable, errs, _granted = writable_kinds(rest, target, gateway_project) if rest is not None else \
                ({}, ["no client"], {})
        except Exception as e:  # noqa: BLE001
            writable, errs = {}, [err_text(e)]
        yes = [k for k, v in writable.items() if v]
        no = [k for k, v in writable.items() if v is False]
        lines: list[str] = []
        for k in no:
            _perms, _any, where, role = WRITE_PERMISSIONS[k]
            proj = (gateway_project or target) if where == "gateway" else target
            for r in role.split():             # (a kind may need two roles, space-separated)
                line = (f"gcloud projects add-iam-policy-binding {proj} "
                        f"--member='{_member(adc['account'], adc['type'])}' --role={r}")
                if line not in lines:
                    lines.append(line)
        role_fix = "\n".join(lines) or None
        if errs and not writable:
            checks.append(_check("can_write", "warn", "Couldn't check write permissions", "; ".join(errs)))
        elif not yes:
            checks.append(_check("can_write", "error", f"No write permissions in {target}",
                                 f"{adc['account'] or 'These credentials'} can't apply any change here.", role_fix))
        elif no or errs:
            checks.append(_check("can_write", "warn", "Some changes can't be applied",
                                 "Can apply: " + ", ".join(KIND_LABEL[k] for k in yes) + ". Can't: "
                                 + ", ".join(KIND_LABEL[k] for k in no) + ("; " + "; ".join(errs) if errs else ""),
                                 role_fix))
        else:
            checks.append(_check("can_write", "ok", "Can apply every kind of change",
                                 "Grants, revokes, gateway binds, Model Armor and its setup, enforcement mode."))

    errors = [c for c in checks if c["status"] == "error"]
    can_apply = mode == "apply" and not errors
    reason = "" if can_apply else (generate_reason if mode != "apply" else errors[0]["title"])
    adc_out = {k: adc[k] for k in ("ok", "type", "account", "quota_project", "adc_project", "source", "error")}
    return {"mode": mode, "runtime": runtime, "adc": adc_out, "gcloud": gc, "target_project": target,
            "gateway_project": gateway_project or target, "checks": checks,
            "writable": {k: v for k, v in writable.items()},
            "can_apply": can_apply, "can_apply_reason": reason}
