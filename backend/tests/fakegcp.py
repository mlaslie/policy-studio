"""A fake read-only GCP (URL -> JSON) for a small project, and helpers to build inventories."""
from __future__ import annotations

import copy
import json
from typing import Any

from policy_studio.gcp.rest import READ_ONLY_POSTS, GcpError

P, N, R = "acme-prod", "4242", "europe-west4"
ORG = "777"
TD = f"agents.global.org-{ORG}.system.id.goog"


def principal(eid: str, number: str = N, region: str = R) -> str:
    return f"principal://{TD}/resources/aiplatform/projects/{number}/locations/{region}/reasoningEngines/{eid}"


PROJECT_SET = f"principalSet://{TD}/attribute.platformContainer/aiplatform/projects/{N}"
E1, E2, E3 = (f"projects/{N}/locations/{R}/reasoningEngines/{i}" for i in ("111", "222", "333"))
EG = f"projects/{P}/locations/{R}/agentGateways/corp-out"
IG = f"projects/{P}/locations/{R}/agentGateways/corp-in"
AGENT_A = f"projects/{P}/locations/{R}/agents/agentregistry-aaa"
AGENT_RT = f"projects/{P}/locations/{R}/agents/agentregistry-rt1"
MCP = f"projects/{P}/locations/{R}/mcpServers/agentregistry-mcp"
MCP_RO = f"projects/{P}/locations/{R}/mcpServers/agentregistry-ro"
EP = f"projects/{P}/locations/{R}/endpoints/agentregistry-ep"
RO_EXPR = ("api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true || "
           "api.getAttribute('iap.googleapis.com/mcp.toolName', '') == ''")

ENGINES = [
    {"name": E1, "displayName": "HR Assistant", "createTime": "2026-10-01T10:00:00Z",
     "spec": {"effectiveIdentity": principal("111").removeprefix("principal://"), "identityType": "AGENT_IDENTITY",
              "deploymentSpec": {"agentGatewayConfig": {"agentToAnywhereConfig": {"agentGateway": EG}}}}},
    {"name": E2, "displayName": "Pricing Analyst", "createTime": "2026-09-01T10:00:00Z",
     "spec": {"effectiveIdentity": principal("222").removeprefix("principal://"), "identityType": "AGENT_IDENTITY",
              "deploymentSpec": {}}},
    {"name": E3, "displayName": "Legacy Bot", "createTime": "2026-01-15T10:00:00Z",
     "spec": {"effectiveIdentity": f"service-{N}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"}},
]

EXTENSIONS = [
    {"name": f"projects/{P}/locations/{R}/authzExtensions/corp-out-iap", "service": "iap.googleapis.com",
     "metadata": {"iapPolicyVersion": "V1", "iamEnforcementMode": "DRY_RUN"}, "failOpen": True},
    {"name": f"projects/{P}/locations/{R}/authzExtensions/corp-ma", "service": f"modelarmor.{R}.rep.googleapis.com",
     "metadata": {"model_armor_settings": json.dumps([{
         "request_template_id": f"projects/{P}/locations/{R}/templates/strict",
         "response_template_id": f"projects/{P}/locations/{R}/templates/strict"}])}},
]

POLICIES = [
    {"name": f"projects/{P}/locations/{R}/authzPolicies/corp-out-iap-policy", "policyProfile": "REQUEST_AUTHZ",
     "action": "CUSTOM", "target": {"resources": [f"projects/{N}/locations/{R}/agentGateways/corp-out"]},
     "customProvider": {"authzExtension": {"resources": [f"projects/{N}/locations/{R}/authzExtensions/corp-out-iap"]}}},
    {"name": f"projects/{P}/locations/{R}/authzPolicies/corp-in-ma", "policyProfile": "CONTENT_AUTHZ",
     "action": "CUSTOM", "target": {"resources": [f"projects/{N}/locations/{R}/agentGateways/corp-in"]},
     "customProvider": {"authzExtension": {"resources": [f"projects/{N}/locations/{R}/authzExtensions/corp-ma"]}}},
]

DEP_SA = "service-9090@gcp-sa-dep.iam.gserviceaccount.com"         # egress gateway's service extensions SA
RE_SA = f"service-{N}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"  # Agent Runtime service agent (ingress)
GATEWAYS = [
    {"name": EG, "createTime": "2026-08-01T00:00:00Z", "googleManaged": {"governedAccessPath": "AGENT_TO_ANYWHERE"},
     "agentGatewayCard": {"serviceExtensionsServiceAccount": DEP_SA},
     "registries": [f"//agentregistry.googleapis.com/projects/{P}/locations/{R}"]},
    {"name": IG, "createTime": "2026-08-01T00:00:00Z", "googleManaged": {"governedAccessPath": "CLIENT_TO_AGENT"}},
]

TEMPLATE = {"name": f"projects/{P}/locations/{R}/templates/strict",
            "filterConfig": {"piAndJailbreakFilterSettings": {"filterEnforcement": "ENABLED",
                                                              "confidenceLevel": "HIGH"},
                             "sdpSettings": {"advancedConfig": {"inspectTemplate": "x"}},
                             "raiSettings": {"raiFilters": [{"filterType": "HARASSMENT",
                                                             "confidenceLevel": "MEDIUM_AND_ABOVE"}]}},
            "templateMetadata": {"customPromptSafetyErrorMessage": "Blocked by policy"}}

AGENTS = [
    {"name": AGENT_A, "displayName": "KB Agent", "protocols": [{"type": "A2A_AGENT", "interfaces": [
        {"url": "https://kb.example.com"}]}], "skills": [{"id": "search", "name": "Search", "description": "kb"}]},
    {"name": AGENT_RT, "displayName": "HR Assistant", "attributes": {
        "agentregistry.googleapis.com/system/RuntimeReference": {"uri": f"//aiplatform.googleapis.com/{E1}"}}},
]
MCPS = [
    {"name": MCP, "displayName": "Tickets MCP", "interfaces": [{"url": "https://tickets.example.com/mcp"}],
     "tools": [{"name": "list_tickets", "annotations": {"readOnlyHint": True}},
               {"name": "delete_ticket", "annotations": {"destructiveHint": True}},
               {"name": "add_note", "annotations": {"destructiveHint": False}}]},
    {"name": MCP_RO, "displayName": "Directory MCP", "tools": [{"name": "lookup", "annotations": {"readOnlyHint": True}}]},
]
ENDPOINTS = [{"name": EP, "displayName": "Weather API", "interfaces": [{"url": "https://api.weather.example"}]}]

IAP_POLICIES = {
    "agents/agentregistry-aaa": {"bindings": [{"role": "roles/iap.egressor", "members": ["allUsers", principal("111")]}]},
    "agents/agentregistry-rt1": {},
    "mcpServers/agentregistry-mcp": {"version": 3, "bindings": [
        {"role": "roles/iap.egressor", "members": [principal("111")]},
        {"role": "roles/iap.egressor", "members": [principal("999")],
         "condition": {"title": "ro", "expression": RO_EXPR}}]},
    "mcpServers/agentregistry-ro": {"bindings": [{"role": "roles/iap.egressor", "members": [PROJECT_SET]}]},
    "endpoints/agentregistry-ep": {"bindings": [{"role": "roles/iap.egressor", "members": [PROJECT_SET]}]},
    "": {},
}


# Project IAM policy: the egress gateway's SA holds two of the three Model Armor roles; the ingress one none.
PROJECT_POLICY = {"version": 1, "etag": "p0", "bindings": [
    {"role": "roles/owner", "members": ["user:alice@example.com"]},
    {"role": "roles/modelarmor.calloutUser", "members": [f"serviceAccount:{DEP_SA}"]},
    {"role": "roles/modelarmor.user", "members": [f"serviceAccount:{DEP_SA}"]},
    {"role": "roles/serviceusage.serviceUsageConsumer", "members": [f"serviceAccount:{DEP_SA}"],
     "condition": {"title": "t", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]}


class FakeRest:
    """Answers the read-only URLs policy_studio issues; records every call.

    `model_armor=False` simulates a region where Model Armor isn't set up: no Model Armor extension, no template,
    no CONTENT_AUTHZ policy.
    """

    def __init__(self, fail: dict[str, int] | None = None, model_armor: bool = True):
        self.calls: list[tuple[str, str]] = []
        self.fail = fail or {}
        self.model_armor = model_armor

    def _maybe_fail(self, url: str) -> None:
        for frag, status in self.fail.items():
            if frag in url:
                raise GcpError(status, f"simulated failure for {frag}", url)

    def get(self, url: str, params: dict | None = None, ok404: bool = False) -> Any:
        self.calls.append(("GET", url))
        self._maybe_fail(url)
        if url.endswith(f"/projects/{P}") and "cloudresourcemanager" in url:
            return {"projectNumber": N}
        if "/templates/strict" in url:
            return copy.deepcopy(TEMPLATE)
        if ok404:
            return None
        raise GcpError(404, "not found", url)

    def list_all(self, url: str, key: str, params: dict | None = None) -> list[dict]:
        self.calls.append(("LIST", url))
        self._maybe_fail(url)
        data = {"agentGateways": GATEWAYS, "authzExtensions": EXTENSIONS, "authzPolicies": POLICIES,
                "reasoningEngines": ENGINES, "agents": AGENTS, "mcpServers": MCPS, "endpoints": ENDPOINTS,
                "templates": [TEMPLATE],
                "services": [{"config": {"name": n}} for n in ("networkservices.googleapis.com",
                                                               "agentregistry.googleapis.com",
                                                               "iap.googleapis.com")]}
        if f"/projects/{P}/" not in url and f"/projects/{N}/" not in url:
            return []
        if not self.model_armor:
            data["authzExtensions"] = [x for x in EXTENSIONS if x["service"] == "iap.googleapis.com"]
            data["authzPolicies"] = [x for x in POLICIES if x["policyProfile"] != "CONTENT_AUTHZ"]
            data["templates"] = []
        return copy.deepcopy(data.get(key, []))

    def post(self, url: str, json: Any = None, ok404: bool = False) -> Any:
        assert url.split("?")[0].endswith(READ_ONLY_POSTS), url
        self.calls.append(("POST", url))
        self._maybe_fail(url)
        if url.endswith(":testIamPermissions"):
            return {"permissions": [p for p in json["permissions"] if not p.endswith((".create", ".delete",
                                                                                       ".update", "setIamPolicy"))]}
        if url.endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "organization", "id": ORG}}]}
        if "cloudresourcemanager" in url and url.endswith(":getIamPolicy"):
            return copy.deepcopy(PROJECT_POLICY)
        if url.endswith(":getIamPolicy"):
            path = url.split("/iap_web/agentRegistry", 1)[1].removesuffix(":getIamPolicy").lstrip("/")
            return copy.deepcopy(IAP_POLICIES.get(path, {}))
        raise AssertionError(url)

    def principal(self) -> str:
        return "alice@example.com"


class FakeWriteGcp(FakeRest):
    """FakeRest plus state for Apply: IAP policies with etags, engines, authz policies and long-running operations.

    Writes arrive only through `_request` (the Writer's transport); `post` stays read-only.
    `etag_conflicts` makes the next N setIamPolicy calls fail with 409 ABORTED; `op_polls` is how many GETs an
    operation needs before it is done.
    """

    def __init__(self, fail: dict[str, int] | None = None, etag_conflicts: int = 0, op_polls: int = 1):
        super().__init__(fail)
        self.iap = {k: {**copy.deepcopy(v), "etag": "e0"} for k, v in IAP_POLICIES.items()}
        self.engines = {e["name"]: copy.deepcopy(e) for e in ENGINES}
        self.policies = {p["name"].rsplit("/", 1)[-1]: copy.deepcopy(p) for p in POLICIES}
        self.templates = {TEMPLATE["name"]: copy.deepcopy(TEMPLATE)}
        self.extensions = {x["name"].rsplit("/", 1)[-1]: copy.deepcopy(x) for x in EXTENSIONS}
        self.project_policy = copy.deepcopy(PROJECT_POLICY)
        self.ops: dict[str, int] = {}
        self.etag_conflicts = etag_conflicts
        self.op_polls = op_polls
        self.writes: list[tuple[str, str, Any]] = []
        self._n = 0

    # --- helpers
    def _iap_path(self, url: str, suffix: str) -> str:
        return url.split("/iap_web/agentRegistry", 1)[1].removesuffix(suffix).lstrip("/")

    def _op(self, prefix: str) -> dict:
        self._n += 1
        name = f"{prefix}/operations/op{self._n}"
        self.ops[name] = self.op_polls
        return {"name": name, "done": False}

    # --- reads
    def get(self, url: str, params: dict | None = None, ok404: bool = False) -> Any:
        if "/operations/" in url:
            self.calls.append(("GET", url))
            name = url.split("/v1/", 1)[1]
            self.ops[name] -= 1
            return {"name": name, "done": self.ops[name] <= 0}
        if "/reasoningEngines/" in url and "aiplatform" in url:
            self.calls.append(("GET", url))
            name = url.split("/v1/", 1)[1]
            if name in self.engines:
                return copy.deepcopy(self.engines[name])
        if ".rep.googleapis.com/v1/" in url and "/templates/" in url:
            self.calls.append(("GET", url))
            t = self.templates.get(url.split("/v1/", 1)[1])
            if t is None and not ok404:
                raise GcpError(404, "not found", url)
            return copy.deepcopy(t)
        if "/authzExtensions/" in url:
            self.calls.append(("GET", url))
            x = self.extensions.get(url.rsplit("/", 1)[-1])
            if x is None and not ok404:
                raise GcpError(404, "not found", url)
            return copy.deepcopy(x)
        if "/authzPolicies/" in url:
            self.calls.append(("GET", url))
            pol = self.policies.get(url.rsplit("/", 1)[-1])
            if pol is None:
                if ok404:
                    return None
                raise GcpError(404, "not found", url)
            return copy.deepcopy(pol)
        return super().get(url, params, ok404)

    def list_all(self, url: str, key: str, params: dict | None = None) -> list[dict]:
        if key == "authzPolicies":
            self.calls.append(("LIST", url))
            return copy.deepcopy(list(self.policies.values()))
        if key == "authzExtensions":
            self.calls.append(("LIST", url))
            return copy.deepcopy(list(self.extensions.values()))
        if key == "templates":
            self.calls.append(("LIST", url))
            return copy.deepcopy(list(self.templates.values()))
        return super().list_all(url, key, params)

    def post(self, url: str, json: Any = None, ok404: bool = False) -> Any:
        if url.endswith(":testIamPermissions"):
            assert url.split("?")[0].endswith(READ_ONLY_POSTS)
            self.calls.append(("POST", url))
            self._maybe_fail(url)
            return {"permissions": list(json["permissions"])}
        if "cloudresourcemanager" in url and url.endswith(":getIamPolicy"):
            self.calls.append(("POST", url))
            self._maybe_fail(url)
            return copy.deepcopy(self.project_policy)
        if url.endswith(":getIamPolicy"):
            self.calls.append(("POST", url))
            self._maybe_fail(url)
            return copy.deepcopy(self.iap.get(self._iap_path(url, ":getIamPolicy"), {"etag": "e0"}))
        return super().post(url, json, ok404)

    # --- writes (Writer transport)
    def _request(self, method: str, url: str, *, json: Any = None, params: dict | None = None,
                 ok404: bool = False) -> Any:
        self.writes.append((method, url, copy.deepcopy(json)))
        self._maybe_fail(url)
        if method == "POST" and "cloudresourcemanager" in url and url.endswith(":setIamPolicy"):
            if self.etag_conflicts > 0:
                self.etag_conflicts -= 1
                self.project_policy["etag"] += "x"
                raise GcpError(409, "ABORTED: There were concurrent policy changes.", url)
            pol = json["policy"]
            if pol.get("etag") != self.project_policy.get("etag"):
                raise GcpError(409, "ABORTED: etag mismatch", url)
            self._n += 1
            self.project_policy = {**copy.deepcopy(pol), "etag": f"p{self._n}"}
            return copy.deepcopy(self.project_policy)
        if method == "POST" and "/templates?templateId=" in url:
            base = url.split("/v1/", 1)[1].split("?", 1)[0]
            name = f"{base}/{url.split('templateId=', 1)[1]}"
            if name in self.templates:
                raise GcpError(409, "already exists", url)
            self.templates[name] = {"name": name, **copy.deepcopy(json)}
            return copy.deepcopy(self.templates[name])
        if method == "DELETE" and ".rep.googleapis.com" in url and "/templates/" in url:
            name = url.split("/v1/", 1)[1]
            if any(name in x.get("metadata", {}).get("model_armor_settings", "") for x in self.extensions.values()):
                raise GcpError(400, "FAILED_PRECONDITION: template is in use", url)
            del self.templates[name]
            return {}
        if method == "POST" and "/authzExtensions?authzExtensionId=" in url:
            xid = url.split("authzExtensionId=", 1)[1]
            base = url.split("/v1/", 1)[1].split("?", 1)[0]
            if xid in self.extensions:
                raise GcpError(409, "already exists", url)
            self.extensions[xid] = {"name": f"{base}/{xid}", **copy.deepcopy(json)}
            return self._op(base.rsplit("/authzExtensions", 1)[0])
        if method == "DELETE" and "/authzExtensions/" in url:
            xid = url.rsplit("/", 1)[-1]
            del self.extensions[xid]
            return self._op(url.split("/v1/", 1)[1].rsplit("/authzExtensions", 1)[0])
        if method == "POST" and url.endswith(":setIamPolicy"):
            path = self._iap_path(url, ":setIamPolicy")
            cur = self.iap.setdefault(path, {"etag": "e0"})
            if self.etag_conflicts > 0:
                self.etag_conflicts -= 1
                cur["etag"] = cur["etag"] + "x"            # someone else changed it
                raise GcpError(409, "ABORTED: There were concurrent policy changes.", url)
            pol = json["policy"]
            if pol.get("etag") != cur.get("etag"):
                raise GcpError(409, "ABORTED: etag mismatch", url)
            self._n += 1
            self.iap[path] = {**copy.deepcopy(pol), "etag": f"e{self._n}"}
            return copy.deepcopy(self.iap[path])
        if method == "PATCH" and "/reasoningEngines/" in url:
            name = url.split("/v1/", 1)[1].split("?", 1)[0]
            eng = self.engines[name]
            eng.setdefault("spec", {}).setdefault("deploymentSpec", {})["agentGatewayConfig"] = \
                copy.deepcopy(json["spec"]["deploymentSpec"]["agentGatewayConfig"])
            return self._op(name)
        if method == "POST" and "/authzPolicies?authzPolicyId=" in url:
            pid = url.split("authzPolicyId=", 1)[1]
            base = url.split("/v1/", 1)[1].split("?", 1)[0]
            if pid in self.policies:
                raise GcpError(409, "already exists", url)
            self.policies[pid] = {"name": f"{base}/{pid}", **copy.deepcopy(json)}
            return self._op(base.rsplit("/authzPolicies", 1)[0])
        if method == "DELETE" and "/authzPolicies/" in url:
            pid = url.rsplit("/", 1)[-1]
            del self.policies[pid]
            return self._op(url.split("/v1/", 1)[1].rsplit("/authzPolicies", 1)[0])
        raise AssertionError(f"unexpected write {method} {url}")
