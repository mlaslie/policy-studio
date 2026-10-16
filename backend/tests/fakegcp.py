"""A fake read-only GCP (URL -> JSON) for a small project, and helpers to build inventories."""
from __future__ import annotations

import copy
import json
import re
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
# Private networking: corp-out reaches corp-vpc through a connectivity template (referenced by project NUMBER).
CT = f"projects/{P}/locations/{R}/agentConnectivityTemplates/corp-tmpl"
ATT = f"projects/{P}/regions/{R}/networkAttachments/corp-att"
CONNECTIVITY_TEMPLATES = {
    "corp-tmpl": {"name": CT, "accessPath": "AGENT_TO_ANYWHERE", "deploymentModel": "CENTRALIZED",
                  "egressNetworkConfig": {"networkAttachment": ATT, "vpcEgress": "PRIVATE_RANGES_ONLY",
                                          "dnsPeeringConfig": {"domains": ["run.app.", "corp.internal."],
                                                               "targetNetwork": f"projects/{P}/global/networks/corp-vpc"}}},
    "vpcsc-tmpl": {"name": f"projects/{P}/locations/{R}/agentConnectivityTemplates/vpcsc-tmpl",
                   "accessPath": "AGENT_TO_ANYWHERE", "egressNetworkConfig": {
                       "networkAttachment": ATT, "vpcEgress": "ALL_TRAFFIC", "tlsConfig": {"trustConfig": "x"},
                       "dnsPeeringConfig": {"domains": ["corp.internal."]}}},
}
NETWORK_ATTACHMENTS = {
    "corp-att": {"name": "corp-att", "network": f"https://www.googleapis.com/compute/v1/projects/{P}/global/networks/corp-vpc",
                 "subnetworks": [f"https://www.googleapis.com/compute/v1/projects/{P}/regions/{R}/subnetworks/att"],
                 "connectionPreference": "ACCEPT_AUTOMATIC", "connectionEndpoints": [{"status": "ACCEPTED"}]},
    "psci-att": {"name": "psci-att", "network": f"https://www.googleapis.com/compute/v1/projects/{P}/global/networks/lab-vpc"},
}
GATEWAYS = [
    {"name": EG, "createTime": "2026-08-01T00:00:00Z", "googleManaged": {"governedAccessPath": "AGENT_TO_ANYWHERE"},
     "agentGatewayCard": {"serviceExtensionsServiceAccount": DEP_SA},
     "agentConnectivityTemplate": f"projects/{N}/locations/{R}/agentConnectivityTemplates/corp-tmpl",
     "registries": [f"//agentregistry.googleapis.com/projects/{P}/locations/{R}"]},
    {"name": IG, "createTime": "2026-08-01T00:00:00Z", "googleManaged": {"governedAccessPath": "CLIENT_TO_AGENT"}},
]

# networking=True adds these: a PSC-interface agent without a gateway (N1), one with both (N2), a gateway with inline
# networkConfig (N3) and one whose template sends ALL_TRAFFIC (N5). N4 = fail={"agentConnectivityTemplates": 403}.
E4, E5 = (f"projects/{N}/locations/{R}/reasoningEngines/{i}" for i in ("444", "555"))
PSCI = {"networkAttachment": f"projects/{P}/regions/{R}/networkAttachments/psci-att"}
NET_ENGINES = [
    {"name": E4, "displayName": "Lab Agent", "createTime": "2026-10-01T10:00:00Z",
     "spec": {"effectiveIdentity": principal("444").removeprefix("principal://"), "identityType": "AGENT_IDENTITY",
              "deploymentSpec": {"pscInterfaceConfig": {**PSCI, "dnsPeeringConfigs": [
                  {"domain": "corp.internal.", "targetProject": P, "targetNetwork": "lab-vpc"}]}}}},
    {"name": E5, "displayName": "Hybrid Agent", "createTime": "2026-10-01T10:00:00Z",
     "spec": {"effectiveIdentity": principal("555").removeprefix("principal://"), "identityType": "AGENT_IDENTITY",
              "deploymentSpec": {"pscInterfaceConfig": PSCI,
                                 "agentGatewayConfig": {"agentToAnywhereConfig": {"agentGateway": EG}}}}},
]
NET_GATEWAYS = [
    {"name": f"projects/{P}/locations/{R}/agentGateways/corp-out-inline", "createTime": "2026-08-01T00:00:00Z",
     "googleManaged": {"governedAccessPath": "AGENT_TO_ANYWHERE"},
     "networkConfig": {"egress": {"networkAttachment": ATT},
                       "dnsPeeringConfig": {"domains": ["run.app."], "targetProject": P,
                                            "targetNetwork": f"projects/{P}/global/networks/corp-vpc"}}},
    {"name": f"projects/{P}/locations/{R}/agentGateways/corp-out-sc", "createTime": "2026-08-01T00:00:00Z",
     "googleManaged": {"governedAccessPath": "AGENT_TO_ANYWHERE"},
     "agentConnectivityTemplate": f"projects/{N}/locations/{R}/agentConnectivityTemplates/vpcsc-tmpl"},
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
# Writable Agent Registry Services behind two of the entries (Directory MCP and the agents have none here).
SVC_TICKETS = f"projects/{P}/locations/{R}/services/tickets-mcp"
SVC_WEATHER = f"projects/{P}/locations/{R}/services/weather-api"
SERVICES = [
    {"name": SVC_TICKETS, "displayName": "Tickets MCP", "description": "ticketing",
     "interfaces": [{"url": "https://tickets.example.com/mcp", "protocolBinding": "JSONRPC"}],
     "mcpServerSpec": {"type": "TOOL_SPEC", "content": {"tools": [{"name": "list_tickets",
                                                                   "annotations": {"readOnlyHint": True}}]}},
     "registryResource": f"projects/{N}/locations/{R}/mcpServers/agentregistry-mcp"},
    {"name": SVC_WEATHER, "displayName": "Weather API",
     "interfaces": [{"url": "https://api.weather.example", "protocolBinding": "HTTP_JSON"}],
     "endpointSpec": {"type": "NO_SPEC"},
     "registryResource": f"projects/{N}/locations/{R}/endpoints/agentregistry-ep"},
]

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
    no CONTENT_AUTHZ policy. `networking=True` adds the private-networking agents and gateways (NET_*).
    """

    def __init__(self, fail: dict[str, int] | None = None, model_armor: bool = True, networking: bool = False):
        self.calls: list[tuple[str, str]] = []
        self.fail = fail or {}
        self.model_armor = model_armor
        self.networking = networking
        self.log_entries: list[dict] = []          # Cloud Logging entries:list answers (newest first)
        self.platform_entries: list[dict] = []     # answers to the caller query (engines' own platform calls)
        self.log_requests: list[dict] = []

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
        if "/agentConnectivityTemplates/" in url and f"/projects/{P}/" in url:   # read by project id only
            t = CONNECTIVITY_TEMPLATES.get(url.rsplit("/", 1)[-1])
            if t:
                return copy.deepcopy(t)
        if "compute.googleapis.com" in url and "/networkAttachments/" in url and f"/projects/{P}/" in url:
            a = NETWORK_ATTACHMENTS.get(url.rsplit("/", 1)[-1])
            if a:
                return copy.deepcopy(a)
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
        if key == "services" and "agentregistry" in url:
            return copy.deepcopy(SERVICES)
        if self.networking:
            data["reasoningEngines"] = ENGINES + NET_ENGINES
            data["agentGateways"] = GATEWAYS + NET_GATEWAYS
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
        if url.endswith("/v2/entries:list"):
            self.log_requests.append(copy.deepcopy(json))
            flt = json.get("filter", "")
            src = self.platform_entries if "httpRequest.requestUrl:" in flt else self.log_entries
            m = re.search(r'NOT jsonPayload\.enforcedGatewaySecurityPolicy\.hostname=~"([^"]*)"', flt)
            if m:                                    # the platform-free query: drop entries whose hostname matches
                rx = re.compile(m.group(1))
                src = [e for e in src if not rx.search(((e.get("jsonPayload") or {}).get(
                    "enforcedGatewaySecurityPolicy") or {}).get("hostname") or "\0")]
            start, size = int(json.get("pageToken") or 0), json.get("pageSize", 50)
            page = {"entries": copy.deepcopy(src[start:start + size])}
            if start + size < len(src):
                page["nextPageToken"] = str(start + size)
            return page
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

    def __init__(self, fail: dict[str, int] | None = None, etag_conflicts: int = 0, op_polls: int = 1,
                 projection_lag: int = 0):
        super().__init__(fail)
        self.services = {x["name"].rsplit("/", 1)[-1]: copy.deepcopy(x) for x in SERVICES}
        self.projection_lag = projection_lag       # GETs of a new Service before registryResource is filled
        self._lag: dict[str, int] = {}
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
        if "agentregistry" in url and "/services/" in url and "/operations/" not in url:
            self.calls.append(("GET", url))
            self._maybe_fail(url)
            sid = url.rsplit("/", 1)[-1]
            svc = self.services.get(sid)
            if svc is None:
                if ok404:
                    return None
                raise GcpError(404, "not found", url)
            svc = copy.deepcopy(svc)
            if self._lag.get(sid, 0) > 0:
                self._lag[sid] -= 1
                svc.pop("registryResource", None)
            return svc
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
        if key == "services" and "agentregistry" in url:
            self.calls.append(("LIST", url))
            return copy.deepcopy(list(self.services.values()))
        if key in ("mcpServers", "endpoints") and "agentregistry" in url:
            # projections follow the Services: a deleted one's entry goes, a created one's appears
            live = {x.get("registryResource", "").rsplit("/", 1)[-1]: x for x in self.services.values()}
            static = {x["registryResource"].rsplit("/", 1)[-1] for x in SERVICES}
            out = [x for x in super().list_all(url, key, params)
                   if x["name"].rsplit("/", 1)[-1] in live or x["name"].rsplit("/", 1)[-1] not in static]
            have = {x["name"].rsplit("/", 1)[-1] for x in out}
            for eid, svc in live.items():
                if eid and eid not in have and svc["registryResource"].split("/")[-2] == key:
                    out.append({"name": f"projects/{P}/locations/{R}/{key}/{eid}", "displayName": svc["displayName"],
                                "interfaces": copy.deepcopy(svc["interfaces"])})
            return out
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
        if url.endswith("/v2/entries:list"):
            return FakeRest.post(self, url, json, ok404)
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
        if method == "POST" and "agentregistry" in url and "/services?serviceId=" in url:
            sid = url.split("serviceId=", 1)[1]
            base = url.split("/v1/", 1)[1].split("?", 1)[0]
            if sid in self.services:
                raise GcpError(409, "already exists", url)
            coll = "mcpServers" if "mcpServerSpec" in json else "endpoints"
            self.services[sid] = {"name": f"{base}/{sid}", **copy.deepcopy(json),
                                  "registryResource": f"projects/{N}/locations/{R}/{coll}/agentregistry-{sid}"}
            self._lag[sid] = self.projection_lag
            return self._op(base.rsplit("/services", 1)[0])
        if method == "DELETE" and "agentregistry" in url and "/services/" in url:
            sid = url.rsplit("/", 1)[-1]
            svc = self.services.pop(sid)
            rr = svc.get("registryResource", "")
            self.iap.pop("/".join(rr.split("/")[-2:]), None)       # the entry's IAP policy goes with it
            return self._op(url.split("/v1/", 1)[1].rsplit("/services", 1)[0])
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
        if method == "PATCH" and "/authzExtensions/" in url:
            xid = url.split("?", 1)[0].rsplit("/", 1)[-1]
            self.extensions[xid].update(copy.deepcopy(json))          # metadata is replaced wholesale
            return self._op(url.split("/v1/", 1)[1].split("?", 1)[0].rsplit("/authzExtensions", 1)[0])
        if method == "PATCH" and "/authzPolicies/" in url:
            pid = url.split("?", 1)[0].rsplit("/", 1)[-1]
            mask = url.split("updateMask=", 1)[1].split("&", 1)[0].split(",") if "updateMask=" in url else []
            pol = self.policies[pid]
            if "customProvider.authzExtension.resources" in mask:
                pol["customProvider"] = copy.deepcopy(json["customProvider"])
            # As seen live: a PATCH clears the policy's labels unless labels is in the update mask.
            pol.pop("labels", None)
            if "labels" in mask and json.get("labels"):
                pol["labels"] = copy.deepcopy(json["labels"])
            return self._op(url.split("/v1/", 1)[1].split("?", 1)[0].rsplit("/authzPolicies", 1)[0])
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
