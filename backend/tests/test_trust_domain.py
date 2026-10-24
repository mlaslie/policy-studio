"""Agent Identity trust domains: per organization (agents.global.org-<ORG>) or, for a project without an organization,
per project (agents.global.proj-<NUMBER>)."""
import pytest

from policy_studio import dryrun, service
from policy_studio.english import member_label
from policy_studio.gcp import engines as eng_mod
from policy_studio.model import Context, Engine

ORGLESS = "principal://agents.global.proj-4242.system.id.goog/resources/aiplatform/projects/4242/locations/us-east4/reasoningEngines/1"
ORG = "principal://agents.global.org-777.system.id.goog/resources/aiplatform/projects/4242/locations/us-east4/reasoningEngines/1"
ORGLESS_SET = "principalSet://agents.global.proj-4242.system.id.goog/attribute.platformContainer/aiplatform/projects/4242"


class Ancestry:
    def __init__(self, org=None, fail=False):
        self.org, self.fail, self.calls = org, fail, 0

    def post(self, url, json=None, ok404=False):
        self.calls += 1
        if self.fail:
            raise PermissionError("403")
        return {"ancestor": [{"resourceId": {"type": "project", "id": "p"}}]
                + ([{"resourceId": {"type": "organization", "id": self.org}}] if self.org else [])}


def eng(principal):
    return Engine(name="projects/4242/locations/us-east4/reasoningEngines/1", id="1", principal=principal)


def test_trust_domain_of():
    assert eng_mod.trust_domain_of(ORG) == "agents.global.org-777.system.id.goog"
    assert eng_mod.trust_domain_of(ORGLESS) == "agents.global.proj-4242.system.id.goog"
    assert eng_mod.trust_domain_of(ORGLESS_SET) == "agents.global.proj-4242.system.id.goog"
    assert eng_mod.trust_domain_of("serviceAccount:x@p.iam.gserviceaccount.com") is None
    assert eng_mod.trust_domain("777", "4242") == "agents.global.org-777.system.id.goog"
    assert eng_mod.trust_domain(None, "4242") == "agents.global.proj-4242.system.id.goog"


@pytest.mark.parametrize("engines,anc,want", [
    ([eng(ORGLESS)], Ancestry(org="777"), ORGLESS_SET),            # an engine's principal wins (no lookup)
    ([], Ancestry(), ORGLESS_SET),                                 # no organization
    ([eng("serviceAccount:x@p.iam.gserviceaccount.com")], Ancestry(org="777"),
     "principalSet://agents.global.org-777.system.id.goog/attribute.platformContainer/aiplatform/projects/4242"),
    ([], Ancestry(fail=True), None),                               # can't tell
])
def test_project_agents_principal(engines, anc, want):
    assert service._project_agents_principal(anc, Context(project="p"), engines, "4242") == want
    assert anc.calls == (0 if engines and eng_mod.trust_domain_of(engines[0].principal) else 1)


def test_orgless_principals_are_understood():
    assert member_label(ORGLESS_SET) == "All agents in project"
    assert member_label(ORGLESS) == "Agent Runtime engine 1 (Agent Identity)"
    assert dryrun.member_matches(ORGLESS_SET, ORGLESS) is True
    assert dryrun.member_matches(ORGLESS_SET, ORG) is False         # another trust domain
