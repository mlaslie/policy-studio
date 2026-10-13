"""How long each kind of change takes to take effect at the gateway, after Apply reports it stored (read back).

Verified (read back) means the setting is stored. It doesn't mean the gateway enforces it yet: a grant verified at
20:12:46 UTC still got a 403 from the gateway 30 s later, and the same call worked a few minutes later.

Minutes are counted from when the item is verified. Apply already waits for long-running operations (an agent
redeploy, a Model Armor policy), so those aren't counted again. frontend/src/lib/timing.ts has the same table, and
tests/test_timing.py compares the two.

  basis  measured    timed here: an enforcement change took effect 2m40s, 2m08s and 2m19s after Apply.
         documented  IAM: Google documents that changes usually propagate within about 2 minutes and can take up to
                     7; seen here: not in effect 30 s after read-back, in effect a few minutes later.
         estimate    not measured.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class Effect:
    after: str           # "Takes effect {after}"
    note: str            # the whole wait from sending the change, for notes and generated comments
    min_m: float         # minutes after the item is verified
    typical_m: float
    max_m: float
    basis: str           # measured | documented | estimate

    @property
    def measured(self) -> bool:
        return self.basis == "measured"

    @property
    def text(self) -> str:
        """`after` with its basis: "(measured)", "(not measured)", or nothing for Google's documented range."""
        return self.after + {"measured": " (measured)", "estimate": " (not measured)"}.get(self.basis, "")


IAM_NOTE = "usually take effect within a few minutes (up to about 7)"
_IAM = dict(after="in a few minutes (up to about 7)", min_m=0.5, typical_m=2, max_m=7, basis="documented")
_BIND = dict(after="within about a minute of the redeploy finishing", min_m=0, typical_m=1, max_m=2,
             basis="estimate")
_MA = dict(after="usually in a few minutes", min_m=1, typical_m=3, max_m=5, basis="estimate")
_SETUP = dict(after="in a few minutes", min_m=1, typical_m=3, max_m=5, basis="estimate")
_MA_NOTE = "takes about 4 minutes, then usually a few more (not measured)"

EFFECT: dict[str, Effect] = {
    "grant": Effect(note=f"IAM grants {IAM_NOTE}", **_IAM),
    "revoke": Effect(note=f"IAM revokes {IAM_NOTE}", **_IAM),
    "modify": Effect(note=f"IAM changes {IAM_NOTE}", **_IAM),
    "iam_project_grant": Effect(note=f"service agent roles {IAM_NOTE}", **_IAM),
    "bind_gateway": Effect(note="binding redeploys the agent (about 5 minutes)", **_BIND),
    "unbind_gateway": Effect(note="unbinding redeploys the agent (about 5 minutes)", **_BIND),
    "set_enforcement": Effect(after="about 2–3 minutes after Apply",
                              note="an enforcement change takes effect about 2–3 minutes after it's sent (measured)",
                              min_m=0, typical_m=2, max_m=3, basis="measured"),
    "dedicate_extension": Effect(after="about 2–3 minutes after the policy update",
                                 note="giving a gateway its own extension takes a policy update (about 20 s), then "
                                      "about 2–3 minutes (not measured)",
                                 min_m=2, typical_m=2.5, max_m=3, basis="estimate"),
    "model_armor_on": Effect(note=f"turning Model Armor on {_MA_NOTE}", **_MA),
    "model_armor_off": Effect(note=f"turning Model Armor off {_MA_NOTE}", **_MA),
    "model_armor_template": Effect(note="a Model Armor template change takes a few minutes (not measured)", **_SETUP),
    "model_armor_extension": Effect(note="a Model Armor extension change takes a few minutes (not measured)",
                                    **_SETUP),
}

WAIT = "Wait before testing."


def effect(kind: str) -> Optional[Effect]:
    return EFFECT.get(kind)


def stored_detail(kind: str) -> str:
    """"Stored. Takes effect ..." for a verified item."""
    e = EFFECT.get(kind)
    return f"Stored. Takes effect {e.text}." if e else "Stored."


def effect_fields(kind: str) -> dict[str, object]:
    """For apply events and the apply log: seconds after the item is verified."""
    e = EFFECT.get(kind)
    if not e:
        return {}
    return {"effect_after_s": round(e.typical_m * 60), "effect_max_s": round(e.max_m * 60),
            "effect_measured": e.measured}


def ready_fields(kinds: Iterable[str]) -> dict[str, int]:
    """For the apply log's done entry: the largest typical and the largest max among the verified kinds."""
    es = [EFFECT[k] for k in kinds if k in EFFECT]
    if not es:
        return {}
    return {"ready_after_s": round(max(e.typical_m for e in es) * 60),
            "ready_max_s": round(max(e.max_m for e in es) * 60)}


def wait_note(kinds: Iterable[str]) -> str:
    """The distinct notes of these kinds in one sentence, for the end of a generated bundle."""
    notes: list[str] = []
    for k in kinds:
        e = EFFECT.get(k)
        if e and e.note not in notes:
            notes.append(e.note)
    return f"After running this: {'; '.join(notes)}. {WAIT}" if notes else ""


def item_comment(kind: str) -> str:
    """One sentence for a generated item."""
    e = EFFECT.get(kind)
    return f"{e.note[:1].upper()}{e.note[1:]}. {WAIT}" if e else ""
