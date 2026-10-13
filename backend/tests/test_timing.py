"""How long each kind of change takes to take effect: every intent kind has an entry, and the numbers match the
frontend's table (frontend/src/lib/timing.ts)."""
import re
import typing
from pathlib import Path

import pytest

from policy_studio import timing
from policy_studio.model import IntentKind

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "timing.ts"


def test_every_kind_has_an_entry():
    assert set(timing.EFFECT) == set(typing.get_args(IntentKind))
    for kind, e in timing.EFFECT.items():
        assert 0 <= e.min_m <= e.typical_m <= e.max_m <= 10, kind
        assert e.basis in ("measured", "documented", "estimate"), kind
        assert e.after and e.note and "please" not in e.note.lower(), kind


def test_labels_say_measured_or_not():
    assert [k for k, e in timing.EFFECT.items() if e.measured] == ["set_enforcement"]
    assert timing.stored_detail("set_enforcement") == "Stored. Takes effect about 2–3 minutes after Apply (measured)."
    assert timing.stored_detail("model_armor_off").endswith("(not measured).")
    assert timing.stored_detail("grant") == "Stored. Takes effect in a few minutes (up to about 7)."
    assert timing.effect_fields("grant") == {"effect_after_s": 120, "effect_max_s": 420, "effect_measured": False}
    assert timing.ready_fields(["bind_gateway", "set_enforcement"]) == {"ready_after_s": 120, "ready_max_s": 180}
    assert timing.ready_fields([]) == {}


@pytest.mark.skipif(not FRONTEND.exists(), reason="no frontend checkout")
def test_matches_the_frontend_table():
    rows = re.findall(r'^\s+(\w+): t\("(\w+)", ([\d.]+), ([\d.]+), ([\d.]+),', FRONTEND.read_text(), re.M)
    front = {k: (basis, float(a), float(b), float(c)) for k, basis, a, b, c in rows}
    back = {k: (e.basis, e.min_m, e.typical_m, e.max_m) for k, e in timing.EFFECT.items()}
    assert front == back
