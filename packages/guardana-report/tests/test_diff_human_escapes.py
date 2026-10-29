"""A comparison prints what the runs recorded without letting it drive the terminal."""

from guardana.core.diff import Change, ChangeKind, CheckState, RunDiff
from guardana.core.severity import Severity
from guardana.report import get_diff_renderer

_STATE = CheckState(outcome="fail", severity=Severity.HIGH, confidence=1.0, count=1, waived=False)


def test_a_location_and_a_detail_cannot_carry_an_escape_or_a_line_break() -> None:
    change = Change(
        kind=ChangeKind.APPEARED,
        rule_id="r",
        location="a\x1b[2Jb.pkl",
        detail="first\nforged line",
        after=_STATE,
    )

    rendered = get_diff_renderer("human").render(
        RunDiff(changes=(change,), unchanged=0, notes=("note\x1b[H",))
    )

    assert "\x1b" not in rendered
    assert "\\x1b[2J" in rendered
    assert "first\\nforged line" in rendered
