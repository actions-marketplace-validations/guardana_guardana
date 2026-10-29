"""What an ingest key wrote must not be able to drive the operator's terminal.

Every string a listing prints came from a submission, and anyone holding an ingest
key chooses it. An escape sequence printed raw can clear the screen, move the
cursor or repaint a verdict, so the listing shows it escaped instead.
"""

import datetime

import pytest
from guardana.server.cli.inventory import _print, _print_findings, _print_runs
from guardana.server.inventory import InventoryEntry, RunEntry
from guardana.server.lifecycle import TrackedFinding

_HOSTILE = "ci\x1b[2J\rforged PASS\x07"


def _assert_no_control_characters(printed: str) -> None:
    for line in printed.splitlines():
        assert all(character.isprintable() for character in line), repr(line)


def test_a_run_listing_escapes_a_submitted_source(capsys: pytest.CaptureFixture[str]) -> None:
    _print_runs((RunEntry("acme/web", _HOSTILE, _HOSTILE, "fail", "now", _HOSTILE),))

    printed = capsys.readouterr().out

    _assert_no_control_characters(printed)
    assert "ci\\x1b[2J\\rforged PASS\\x07" in printed
    assert "fail" in printed


def test_an_inventory_listing_escapes_a_submitted_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _print((InventoryEntry("acme/web", _HOSTILE, 1, "now"),), "AI systems", "ai-system")

    printed = capsys.readouterr().out

    _assert_no_control_characters(printed)
    assert "\\x1b[2J" in printed


def test_a_finding_listing_escapes_what_a_run_and_a_triager_wrote(
    capsys: pytest.CaptureFixture[str],
) -> None:
    finding = TrackedFinding(
        identity="sha256:0123456789abcdef",
        rule_id=_HOSTILE,
        severity="HIGH\x1b[0m",
        target_ref=_HOSTILE,
        status="waived",
        owner=None,
        waived_by=_HOSTILE,
        waiver_reason=_HOSTILE,
        waiver_expires=datetime.date(2030, 1, 1),
        waiver_lapsed=False,
        runs=1,
        first_seen="then",
        last_seen="now",
    )

    _print_findings((finding,))

    printed = capsys.readouterr().out
    _assert_no_control_characters(printed)
    assert "\\x1b[2J" in printed


def test_printable_text_is_shown_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    """Escaping must not mangle an ordinary name, including one outside ASCII."""
    _print_runs((RunEntry("acme/web", "wyszukiwarka", "prod", "pass", "now", "ci#model"),))

    printed = capsys.readouterr().out

    assert "wyszukiwarka/prod" in printed
    assert printed.rstrip().endswith("ci#model")
