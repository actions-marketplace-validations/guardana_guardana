"""The first-run measure comes only from the study sheet, and only when the sheet can bear it."""

from pathlib import Path

import pytest

import first_run_measure as measure

_HEADER = ",".join(measure.COLUMNS)


def _row(participant: str, **overrides: str) -> str:
    values = {
        "participant": participant,
        "date": "2026-10-05",
        "os": "macOS 15",
        "python": "3.12",
        "install_seconds": "60",
        "first_failure_seconds": "150",
        "fixed_seconds": "300",
        "saved_run_seconds": "360",
        "edited_check_seconds": "480",
        "finished_in_10_min": "yes",
        "maintainer_help": "none",
        "stuck_at": "",
        "consent_to_publish": "yes",
    }
    values.update(overrides)
    return ",".join(values[column] for column in measure.COLUMNS)


def _sheet(tmp_path: Path, *rows: str) -> Path:
    path = tmp_path / "sheet.csv"
    path.write_text("\n".join([_HEADER, *rows]) + "\n", encoding="utf-8")
    return path


def test_the_committed_sheet_parses() -> None:
    measure.read_sheet()


def test_fewer_than_five_sessions_is_not_measured(tmp_path: Path) -> None:
    sessions = measure.read_sheet(_sheet(tmp_path, *(_row(f"P{n}") for n in range(1, 5))))

    text = measure.render(sessions)

    assert text.startswith("**Not measured.** 4 of the 5")
    assert "Finished" not in text


def test_five_sessions_state_counts_and_times_from_the_rows(tmp_path: Path) -> None:
    rows = [
        _row("P1", saved_run_seconds="300"),
        _row("P2", saved_run_seconds="420"),
        _row("P3", saved_run_seconds="540", edited_check_seconds="580", maintainer_help="hint"),
        _row(
            "P4",
            saved_run_seconds="",
            edited_check_seconds="",
            finished_in_10_min="no",
            stuck_at="fix",
        ),
        _row(
            "P5",
            saved_run_seconds="700",
            edited_check_seconds="800",
            finished_in_10_min="no",
            stuck_at="fix",
        ),
    ]

    text = measure.render(measure.read_sheet(_sheet(tmp_path, *rows)))

    assert "Sessions recorded: 5." in text
    assert "without maintainer help: 2 of 5 (target: 4 of every 5, not met)" in text
    assert "for the 4 who reached one: fastest 300, median 480, slowest 700" in text
    assert "Where people got stuck: fix (2)." in text


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (_row("P1", consent_to_publish="no"), "no consent"),
        (_row("Anna"), "never go here"),
        (_row("P1", date="5.10.2026"), "YYYY-MM-DD"),
        (_row("P1", fixed_seconds="5 min"), "whole number"),
        (_row("P1", maintainer_help="a little"), "maintainer_help"),
        (_row("P1", edited_check_seconds="900"), "step times say otherwise"),
        (_row("P1", edited_check_seconds=""), "step times say otherwise"),
        (_row("P1", finished_in_10_min="no"), "step times say otherwise"),
        (_row("P1", install_seconds=""), "step times say otherwise"),
        (_row("P1", saved_run_seconds="1500"), "go backwards"),
    ],
)
def test_a_row_the_measure_cannot_bear_is_refused(tmp_path: Path, row: str, reason: str) -> None:
    with pytest.raises(measure.SheetError, match=reason):
        measure.read_sheet(_sheet(tmp_path, row))


def test_a_participant_recorded_twice_is_refused(tmp_path: Path) -> None:
    with pytest.raises(measure.SheetError, match="recorded twice: P1"):
        measure.read_sheet(_sheet(tmp_path, _row("P1"), _row("P1")))


def test_a_sheet_with_other_columns_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "sheet.csv"
    path.write_text(_HEADER + ",name\n", encoding="utf-8")

    with pytest.raises(measure.SheetError, match="header must be exactly"):
        measure.read_sheet(path)


def test_the_target_is_a_share_not_a_count(tmp_path: Path) -> None:
    rows = [_row(f"P{n}") for n in range(1, 5)]
    rows += [_row(f"P{n}", edited_check_seconds="", finished_in_10_min="no") for n in range(5, 11)]

    text = measure.render(measure.read_sheet(_sheet(tmp_path, *rows)))

    assert "4 of 10 (target: 4 of every 5, not met)" in text
