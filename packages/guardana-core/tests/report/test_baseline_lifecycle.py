"""An accepted risk that never lapses is a finding somebody deleted.

A waiver is the one place the engine deliberately does not fail on a finding, and
the only thing that makes that defensible is that it is temporary and visible. So
an expiry actually expires — the finding comes back and fails the gate again — and
a waiver nobody wrote a reason for is reported rather than quietly honoured.
"""

from datetime import date
from pathlib import Path

import pytest
import yaml
from guardana.core.report.baseline import (
    BASELINE_VERSION,
    Baseline,
    BaselineError,
    Waiver,
    load_baseline,
    read_baseline,
)

_TODAY = date(2026, 8, 2)


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "baseline.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_a_waiver_without_an_expiry_stays_active() -> None:
    baseline = Baseline(waivers=(Waiver(fingerprint="abc"),))

    assert baseline.active(_TODAY) == frozenset({"abc"})


def test_a_waiver_that_has_not_expired_stays_active() -> None:
    baseline = Baseline(waivers=(Waiver(fingerprint="abc", expires=date(2026, 12, 31)),))

    assert baseline.active(_TODAY) == frozenset({"abc"})


def test_an_expired_waiver_stops_waiving() -> None:
    # The whole point. The finding comes back and fails the gate again, which is
    # what makes an accepted risk an acceptance rather than a deletion.
    baseline = Baseline(waivers=(Waiver(fingerprint="abc", expires=date(2026, 7, 1)),))

    assert baseline.active(_TODAY) == frozenset()


def test_a_waiver_expiring_today_is_still_active() -> None:
    # Off-by-one in the safe direction: it lapses the day *after* the date written.
    baseline = Baseline(waivers=(Waiver(fingerprint="abc", expires=_TODAY),))

    assert baseline.active(_TODAY) == frozenset({"abc"})


def test_expired_waivers_can_be_listed_so_a_command_can_explain_itself() -> None:
    # Otherwise a gate goes red on a finding somebody waived months ago and nobody
    # can tell why it came back.
    baseline = Baseline(waivers=(Waiver(fingerprint="abc", expires=date(2026, 7, 1)),))

    assert [w.fingerprint for w in baseline.expired(_TODAY)] == ["abc"]


def test_a_generated_waiver_is_reported_as_unreviewed(tmp_path: Path) -> None:
    from guardana.core.report import ScanResult, serialize_baseline  # noqa: PLC0415
    from guardana.core.report.finding import Evidence, Finding  # noqa: PLC0415
    from guardana.core.severity import Severity  # noqa: PLC0415

    finding = Finding("r", Severity.HIGH, "t", (), "x.py:1", Evidence(summary="s"))
    path = tmp_path / "b.yaml"
    path.write_text(serialize_baseline(ScanResult((finding,), ("r",), ())), encoding="utf-8")

    assert read_baseline(path).unreviewed, (
        "a waiver still carrying the generated placeholders is not an accepted risk"
    )


def test_a_reviewed_waiver_is_not_reported_as_unreviewed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "version": BASELINE_VERSION,
            "waivers": [
                {
                    "fingerprint": "abc",
                    "reason": "third-party fixture, tracked in JIRA-42",
                    "approved_by": "security@example.com",
                }
            ],
        },
    )

    assert read_baseline(path).unreviewed == ()


def test_a_version_one_baseline_still_loads(tmp_path: Path) -> None:
    # A team upgrading must not have every waiver stop working.
    path = _write(tmp_path, {"version": 1, "waivers": [{"fingerprint": "abc"}]})

    assert load_baseline(path) == frozenset({"abc"})


def test_a_baseline_from_a_newer_version_is_refused(tmp_path: Path) -> None:
    # Reading it optimistically would mean honouring waivers whose conditions this
    # build cannot evaluate — an expiry field it does not know about, say.
    path = _write(tmp_path, {"version": BASELINE_VERSION + 1, "waivers": []})

    with pytest.raises(BaselineError, match="newer"):
        read_baseline(path)


@pytest.mark.parametrize("version", [True, False, "2", 1.0, None, [2]])
def test_a_version_that_is_not_an_integer_is_refused(tmp_path: Path, version: object) -> None:
    path = _write(tmp_path, {"version": version, "waivers": [{"fingerprint": "abc"}]})

    with pytest.raises(BaselineError) as refused:
        read_baseline(path)

    assert str(refused.value) == f"invalid baseline {path}: version must be an integer"


@pytest.mark.parametrize("version", [0, -1])
def test_a_version_below_one_does_not_exist(tmp_path: Path, version: int) -> None:
    path = _write(tmp_path, {"version": version, "waivers": [{"fingerprint": "abc"}]})

    with pytest.raises(BaselineError) as refused:
        read_baseline(path)

    assert str(refused.value) == f"invalid baseline {path}: version {version} does not exist"


def test_a_baseline_without_a_version_reads_as_version_one(tmp_path: Path) -> None:
    path = _write(tmp_path, {"waivers": [{"fingerprint": "abc"}]})

    assert read_baseline(path).version == 1


def test_an_unreadable_expiry_is_refused_not_treated_as_permanent(tmp_path: Path) -> None:
    # The one mistake this field exists to prevent: a typo'd date that silently
    # becomes a waiver with no end.
    path = _write(
        tmp_path, {"version": 2, "waivers": [{"fingerprint": "abc", "expires": "next tuesday"}]}
    )

    with pytest.raises(BaselineError, match="expires"):
        read_baseline(path)


def test_a_misspelled_waiver_key_is_refused_rather_than_read_around(tmp_path: Path) -> None:
    """The same mistake one letter earlier, failing in the opposite direction.

    `expries:` leaves the value unparsed and the waiver permanent — the outcome the
    test above exists to prevent, reached by a route that test cannot see. Measured
    on the released build: `baseline verify` reported the waiver "still active" and
    exited `0`, and a scan waived a hardcoded secret whose acceptance had lapsed
    seven months earlier.

    Every other hand-written document here refuses an unknown key — profile, YAML
    rule, trace span, contract assertion, pack manifest. This was the one that read
    around it, and it is the one document whose whole job is to stop a gate firing.
    """
    path = _write(
        tmp_path,
        {"version": 2, "waivers": [{"fingerprint": "abc", "expries": "2026-01-01"}]},
    )

    with pytest.raises(BaselineError, match="expries"):
        read_baseline(path)


def test_the_waiver_that_typo_was_meant_to_be_loads_and_lapses(tmp_path: Path) -> None:
    """The inversion, so the refusal above cannot be satisfied by refusing everything."""
    path = _write(
        tmp_path,
        {"version": 2, "waivers": [{"fingerprint": "abc", "expires": "2026-01-01"}]},
    )

    assert read_baseline(path).active(_TODAY) == frozenset()


def test_a_misspelled_top_level_key_is_refused(tmp_path: Path) -> None:
    """`waiverz:` waives nothing and says nothing — a gate somebody thinks they set."""
    path = _write(tmp_path, {"version": 2, "waiverz": [{"fingerprint": "abc"}]})

    with pytest.raises(BaselineError, match="waiverz"):
        read_baseline(path)


def test_load_baseline_excludes_expired_waivers(tmp_path: Path) -> None:
    """The compatibility shim must not be the place the expiry gets forgotten."""
    path = _write(
        tmp_path,
        {"version": 2, "waivers": [{"fingerprint": "abc", "expires": "2020-01-01"}]},
    )

    assert load_baseline(path) == frozenset()


@pytest.mark.parametrize(
    ("reason", "approved_by"),
    [("", "security@example.com"), ("   ", "security@example.com"), ("sandboxed", " \t")],
)
def test_a_waiver_with_a_blank_reason_or_approver_is_unreviewed(
    tmp_path: Path, reason: str, approved_by: str
) -> None:
    waiver = {"fingerprint": "abc", "reason": reason, "approved_by": approved_by}
    path = _write(tmp_path, {"version": BASELINE_VERSION, "waivers": [waiver]})

    assert [w.fingerprint for w in read_baseline(path).unreviewed] == ["abc"]


def test_a_version_one_waiver_is_asked_for_a_reason_but_not_an_approver(tmp_path: Path) -> None:
    waivers = [{"fingerprint": "kept", "reason": "sandboxed"}, {"fingerprint": "blank"}]
    path = _write(tmp_path, {"version": 1, "waivers": waivers})

    assert [w.fingerprint for w in read_baseline(path).unreviewed] == ["blank"]


def test_a_waiver_built_in_code_without_an_approver_is_unreviewed() -> None:
    assert Waiver("abc", reason="sandboxed").is_unreviewed
    assert not Waiver("abc", reason="sandboxed", approved_by="security@example.com").is_unreviewed
