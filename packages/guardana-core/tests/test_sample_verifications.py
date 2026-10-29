"""The kit's sample runs are real engine output covering every shape an output must handle.

An output checked only against a passing run has never seen a stopped one, an empty
one or one that verified nothing, and those are the runs it most needs to describe.
"""

from guardana.core.gate import GateOutcome, OpenQuestion
from guardana.core.report import StopReason
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.target import TargetKind
from guardana.core.testing import sample_verifications


def test_the_samples_are_a_passed_a_failed_an_empty_a_stopped_and_an_unverified_run() -> None:
    passed, failed, empty, stopped, unverified = sample_verifications()

    assert (passed.gate, passed.exit_code) == (GateOutcome.PASS, 0)
    assert (failed.gate, failed.exit_code) == (GateOutcome.FAIL, 1)
    assert failed.result.findings
    assert [s.kind for s in empty.result.coverage_shortfall] == [ShortfallKind.EMPTY_TARGET]
    assert empty.gate is GateOutcome.INDETERMINATE
    assert stopped.result.stopped_by is StopReason.BUDGET_EXHAUSTED
    assert stopped.manifest.target.kind is TargetKind.ENDPOINT
    assert stopped.exit_code == 6
    assert unverified.result.rules_run == ()
    assert OpenQuestion.NOTHING_VERIFIED in unverified.open_questions


def test_every_sample_is_a_saved_run_with_its_own_id_and_times() -> None:
    samples = sample_verifications()

    assert len({sample.manifest.run_id for sample in samples}) == len(samples)
    for sample in samples:
        assert sample.manifest.started_at is not None
        assert sample.manifest.completed_at is not None
        assert sample.document()["schema_version"] == sample.manifest.schema_version


def test_each_call_runs_afresh() -> None:
    first = {sample.manifest.run_id for sample in sample_verifications()}
    second = {sample.manifest.run_id for sample in sample_verifications()}

    assert first.isdisjoint(second)
