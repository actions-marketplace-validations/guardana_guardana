"""What an output says when the recorded gate refused a run and no rendered fact says why."""

from guardana.core.gate import GateOutcome, OpenQuestion
from guardana.core.manifest import RunManifest
from guardana.core.report import ScanResult


def recorded_gate(run: RunManifest | None, gate: GateOutcome | None) -> GateOutcome | None:
    """Return the gate a renderer reads: the saved run's, or its caller's when nothing was saved.

    A `monitor` cycle writes no run document, and its alert would otherwise render with no
    gate at all, which is the one input that names a skip the policy refused.
    """
    return run.result_summary.gate if run is not None else gate


def unnamed_refusal(
    result: ScanResult, gate: GateOutcome | None, questions: tuple[OpenQuestion, ...]
) -> GateOutcome | None:
    """Return the recorded gate when it refused the run and nothing a renderer names says why.

    Every open question but a skip is named whatever the policy, and a finding explains a
    `fail`; what is left is a skip the policy refused, or a gate no rendered fact accounts
    for. Every renderer reads this, so none of them can print a clean run the gate refused.
    """
    if gate is None or gate is GateOutcome.PASS:
        return None
    if any(q is not OpenQuestion.SKIPPED for q in questions):
        return None
    if gate is GateOutcome.FAIL and result.findings:
        return None
    return gate


def refused_skips(result: ScanResult, gate: GateOutcome) -> int:
    """Count the skips an unnamed refusal is over, or 0 when it is not over a skip.

    An `indeterminate` with no other open question can only be a refused skip; a `fail`
    is never over one.
    """
    if gate is not GateOutcome.INDETERMINATE:
        return 0
    return sum(1 for s in result.rules_skipped if s.is_coverage_gap)


def refusal_clause(result: ScanResult, gate: GateOutcome) -> str:
    """Say why a refused run is not clean when `unnamed_refusal` found nothing else to name."""
    skipped = refused_skips(result, gate)
    if skipped:
        return f"{skipped} rule(s) were skipped and the gate refused the run: {gate}"
    return f"the gate is {gate}"
