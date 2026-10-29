"""A rule that finds, while it runs, that the target lacks what it examines records a skip.

`NotOffered` raised before the rule reports anything is a `not_offered` skip: a coverage
gap the release preset refuses and the default preset lists, never a rule that ran. Raised
after the rule reported, it is an error of that rule, and what it reported is kept.
"""

from collections.abc import Iterable

import pytest
from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.gate import (
    GateOutcome,
    OpenQuestion,
    exit_code_for,
    gate_outcome,
    open_questions,
)
from guardana.core.profile import Policy, Profile
from guardana.core.profile.presets import preset
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult, SkippedRule, SkipReason
from guardana.core.report.check_error import bounded_reason
from guardana.core.rule import NotOffered, Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport

_REF = "http://x#m"


def _meta(rule_id: str) -> RuleMeta:
    return RuleMeta(
        rule_id,
        rule_id,
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )


class _Lacking(Rule):
    """Find the examined capability absent before reporting anything."""

    def __init__(
        self, rule_id: str = "acme.tasks", detail: str = "the server lists no tasks"
    ) -> None:
        self.meta = _meta(rule_id)
        self._detail = detail

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Raise `NotOffered` naming what is missing."""
        raise NotOffered(self._detail, missing=("tasks",))
        yield  # pragma: no cover — keeps this a generator


class _ReportsThenLacks(Rule):
    """Yield a finding, then claim the target offers nothing to examine."""

    meta = _meta("acme.late")

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report once, then raise `NotOffered`."""
        yield Finding(self.meta.id, Severity.HIGH, "t", (), target.ref, Evidence(summary="s"))
        raise NotOffered("the server lists no tasks")


class _MeasuresThenLacks(Rule):
    """Record a measured case, then claim the target offers nothing to examine."""

    meta = _meta("acme.measured")

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Record one assessment, then raise `NotOffered`."""
        ctx.record(
            Assessment(
                case_id="c",
                assessor="acme",
                subject_ref=target.ref,
                status=AssessmentStatus.MEASURED,
                rule_id=self.meta.id,
                passed=True,
            )
        )
        raise NotOffered("the server lists no tasks")
        yield  # pragma: no cover — keeps this a generator


class _Clean(Rule):
    """Run and find nothing."""

    def __init__(self, rule_id: str = "acme.clean") -> None:
        self.meta = _meta(rule_id)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing."""
        return ()


class _NeedsTools(Rule):
    """A rule the selection skips for a capability the target lacks."""

    meta = RuleMeta(
        "acme.tools",
        "needs tools",
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CALL_TOOLS}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Never reached."""
        return ()


def _run(*rules: Rule, profile: Profile | None = None, concurrency: int = 1) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))
    return Runner(
        registry=registry,
        profile=profile or Profile("t", Policy()),
        concurrency=concurrency,
    ).run(target)


def test_a_rule_the_target_does_not_offer_is_recorded_as_a_not_offered_skip() -> None:
    result = _run(_Lacking(), _Clean())

    assert result.rules_skipped == (
        SkippedRule(
            "acme.tasks", SkipReason.NOT_OFFERED, ("tasks",), f"{_REF}: the server lists no tasks"
        ),
    )
    assert result.rules_run == ("acme.clean",)
    assert result.errors == ()
    assert result.stopped_by is None


def test_a_not_offered_skip_is_a_coverage_gap_the_gate_sees() -> None:
    result = _run(_Lacking(), _Clean())

    assert result.rules_skipped[0].is_coverage_gap
    assert OpenQuestion.SKIPPED in open_questions(result)


def test_the_release_preset_refuses_a_pass_over_a_rule_the_target_does_not_offer() -> None:
    release = preset("release")
    result = _run(_Lacking(), _Clean(), profile=release)

    outcome = gate_outcome(result, release.policy)

    assert outcome is GateOutcome.INDETERMINATE
    assert exit_code_for(outcome, result.stopped_by) == 2


def test_the_default_policy_lists_the_skip_and_still_passes() -> None:
    result = _run(_Lacking(), _Clean())

    assert gate_outcome(result, Policy()) is GateOutcome.PASS
    assert [s.reason for s in result.rules_skipped] == [SkipReason.NOT_OFFERED]


def test_a_run_time_skip_follows_the_selection_skips_in_rule_order() -> None:
    result = _run(
        _Lacking("acme.first"), _NeedsTools(), _Clean(), _Lacking("acme.second"), concurrency=3
    )

    assert [(s.rule_id, s.reason) for s in result.rules_skipped] == [
        ("acme.tools", SkipReason.MISSING_CAPABILITY),
        ("acme.first", SkipReason.NOT_OFFERED),
        ("acme.second", SkipReason.NOT_OFFERED),
    ]


def test_the_detail_is_cut_to_the_length_a_recorded_reason_may_have() -> None:
    result = _run(_Lacking(detail="x" * 5000))

    detail = result.rules_skipped[0].detail
    assert detail == bounded_reason(f"{_REF}: {'x' * 5000}")
    assert len(detail) < 5000


def test_not_offered_raised_after_a_finding_is_an_error_and_the_finding_is_kept() -> None:
    result = _run(_ReportsThenLacks())

    assert [f.rule_id for f in result.findings] == ["acme.late"]
    assert [(e.source, e.stage, e.reason) for e in result.errors] == [
        ("acme.late", "run", "raised NotOffered after reporting")
    ]
    assert result.rules_skipped == ()
    assert result.rules_run == ()


def test_not_offered_raised_after_a_measured_case_is_an_error_and_the_case_is_kept() -> None:
    result = _run(_MeasuresThenLacks())

    assert [a.rule_id for a in result.assessments] == ["acme.measured"]
    assert [e.reason for e in result.errors] == ["raised NotOffered after reporting"]
    assert result.rules_skipped == ()


def test_a_merged_result_keeps_a_run_time_skip() -> None:
    first = _run(_Lacking())
    second = _run(_Clean())

    merged = ScanResult.merged([first, second])

    assert [s.reason for s in merged.rules_skipped] == [SkipReason.NOT_OFFERED]
    assert merged.rules_run == ("acme.clean",)


def test_not_offered_carries_its_detail_and_what_is_missing() -> None:
    raised = NotOffered("no tasks", missing=("tasks", "tasks/list"))

    assert str(raised) == "no tasks"
    assert raised.detail == "no tasks"
    assert raised.missing == ("tasks", "tasks/list")


@pytest.mark.parametrize("missing", [(), ("tasks",)])
def test_what_is_missing_reaches_the_skip(missing: tuple[str, ...]) -> None:
    class _Names(_Lacking):
        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            raise NotOffered("absent", missing=missing)
            yield  # pragma: no cover — keeps this a generator

    assert _run(_Names()).rules_skipped[0].missing == missing
