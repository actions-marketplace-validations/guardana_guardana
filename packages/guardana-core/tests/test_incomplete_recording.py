"""A recording kept from a stopped run never grades to a pass.

The origin stopped before every reply was received, so a suite that passes over what the
recording holds has passed over part of the run. The run carries an
`incomplete_recording` shortfall naming the origin, which leaves it `indeterminate`
unless a finding fails it, and the plan foresees the same refusal.
"""

from collections.abc import Iterable

import pytest
from guardana.core.gate import GateOutcome, OpenQuestion, gate_outcome
from guardana.core.plan import build_plan
from guardana.core.profile import Policy, Profile
from guardana.core.recording import RecordedExchange, Recording, RecordingOrigin
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding
from guardana.core.report.shortfall import ShortfallKind
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner, incomplete_recording
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    ChatEndpoint,
    ChatMessage,
    EndpointTarget,
    RecordedTarget,
    Target,
    TargetKind,
)

_RULE = "acme.support.answers"
_QUESTION = "How do I reset my password?"
_REPLY = "Open Settings, then Security."


class _Answers(Rule):
    """Asks one question; finds the reply wanting only when `fails` says so."""

    def __init__(self, *, fails: bool = False) -> None:
        self._fails = fails
        self.meta = RuleMeta(
            id=_RULE,
            title="answers",
            severity=Severity.HIGH,
            target_kind=TargetKind.ENDPOINT,
            taxonomy=(),
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Ask the question and yield a finding quoting the reply when told to fail."""
        if not isinstance(target, ChatEndpoint):
            return
        reply = target.chat([ChatMessage(role="user", content=_QUESTION)])
        if self._fails:
            yield Finding(
                rule_id=_RULE,
                severity=Severity.HIGH,
                title="answers",
                taxonomy=(),
                target_ref=target.ref,
                evidence=Evidence(summary=reply),
            )


def _origin(*, stopped_by: str | None, gate: str | None = None) -> RecordingOrigin:
    return RecordingOrigin(
        run_id="run-7",
        target="http://app.test/v1",
        started_at=None,
        stopped_by=stopped_by,
        gate=gate,
        trials={_RULE: 1},
        rules=(_RULE,),
    )


def _target(origin: RecordingOrigin | None) -> RecordedTarget:
    exchange = RecordedExchange(
        rule=_RULE, input=(ChatMessage(role="user", content=_QUESTION),), reply=_REPLY, line=2
    )
    return RecordedTarget(
        Recording(
            name="support-replies",
            version="1",
            verbatim=True,
            subject=None,
            origin=origin,
            exchanges=(exchange,),
            digest=None,
        )
    )


def _registry(rule: Rule) -> Registry:
    registry = Registry()
    registry.register_rule(rule)
    return registry


def _profile() -> Profile:
    return Profile("t", Policy())


def _graded(target: RecordedTarget, *, fails: bool = False) -> GateOutcome:
    profile = _profile()
    result = Runner(registry=_registry(_Answers(fails=fails)), profile=profile).run(target)
    return gate_outcome(result, profile.policy)


def test_a_stopped_origin_is_one_shortfall_naming_the_origin_run() -> None:
    (shortfall,) = incomplete_recording(_target(_origin(stopped_by="budget_exhausted")))

    assert shortfall.kind is ShortfallKind.INCOMPLETE_RECORDING
    assert shortfall.name == "run-7"
    assert "budget_exhausted" in shortfall.detail
    assert "cannot be graded" in shortfall.detail


@pytest.mark.parametrize(
    "origin",
    [
        None,
        _origin(stopped_by=None),
        _origin(stopped_by=None, gate="indeterminate"),
    ],
    ids=["written by hand", "origin finished", "origin indeterminate but not stopped"],
)
def test_only_a_stop_makes_a_recording_incomplete(origin: RecordingOrigin | None) -> None:
    assert incomplete_recording(_target(origin)) == ()


def test_a_live_target_is_never_an_incomplete_recording() -> None:
    assert incomplete_recording(EndpointTarget("http://app.test/v1", "m")) == ()


def test_a_passing_grade_of_a_stopped_recording_is_indeterminate() -> None:
    target = _target(_origin(stopped_by="budget_exhausted"))
    profile = _profile()

    result = Runner(registry=_registry(_Answers()), profile=profile).run(target)

    assert result.findings == ()
    assert result.rules_run == (_RULE,)
    assert [s.kind for s in result.coverage_shortfall] == [ShortfallKind.INCOMPLETE_RECORDING]
    assert gate_outcome(result, profile.policy) is GateOutcome.INDETERMINATE


def test_a_finding_still_fails_a_grade_of_a_stopped_recording() -> None:
    target = _target(_origin(stopped_by="budget_exhausted"))

    assert _graded(target, fails=True) is GateOutcome.FAIL


def test_a_grade_of_a_finished_recording_is_unchanged() -> None:
    assert _graded(_target(_origin(stopped_by=None))) is GateOutcome.PASS
    assert _graded(_target(_origin(stopped_by=None)), fails=True) is GateOutcome.FAIL


def test_the_plan_refuses_a_stopped_recording_as_the_run_does() -> None:
    profile = _profile()
    registry = _registry(_Answers())

    stopped = build_plan(registry, profile, _target(_origin(stopped_by="deadline_exceeded")))
    finished = build_plan(registry, profile, _target(_origin(stopped_by=None)))

    assert stopped.blockers(profile.policy.fail_on) == (OpenQuestion.COVERAGE_SHORTFALL,)
    assert finished.blockers(profile.policy.fail_on) == ()
