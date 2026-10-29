"""A target that stops accepting what the run agreed with it stops the run as `target_changed`.

The server still answers, so `target_unavailable` would name the wrong cause. The stop
exits `4`, is outranked by a target that went away and outranks a spent budget, in a
pooled run and in a merged one alike. A reply that arrived and is unreadable stops the
run as the target's failure, said in its own words.
"""

import threading
from collections.abc import Iterable

import pytest
from guardana.core.budget import BudgetExhausted
from guardana.core.diff import compare
from guardana.core.gate import GateOutcome, StopReason, exit_code_for, gate_outcome
from guardana.core.profile import Policy, Profile
from guardana.core.redaction import EvidenceMode, MessageQuoting, RedactionPolicy
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner, target_failures
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, EndpointUnreachable, Target, TargetKind
from guardana.core.target.endpoint import TargetChanged, UnreadableReply
from guardana.core.target.failure import (
    FailureRemedies,
    FailureScope,
    describe_failure,
    failure_scope,
)
from guardana.core.testing import ScriptedTransport

_CHANGED = (
    "the MCP server at http://x#m stopped accepting revision 2025-11-25 during the run; "
    "it now offers 2026-07-28"
)
_UNREADABLE = "the MCP server at http://x#m sent a reply that is not JSON-RPC (HTTP 200, 9 bytes)"
_QUOTING = MessageQuoting.of(RedactionPolicy())
_POLICY = Policy()


class _Raising(Rule):
    """Raise what it is given, after its peers have started, as a rule whose send met it."""

    def __init__(
        self, rule_id: str, error: Exception, barrier: threading.Barrier | None = None
    ) -> None:
        self._error = error
        self._barrier = barrier
        self.meta = RuleMeta(
            rule_id,
            rule_id,
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Wait for any peer, then fail."""
        if self._barrier is not None:
            self._barrier.wait()
        raise self._error
        yield  # pragma: no cover — keeps this a generator


class _Clean(Rule):
    """Run and find nothing, recording that it ran."""

    def __init__(self, rule_id: str) -> None:
        self.started = False
        self.meta = RuleMeta(
            rule_id,
            rule_id,
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing."""
        self.started = True
        return ()


def _run(*rules: Rule, concurrency: int = 1) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))
    return Runner(registry=registry, profile=Profile("t", _POLICY), concurrency=concurrency).run(
        target
    )


# What the failure says and whose it is


@pytest.mark.parametrize("error", [TargetChanged(_CHANGED), UnreadableReply(_UNREADABLE)])
def test_a_changed_target_and_an_unreadable_reply_are_the_target_s(error: Exception) -> None:
    assert failure_scope(error) is FailureScope.TARGET


@pytest.mark.parametrize(
    ("error", "message"),
    [(TargetChanged(_CHANGED), _CHANGED), (UnreadableReply(_UNREADABLE), _UNREADABLE)],
    ids=["changed", "unreadable"],
)
def test_the_failure_is_said_in_its_own_words(error: Exception, message: str) -> None:
    said = describe_failure(error, "http://x#m", _QUOTING, FailureRemedies())

    assert said == message
    assert "could not reach" not in said


def test_metadata_only_withholds_the_words_of_a_changed_target() -> None:
    quoting = MessageQuoting.of(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    said = describe_failure(TargetChanged(_CHANGED), "http://x#m", quoting, FailureRemedies())

    assert said.startswith("TargetChanged, ")
    assert "2026-07-28" not in said


# The stop a run records


def test_a_target_that_changed_stops_the_run_and_exits_4() -> None:
    later = _Clean("b.later")

    result = _run(_Raising("a.changed", TargetChanged(_CHANGED)), later)

    assert result.stopped_by is StopReason.TARGET_CHANGED
    assert [(e.source, e.stage, e.reason) for e in result.errors] == [
        ("a.changed", "target", _CHANGED)
    ]
    assert not later.started
    assert result.rules_run == ()
    assert exit_code_for(gate_outcome(result, _POLICY), result.stopped_by) == 4


def test_an_unreadable_reply_stops_the_run_as_a_target_that_failed() -> None:
    result = _run(_Raising("a.unreadable", UnreadableReply(_UNREADABLE)))

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert [e.reason for e in result.errors] == [_UNREADABLE]


def test_the_cause_of_a_changed_target_is_reported_as_the_run_recorded_it() -> None:
    result = _run(_Raising("a.changed", TargetChanged(_CHANGED)))

    assert target_failures(result) == (_CHANGED,)


@pytest.mark.parametrize("changed_first", [True, False], ids=["changed-first", "budget-first"])
def test_a_changed_target_outranks_a_budget_stop_in_the_same_run(changed_first: bool) -> None:
    both = threading.Barrier(2, timeout=5)
    stops: list[Rule] = [
        _Raising("a.changed", TargetChanged(_CHANGED), both),
        _Raising("b.budget", BudgetExhausted("max_requests reached"), both),
    ]

    result = _run(*(stops if changed_first else reversed(stops)), concurrency=2)

    assert result.stopped_by is StopReason.TARGET_CHANGED


@pytest.mark.parametrize("changed_first", [True, False], ids=["changed-first", "gone-first"])
def test_a_target_that_went_away_outranks_one_that_changed(changed_first: bool) -> None:
    both = threading.Barrier(2, timeout=5)
    stops: list[Rule] = [
        _Raising("a.changed", TargetChanged(_CHANGED), both),
        _Raising("b.gone", EndpointUnreachable("http://x#m did not answer"), both),
    ]

    result = _run(*(stops if changed_first else reversed(stops)), concurrency=2)

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE


@pytest.mark.parametrize(
    ("stops", "merged"),
    [
        ((StopReason.BUDGET_EXHAUSTED, StopReason.TARGET_CHANGED), StopReason.TARGET_CHANGED),
        ((StopReason.TARGET_CHANGED, StopReason.BUDGET_EXHAUSTED), StopReason.TARGET_CHANGED),
        ((StopReason.TARGET_CHANGED, StopReason.TARGET_UNAVAILABLE), StopReason.TARGET_UNAVAILABLE),
        ((StopReason.TARGET_UNAVAILABLE, StopReason.TARGET_CHANGED), StopReason.TARGET_UNAVAILABLE),
        ((None, StopReason.TARGET_CHANGED), StopReason.TARGET_CHANGED),
    ],
)
def test_a_merged_run_ranks_the_stops_its_passes_recorded(
    stops: tuple[StopReason | None, StopReason | None], merged: StopReason
) -> None:
    passes = [ScanResult((), (), (), stopped_by=stop) for stop in stops]

    assert ScanResult.merged(passes).stopped_by is merged


def test_the_exit_code_of_a_changed_target_is_4_whatever_the_verdict() -> None:
    for outcome in GateOutcome:
        assert exit_code_for(outcome, StopReason.TARGET_CHANGED) == 4


def test_a_comparison_names_a_side_its_target_changed_under() -> None:
    finding = Finding("a", Severity.HIGH, "t", (), "http://x#m", Evidence(summary="s"))
    complete = ScanResult((finding,), ("a", "b"), ())
    changed = ScanResult((finding,), ("a",), (), stopped_by=StopReason.TARGET_CHANGED)

    diff = compare(complete, changed)

    assert any("changed" in reason and "second" in reason for reason in diff.incomplete), (
        diff.incomplete
    )
