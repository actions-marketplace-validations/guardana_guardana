"""A rule that attempted cases and graded too few of them establishes nothing.

Graded is `measured`; attempted is every assessment that is not `skipped`. None graded
is a shortfall under every policy; `fail_on.min_graded_share` raises the bar per rule.
A shortfall has no switch, so the run is `indeterminate` unless a finding fails it.
"""

import json
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.evaluator.length import LengthEvaluator
from guardana.core.gate import GateOutcome, exit_code_for, gate_outcome
from guardana.core.profile import Policy, Profile, ProfileError, default_profile, load_profile
from guardana.core.profile.digest import profile_digest
from guardana.core.profile.model import FailOn
from guardana.core.profile.presets import preset
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport

_CI_PROFILE_DIGEST = "sha256:2219ab15facdd105c1e8fd70d1b970feca4e474d4f9973ef377aae8e2aba3e0c"
"""What saved runs and recipe locks recorded for the `ci` preset before the floor existed."""


class _Recording(Rule):
    """A rule that records one assessment per status it is given, and finds nothing."""

    def __init__(self, rule_id: str, *statuses: AssessmentStatus) -> None:
        self._statuses = statuses
        self.meta = RuleMeta(
            id=rule_id,
            title=rule_id,
            severity=Severity.HIGH,
            target_kind=TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Record each status as one case attempt."""
        for index, status in enumerate(self._statuses):
            ctx.record(
                Assessment(
                    case_id=f"case-{index}",
                    assessor="acme.test",
                    subject_ref=target.ref,
                    status=status,
                    rule_id=self.meta.id,
                    passed=True if status is AssessmentStatus.MEASURED else None,
                    reason=UnmeasuredReason.TARGET_DECLINED
                    if status is AssessmentStatus.INCONCLUSIVE
                    else None,
                )
            )
        return ()


def _endpoint(*replies: str) -> EndpointTarget:
    return EndpointTarget("http://model.test", "m", transport=ScriptedTransport(*replies))


def _run(*rules: Rule, profile: Profile | None = None) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    return Runner(registry, profile or default_profile()).run(_endpoint("ok"))


def _floor(share: float) -> Profile:
    return Profile("t", Policy(fail_on=FailOn(min_graded_share=share)))


def _ungraded(result: ScanResult) -> tuple[CoverageShortfall, ...]:
    return tuple(g for g in result.coverage_shortfall if g.kind is ShortfallKind.UNGRADED_CASES)


_MEASURED = AssessmentStatus.MEASURED
_INCONCLUSIVE = AssessmentStatus.INCONCLUSIVE
_SKIPPED = AssessmentStatus.SKIPPED
_ERROR = AssessmentStatus.ERROR


@pytest.mark.parametrize("profile", ["default", "ci", "release"])
def test_a_rule_that_graded_none_of_its_attempts_is_indeterminate_under_every_preset(
    profile: str,
) -> None:
    chosen = default_profile() if profile == "default" else preset(profile)

    result = _run(_Recording("acme.test.declined", _INCONCLUSIVE, _ERROR, _SKIPPED), profile=chosen)

    assert _ungraded(result) == (
        CoverageShortfall(
            kind=ShortfallKind.UNGRADED_CASES,
            name="acme.test.declined",
            detail=(
                "graded 0 of 2 case attempt(s): every one was declined or could not be "
                "decided, so the check established nothing"
            ),
        ),
    )
    outcome = gate_outcome(result, chosen.policy)
    assert outcome is GateOutcome.INDETERMINATE
    assert exit_code_for(outcome, result.stopped_by) == 2


def test_a_rule_whose_every_assessment_was_skipped_is_not_checked() -> None:
    result = _run(_Recording("acme.test.skipped", _SKIPPED, _SKIPPED))

    assert _ungraded(result) == ()


def test_a_rule_that_recorded_no_assessment_is_not_checked() -> None:
    assert _ungraded(_run(_Recording("acme.test.silent"))) == ()


def test_one_graded_attempt_is_enough_without_a_floor() -> None:
    result = _run(_Recording("acme.test.one", _MEASURED, *[_INCONCLUSIVE] * 9))

    assert _ungraded(result) == ()
    assert gate_outcome(result, Policy()) is GateOutcome.PASS


def test_a_share_below_the_floor_is_a_shortfall_naming_both_numbers() -> None:
    rule = _Recording("acme.test.seven", *[_MEASURED] * 7, *[_INCONCLUSIVE] * 3, _SKIPPED)

    result = _run(rule, profile=_floor(0.8))

    assert _ungraded(result) == (
        CoverageShortfall(
            kind=ShortfallKind.UNGRADED_CASES,
            name="acme.test.seven",
            detail="graded 7 of 10 case attempts (70%), below the floor of 80%",
        ),
    )
    assert gate_outcome(result, _floor(0.8).policy) is GateOutcome.INDETERMINATE


def test_a_share_at_the_floor_passes_it() -> None:
    rule = _Recording("acme.test.eight", *[_MEASURED] * 8, *[_INCONCLUSIVE] * 2)

    result = _run(rule, profile=_floor(0.8))

    assert _ungraded(result) == ()
    assert gate_outcome(result, _floor(0.8).policy) is GateOutcome.PASS


def test_the_floor_is_checked_per_rule_not_over_the_run() -> None:
    graded = _Recording("acme.test.graded", *[_MEASURED] * 30)
    ungraded = _Recording("acme.test.ungraded", _MEASURED, *[_INCONCLUSIVE] * 3)

    result = _run(graded, ungraded, profile=_floor(0.5))

    assert [gap.name for gap in _ungraded(result)] == ["acme.test.ungraded"]


def test_a_rule_that_graded_none_under_a_floor_is_one_shortfall() -> None:
    result = _run(_Recording("acme.test.none", _INCONCLUSIVE, _INCONCLUSIVE), profile=_floor(0.5))

    (gap,) = _ungraded(result)
    assert gap.detail.startswith("graded 0 of 2 case attempt(s): every one was declined")


def test_a_share_below_the_floor_is_written_without_rounding_up_to_it() -> None:
    rule = _Recording("acme.test.close", *[_MEASURED] * 999, *[_INCONCLUSIVE] * 1001)

    (gap,) = _ungraded(_run(rule, profile=_floor(0.5)))

    assert gap.detail == "graded 999 of 2000 case attempts (49.9%), below the floor of 50%"


def test_a_finding_still_fails_a_run_with_an_ungraded_rule() -> None:
    class _Fires(Rule):
        meta = RuleMeta(
            "acme.test.fires",
            "fires",
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            yield Finding(
                rule_id=self.meta.id,
                severity=Severity.HIGH,
                title="t",
                taxonomy=(),
                target_ref=target.ref,
                evidence=Evidence(summary="leaked"),
            )

    result = _run(_Fires(), _Recording("acme.test.declined", _INCONCLUSIVE))

    assert _ungraded(result)
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


def _suite(tmp_path: Path, cases: int) -> SuiteRule:
    header = {"guardana_dataset": 1, "name": "support", "version": "2026.09"}
    lines = [json.dumps(header), *(json.dumps({"input": f"Q{n}?"}) for n in range(cases))]
    (tmp_path / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule = {
        "id": "acme.quality.support",
        "title": "The support bot still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "evaluator": "length",
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 0.5, "min_sample": cases // 2},
    }
    (tmp_path / "suite.yaml").write_text(json.dumps(rule), encoding="utf-8")
    loaded = load_yaml_rules(tmp_path / "suite.yaml")[0]
    if not isinstance(loaded, SuiteRule):
        raise TypeError(type(loaded).__name__)
    return loaded


def _run_suite(rule: SuiteRule, replies: list[str], profile: Profile) -> ScanResult:
    registry = Registry()
    registry.register_rule(rule)
    registry.register_evaluator(LengthEvaluator())
    return Runner(registry, profile).run(_endpoint(*replies))


def test_a_suite_whose_every_reply_was_ungradable_is_a_shortfall(tmp_path: Path) -> None:
    result = _run_suite(_suite(tmp_path, 10), [""] * 10, default_profile())

    assert [gap.name for gap in _ungraded(result)] == ["acme.quality.support"]


def test_a_suite_below_the_floor_is_a_shortfall_and_at_it_is_not(tmp_path: Path) -> None:
    rule = _suite(tmp_path, 10)
    answer = "Open Settings and follow the reset link."

    below = _run_suite(rule, [answer] * 7 + [""] * 3, _floor(0.8))
    at = _run_suite(rule, [answer] * 8 + [""] * 2, _floor(0.8))

    assert [gap.detail for gap in _ungraded(below)] == [
        "graded 7 of 10 case attempts (70%), below the floor of 80%"
    ]
    assert _ungraded(at) == ()


def _profile_with(tmp_path: Path, block: str) -> Profile:
    path = tmp_path / "guardana.yaml"
    path.write_text(f"name: t\nfail_on:\n{block}", encoding="utf-8")
    return load_profile(path)


def test_the_floor_is_read_from_the_fail_on_block(tmp_path: Path) -> None:
    profile = _profile_with(tmp_path, "  min_graded_share: 0.8\n")

    assert profile.policy.fail_on.min_graded_share == 0.8


def test_a_floor_of_one_is_accepted(tmp_path: Path) -> None:
    assert _profile_with(tmp_path, "  min_graded_share: 1\n").policy.fail_on.min_graded_share == 1


def test_the_floor_is_unset_by_default_and_in_every_preset() -> None:
    assert FailOn().min_graded_share is None
    for name in ("ci", "release", "monitor", "pre-training"):
        assert preset(name).policy.fail_on.min_graded_share is None


@pytest.mark.parametrize("value", ["0", "-0.5", "1.5", "'0.8'", "true", ".nan"])
def test_a_floor_outside_zero_to_one_is_refused(tmp_path: Path, value: str) -> None:
    with pytest.raises(ProfileError, match=r"min_graded_share"):
        _profile_with(tmp_path, f"  min_graded_share: {value}\n")


def test_the_digest_is_unchanged_while_no_floor_is_set() -> None:
    assert profile_digest(preset("ci")) == _CI_PROFILE_DIGEST


def test_setting_a_floor_changes_the_digest() -> None:
    ci = preset("ci")
    fail_on = replace(ci.policy.fail_on, min_graded_share=0.8)
    floored = replace(ci, policy=replace(ci.policy, fail_on=fail_on))

    assert profile_digest(floored) != _CI_PROFILE_DIGEST
