"""A plan refuses exactly the runs the gate would refuse for what is known before them.

`RunPlan.blockers` reads the gate's own open questions off a result of the planned
rules, so each scenario below is run both ways under a strict and a lenient preset. The
one direction a plan cannot see is a check that runs and declines: only the run knows.
"""

from collections.abc import Iterable
from pathlib import Path

import pytest
from guardana.core.evaluator.base import Expectation, Verdict
from guardana.core.gate import GateOutcome, OpenQuestion, gate_outcome
from guardana.core.plan import build_plan
from guardana.core.profile import Profile, preset
from guardana.core.registry import Registry
from guardana.core.report import CheckError, Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleLoadError, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind


class _Clean(Rule):
    """Reads the target and finds nothing."""

    meta = RuleMeta(
        "acme.parity.clean",
        "clean",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing."""
        return ()


class _NeedsChat(Rule):
    """Needs a capability a directory never has, so it is skipped."""

    meta = RuleMeta(
        "acme.parity.chat",
        "chat",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Never reached."""
        return ()


class _Declines(Rule):
    """Runs and cannot reach a verdict."""

    meta = RuleMeta(
        "acme.parity.declines",
        "declines",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Yield one inconclusive verdict."""
        yield Finding(
            self.meta.id,
            self.meta.severity,
            "unverified",
            (),
            target.ref,
            Evidence(summary="could not verify"),
            verdict=Verdict("inconclusive", 0.0, "judge unreachable", "acme_judge"),
        )


class _GradedByNobody(Rule):
    """Grades with a judge no profile configured, so it raises when it starts."""

    meta = RuleMeta(
        "acme.parity.judged",
        "judged",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
        evaluator="acme_judge",
    )

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Name the judge this rule grades with."""
        return (("acme_judge", Expectation(goal="refuses")),)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Raise as a declarative rule does when its evaluator is not registered."""
        if "acme_judge" not in ctx.evaluators:
            raise RuleLoadError("unknown evaluator: 'acme_judge'")
        return ()


@pytest.fixture(autouse=True)
def _a_file_to_scan(tmp_path: Path) -> None:
    """Give every scanned directory a file, so only the scenario decides the outcome."""
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")


def _registry(*rules: Rule, load_error: bool = False) -> Registry:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    if load_error:
        registry.record_load_error(
            CheckError(source="acme-pack", stage="discovery", reason="plugin failed to import")
        )
    return registry


def _both_ways(registry: Registry, profile: Profile, tmp_path: Path) -> tuple[bool, bool]:
    """Return whether the plan refuses and whether the run fails to pass, for one setup."""
    plan_refuses = bool(
        build_plan(registry, profile, ArtifactTarget(tmp_path)).blockers(profile.policy.fail_on)
    )
    result = Runner(registry=registry, profile=profile).run(ArtifactTarget(tmp_path))
    run_refuses = gate_outcome(result, profile.policy) is not GateOutcome.PASS
    return plan_refuses, run_refuses


_KNOWN_BEFORE_THE_RUN = {
    "every rule runnable and clean": ((_Clean,), False, {"release": False, "ci": False}),
    "a rule the target cannot satisfy": (
        (_Clean, _NeedsChat),
        False,
        {"release": True, "ci": False},
    ),
    "a registry load error": ((_Clean,), True, {"release": True, "ci": True}),
    "zero rules selected": ((), False, {"release": True, "ci": True}),
    "a rule graded by an evaluator nobody registered": (
        (_Clean, _GradedByNobody),
        False,
        {"release": True, "ci": True},
    ),
}


@pytest.mark.parametrize("preset_name", ["release", "ci"])
@pytest.mark.parametrize("scenario", list(_KNOWN_BEFORE_THE_RUN))
def test_the_plan_and_the_gate_agree_on_what_is_known_before_the_run(
    tmp_path: Path, scenario: str, preset_name: str
) -> None:
    rule_types, load_error, refused = _KNOWN_BEFORE_THE_RUN[scenario]
    registry = _registry(*(rule_type() for rule_type in rule_types), load_error=load_error)

    plan_refuses, run_refuses = _both_ways(registry, preset(preset_name), tmp_path)

    assert (plan_refuses, run_refuses) == (refused[preset_name], refused[preset_name])


@pytest.mark.parametrize("preset_name", ["release", "ci"])
def test_the_plan_and_the_gate_both_refuse_a_directory_with_no_file(
    tmp_path: Path, preset_name: str
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    assert _both_ways(_registry(_Clean()), preset(preset_name), empty) == (True, True)


def test_a_planned_skip_carries_the_reason_and_words_the_run_records(tmp_path: Path) -> None:
    registry = _registry(_Clean(), _NeedsChat())
    profile = preset("release")

    plan = build_plan(registry, profile, ArtifactTarget(tmp_path))
    result = Runner(registry=registry, profile=profile).run(ArtifactTarget(tmp_path))

    assert plan.skipped == result.rules_skipped
    assert plan.blockers(profile.policy.fail_on) == (OpenQuestion.SKIPPED,)


def test_a_check_that_declines_is_the_one_refusal_a_plan_cannot_foresee(tmp_path: Path) -> None:
    registry = _registry(_Clean(), _Declines())

    assert _both_ways(registry, preset("release"), tmp_path) == (False, True)
    assert _both_ways(registry, preset("ci"), tmp_path) == (False, False)


def test_a_planned_unknown_evaluator_is_the_error_the_run_records(tmp_path: Path) -> None:
    registry = _registry(_Clean(), _GradedByNobody())
    profile = preset("release")

    planned = build_plan(registry, profile, ArtifactTarget(tmp_path)).errors
    recorded = Runner(registry=registry, profile=profile).run(ArtifactTarget(tmp_path)).errors

    assert planned == recorded
