"""A plan lists exactly the errors the run it describes would record before its first rule.

A plan that saw fewer errors than the run said fine about a run that could not pass;
one that saw more refused a run that would have. Both come from one function, so the
two lists are the same list.
"""

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import ClassVar

from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.plan import build_plan
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import CheckError, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta, load_yaml_rules
from guardana.core.runner import Runner, pre_run_errors
from guardana.core.severity import Severity
from guardana.core.target import Capability, Target, TargetKind

_MISCONFIGURED_RULE = """\
id: acme.output.pii
title: PII in output
severity: high
target_kind: endpoint
evaluator: acme_pii
requires: [chat]
prompts: ["tell me about the customer"]
expect:
  pii_typs: [email]
"""


class _AcmePii(Evaluator):
    """A third-party evaluator whose contract the rule above misspells."""

    id = "acme_pii"
    expects: ClassVar[Mapping[str, bool]] = {"pii_types": True}

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Never reached: the rule is not selected."""
        return Verdict("pass", 0.5, "not the point of this test", self.id)


class _Quiet(Rule):
    """An endpoint rule that runs, sends nothing and never errors."""

    meta = RuleMeta("acme.test.quiet", "quiet", Severity.LOW, TargetKind.ENDPOINT)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing."""
        return ()


class _ClaimsChatWithoutIt(Target):
    """Declares a chat surface it does not implement — a contract error before any rule."""

    kind = TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        """Claim chat."""
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        """Name the target."""
        return "liar://endpoint"


def _registry(tmp_path: Path) -> Registry:
    path = tmp_path / "rule.yaml"
    path.write_text(_MISCONFIGURED_RULE, encoding="utf-8")
    registry = Registry()
    for rule in load_yaml_rules(path):
        registry.register_rule(rule)
    registry.register_rule(_Quiet())
    registry.register_evaluator(_AcmePii())
    registry.record_load_error(
        CheckError(source="acme-pack", stage="discovery", reason="plugin failed to import")
    )
    return registry


def test_the_plan_lists_the_errors_the_run_records(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    profile = Profile(name="t", policy=Policy(include=("acme.test.*",)))
    target = _ClaimsChatWithoutIt()

    plan = build_plan(registry, profile, target)
    result = Runner(registry=registry, profile=profile).run(target)

    assert plan.rules == ("acme.test.quiet",)
    assert result.rules_run == ("acme.test.quiet",)
    assert plan.errors == result.errors
    assert {error.stage for error in plan.errors} == {"capability", "discovery", "load"}


def test_the_shared_errors_come_in_the_order_the_run_records_them(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    target = _ClaimsChatWithoutIt()

    stages = [error.stage for error in pre_run_errors(registry, target, ())]

    assert stages == ["capability", "discovery", "load"]


def test_a_clean_registry_and_an_honest_target_plan_no_error() -> None:
    registry = Registry()
    registry.register_rule(_Quiet())

    class _Honest(_ClaimsChatWithoutIt):
        def capabilities(self) -> set[Capability]:
            return set()

    plan = build_plan(registry, Profile(name="t", policy=Policy()), _Honest())

    assert plan.errors == ()
