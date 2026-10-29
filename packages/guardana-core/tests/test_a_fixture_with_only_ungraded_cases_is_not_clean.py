"""A fixture whose rule only recorded an ungraded case never passes as clean."""

from collections.abc import Iterable

from guardana.core.assessment import from_verdict
from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome, RuleFixture, materialise
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM03_2026
from guardana.core.testing import files_target

_UNGRADED = Verdict(
    outcome="inconclusive", confidence=0.0, rationale="no reply", evaluator_id="acme"
)


class _RecordsOnly(Rule):
    """Fires on `bad.txt`, declines on `odd.txt`, and only records an ungraded case otherwise."""

    meta = RuleMeta(
        id="acme.test.records_only",
        title="Records only",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03_2026,),
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a finding, a declined case and a case that is only recorded as ungraded."""
        return materialise(
            (
                DeclaredFixture(
                    "fires", FixtureOutcome.FINDING, lambda: files_target({"bad.txt": "x"})
                ),
                DeclaredFixture(
                    "ungraded", FixtureOutcome.CLEAN, lambda: files_target({"plain.txt": "x"})
                ),
                DeclaredFixture(
                    "declines", FixtureOutcome.INCONCLUSIVE, lambda: files_target({"odd.txt": "x"})
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report, decline or record an ungraded case, by the file the target holds."""
        names = {path.name for path in target.iter_files((".txt",))}  # type: ignore[attr-defined]
        if "bad.txt" in names:
            yield Finding(self.meta.id, Severity.HIGH, "x", (), target.ref, Evidence("found"))
        elif "odd.txt" in names:
            yield Finding(
                self.meta.id, Severity.HIGH, "x", (), target.ref, Evidence("declined"), _UNGRADED
            )
        else:
            ctx.record(
                from_verdict(_UNGRADED, case_id="c1", subject_ref=target.ref, rule_id=self.meta.id)
            )


def _ungraded() -> RuleFixture:
    (fixture,) = [f for f in _RecordsOnly().fixtures() if f.name == "ungraded"]
    return fixture


def test_control_a_run_over_the_ungraded_sample_is_indeterminate() -> None:
    registry = Registry()
    registry.register_rule(_RecordsOnly())
    profile = Profile("t", Policy())

    result = Runner(registry=registry, profile=profile, calibrations={}).run(_ungraded().target)

    assert gate_outcome(result, profile.policy) is GateOutcome.INDETERMINATE


def test_the_ungraded_sample_does_not_pass_as_clean() -> None:
    verification = verify_rule(_RecordsOnly(), RuleContext())

    (ungraded,) = [r for r in verification.results if r.fixture == "ungraded"]
    assert ungraded.verdict is not FixtureVerdict.PASSED, ungraded
