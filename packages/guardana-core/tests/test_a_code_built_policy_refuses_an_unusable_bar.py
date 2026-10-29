"""A policy built in code never turns measured failures into a pass through an unusable bar."""

import math
from collections.abc import Iterable
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM03_2026
from guardana.core.verify import Verifier


class _Graded(Rule):
    """Reports one failure an evaluator graded with confidence 0.9."""

    meta = RuleMeta(
        id="acme.test.graded",
        title="Graded",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03_2026,),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report the graded failure once, whatever the target holds."""
        verdict = Verdict("fail", 0.9, "complied", "acme")
        yield Finding(self.meta.id, Severity.HIGH, "x", (), target.ref, Evidence("e"), verdict)


def _exit_code(tmp_path: Path, min_confidence: float) -> int:
    """Scan through the facade under `min_confidence`; a refused policy reads as exit 3."""
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    try:
        verifier = Verifier(
            trust=PluginTrust(mode=PluginMode.BUILTINS),
            profile=Profile(
                "code", Policy(include=("acme.*",), fail_on=FailOn(min_confidence=min_confidence))
            ),
            rules=(_Graded(),),
        )
        verification = verifier.scan(tmp_path)
    except ValueError:
        return 3
    if not verification.result.findings:
        raise RuntimeError("precondition: the run should record the graded failure")
    return verification.exit_code


def test_control_a_graded_failure_above_the_bar_fails_the_run(tmp_path: Path) -> None:
    assert _exit_code(tmp_path, 0.7) == 1


def test_a_nan_confidence_bar_never_passes_a_graded_failure(tmp_path: Path) -> None:
    assert _exit_code(tmp_path, math.nan) != 0
