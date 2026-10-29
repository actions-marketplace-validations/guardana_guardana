"""Every kind of run hands its rules the calibrations its manifest records.

A manifest that names a calibration the rules never read would show a judge-graded
check as calibrated when it was not.
"""

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from guardana.core.calibration.store import RecordedCalibration
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, McpServerTarget, Target, TargetKind
from guardana.core.testing import ScriptedMcpServer
from guardana.core.verify import Verifier

_MEASURED = {
    "llm_judge": RecordedCalibration(
        evaluator="llm_judge",
        dataset_digest="sha256:" + "ab" * 32,
        measured_at=datetime(2026, 1, 1, tzinfo=UTC),
        brier=0.1,
        ece=0.05,
        samples=60,
    )
}


class _ReadsCalibrations(Rule):
    """Records the calibrations it was handed, and finds nothing."""

    def __init__(self, kind: TargetKind, needs: Capability) -> None:
        self.meta = RuleMeta(
            id=f"acme.reads_calibrations.{kind}",
            title="reads the calibrations it is handed",
            severity=Severity.LOW,
            target_kind=kind,
            required_capabilities=frozenset({needs}),
        )
        self.seen: list[set[str]] = []

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        self.seen.append(set(ctx.calibrations))
        return ()


def _target(kind: TargetKind, tmp_path: Path) -> Target:
    if kind is TargetKind.ARTIFACT:
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
        return ArtifactTarget(tmp_path)
    server = ScriptedMcpServer("https://93.184.215.14/mcp", tools=[{"name": "t"}])
    return McpServerTarget(server.url, sender=server, discovery_sender=server)


@pytest.mark.parametrize(
    ("kind", "needs"),
    [(TargetKind.ARTIFACT, Capability.READ_FILES), (TargetKind.ENDPOINT, Capability.LIST_TOOLS)],
)
def test_the_rules_read_the_calibrations_the_manifest_records(
    kind: TargetKind, needs: Capability, tmp_path: Path
) -> None:
    rule = _ReadsCalibrations(kind, needs)
    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.DISABLED), rules=(rule,), calibrations=_MEASURED
    )

    verifier.run(_target(kind, tmp_path))

    assert rule.seen == [{"llm_judge"}]
