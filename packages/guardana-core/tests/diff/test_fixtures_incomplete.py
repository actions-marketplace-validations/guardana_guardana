"""Two runs given different fixtures, or fixtures on one side only, are an incomplete comparison.

An item one fixtures file declares and the other does not was asked about by one run
only, so a finding on it that disappears is not a fixed leak. That is incompleteness, not
a note: it fails the comparison whatever the policy says.
"""

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from guardana.core.diff import compare_reports, gate_diff
from guardana.core.gate import GateOutcome
from guardana.core.manifest import FixturesRecord, RunManifest, TargetIdentity, ToolInfo
from guardana.core.manifest.records import ResultSummary
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings
from guardana.core.manifest.usage import RunUsage
from guardana.core.profile import Policy
from guardana.core.report import RunReport, ScanResult
from guardana.core.target import TargetKind

_RULE = "guardana.tenancy.cross_tenant_answer"


def _fixtures(digest: str) -> FixturesRecord:
    return FixturesRecord(
        name="support-bot",
        digest=digest,
        data="synthetic",
        tenants=("acme", "globex"),
        documents=3,
        records=0,
        tools=0,
        markers=1,
    )


_A = _fixtures("sha256:" + "aa" * 32)
_B = _fixtures("sha256:" + "bb" * 32)


def _report(day: int, fixtures: FixturesRecord | None) -> RunReport:
    when = datetime(2026, 8, day, tzinfo=UTC)
    manifest = RunManifest(
        run_id=f"r{day}",
        created_at=when,
        started_at=when,
        completed_at=when,
        guardana=ToolInfo(version="0.37.0"),
        target=TargetIdentity(kind=TargetKind.ENDPOINT, ref="http://x#m"),
        configuration=ConfigurationRef(profile_name="default"),
        execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
        usage=RunUsage(),
        result_summary=ResultSummary(
            findings=0,
            unverified=0,
            waived=0,
            errors=0,
            observations=0,
            rules_run=(_RULE,),
            rules_skipped=(),
            max_severity=None,
            gate=GateOutcome.PASS,
        ),
    )
    return RunReport(
        manifest=replace(manifest, fixtures=fixtures),
        result=ScanResult(findings=(), rules_run=(_RULE,), rules_skipped=()),
    )


@pytest.mark.parametrize(
    ("before", "after", "says"),
    [
        (_A, _B, "given different fixtures"),
        (_A, None, "only the first run was given fixtures"),
        (None, _B, "only the second run was given fixtures"),
        (_A, replace(_A, markers=2), "different algorithms (1 and 2)"),
    ],
    ids=["different digests", "first only", "second only", "different markers"],
)
def test_a_change_of_fixtures_makes_the_comparison_incomplete(
    before: FixturesRecord | None, after: FixturesRecord | None, says: str
) -> None:
    diff = compare_reports(_report(1, before), _report(2, after))

    assert any(says in reason for reason in diff.incomplete), diff.incomplete
    assert not any("fixtures" in note for note in diff.notes)
    assert gate_diff(diff, Policy())


@pytest.mark.parametrize(
    ("before", "after"), [(_A, _A), (None, None)], ids=["same fixtures", "neither"]
)
def test_the_same_fixtures_or_none_leave_the_comparison_complete(
    before: FixturesRecord | None, after: FixturesRecord | None
) -> None:
    diff = compare_reports(_report(1, before), _report(2, after))

    assert diff.incomplete == ()
    assert not gate_diff(diff, Policy())
