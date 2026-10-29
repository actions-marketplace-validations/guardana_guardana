"""Under `metadata_only`, a waiver still covers one finding, never its neighbours.

A waiver matches on rule, file and evidence summary. Withholding every summary as the
same note made two findings of one rule in one file indistinguishable, so a baseline
written for the first key waived a second key added later, and the scan exited `0`.
"""

from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report import Evidence, Finding
from guardana.core.severity import Severity
from guardana.core.testing import fake_aws_key, fake_llm_key
from typer.testing import CliRunner

_PROFILE = "name: private\nprivacy:\n  evidence_mode: metadata_only\n"
runner = CliRunner()


def _scan(*args: str) -> int:
    return runner.invoke(app, ["scan", "tree", "--profile", "guardana.yaml", *args]).exit_code


def test_a_new_secret_beside_a_waived_one_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "guardana.yaml").write_text(_PROFILE, encoding="utf-8")
    (tmp_path / "tree").mkdir()
    settings = tmp_path / "tree" / "settings.py"
    settings.write_text(f'AWS = "{fake_aws_key()}"\n', encoding="utf-8")
    assert _scan() == ExitCode.POLICY_FAILED
    assert _scan("--write-baseline", "baseline.yaml") == ExitCode.OK
    assert _scan("--baseline", "baseline.yaml") == ExitCode.OK

    settings.write_text(f'AWS = "{fake_aws_key()}"\nLLM = "{fake_llm_key()}"\n', encoding="utf-8")

    assert _scan("--baseline", "baseline.yaml") == ExitCode.POLICY_FAILED


def test_withholding_a_summary_twice_changes_nothing() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))
    finding = Finding(
        rule_id="guardana.supply_chain.secrets",
        severity=Severity.HIGH,
        title="a key",
        taxonomy=(),
        target_ref="settings.py:1",
        evidence=Evidence(summary=f"key {fake_aws_key()} assigned"),
    )

    once = redactor.redact(finding)

    assert fake_aws_key() not in once.evidence.summary
    assert redactor.redact(once) == once
