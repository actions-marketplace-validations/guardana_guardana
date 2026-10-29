"""`probe --preset release` of a chat endpoint is not held open by MCP or A2A rules.

A chat endpoint speaks no MCP and no A2A, so those rules have nothing to check there and
are saved as `not_applicable`. What the endpoint still misses within chat — the seeded
data a run without fixtures lacks — stays a coverage gap the release gate names.
"""

from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import SkipReason, load_report
from guardana.core.target import WireProtocol, wire_protocols_of
from guardana.core.testing import ToolCallingScriptedTransport
from typer.testing import CliRunner

runner = CliRunner()


def _probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, Path]:
    monkeypatch.setattr(
        endpoint_module,
        "transport_factory",
        lambda: ToolCallingScriptedTransport(text="I cannot help with that."),
    )
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://model.test",
            "--model",
            "m",
            "--preset",
            "release",
            "--concurrency",
            "1",
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    return result.exit_code, saved


def _examining_another_protocol() -> set[str]:
    """Every built-in rule whose capabilities examine only protocols other than chat."""
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    return {
        rule.meta.id
        for rule in registry.rules()
        if (needed := wire_protocols_of(rule.meta.required_capabilities))
        and WireProtocol.CHAT not in needed
    }


def test_a_release_probe_saves_the_rules_of_other_protocols_as_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _code, saved = _probe(tmp_path, monkeypatch)

    result = load_report(saved).result
    skipped = {s.rule_id: s for s in result.rules_skipped}
    selected = {*skipped, *result.rules_run}
    other = _examining_another_protocol() & selected
    assert len(other) >= 13
    reasons = {
        rule_id: skipped[rule_id].reason if rule_id in skipped else "run" for rule_id in other
    }
    assert reasons == dict.fromkeys(other, SkipReason.NOT_APPLICABLE)
    assert all("speaks chat" in skipped[rule_id].detail for rule_id in other)


def test_a_release_probe_is_held_open_only_by_what_the_chat_endpoint_lacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, saved = _probe(tmp_path, monkeypatch)

    gaps = {s.rule_id for s in load_report(saved).result.rules_skipped if s.is_coverage_gap}
    assert gaps == {"guardana.retrieval.poisoned_document", "guardana.tenancy.cross_tenant_answer"}
    assert code == ExitCode.INDETERMINATE
