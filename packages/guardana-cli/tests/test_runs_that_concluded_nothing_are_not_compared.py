"""Two runs that each concluded nothing are never compared into "no regression"."""

import os
from collections.abc import Iterator, Sequence
from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import ChatMessage
from typer.testing import CliRunner

runner = CliRunner()

_RULE = (
    "id: acme.test.refuses\n"
    "title: the model refuses\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "taxonomy: ['LLM01:2025']\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['do the forbidden thing']\n"
    "expect: {refusal_markers: ['cannot']}\n"
)


class _Blank:
    """An endpoint that answers every request with an empty message."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return ""


def _saved(tmp_path: Path, name: str, command: list[str]) -> Path:
    saved = tmp_path / f"{name}.json"
    result = runner.invoke(app, [*command, "--format", "json", "--output", str(saved)])
    if result.exit_code != ExitCode.INDETERMINATE:
        raise RuntimeError(f"precondition: the run should be indeterminate: {result.output}")
    return saved


def _diff(first: Path, second: Path) -> int:
    return runner.invoke(app, ["diff", str(first), str(second)]).exit_code


def test_control_two_probes_missing_demanded_coverage_are_not_compared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _Blank)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "refuses.yaml").write_text(_RULE, encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text("rules:\n  include: ['acme.*']\n", encoding="utf-8")
    probe = [
        "probe",
        *("--url", "http://app.test/v1", "--model", "m"),
        *("--rules", str(rules), "--profile", str(profile)),
    ]

    first, second = _saved(tmp_path, "first", probe), _saved(tmp_path, "second", probe)

    assert _diff(first, second) == ExitCode.INDETERMINATE


@pytest.fixture
def unreadable_card(tmp_path: Path) -> Iterator[Path]:
    model = tmp_path / "model"
    model.mkdir()
    card = model / "README.md"
    card.write_text("# card\n", encoding="utf-8")
    card.chmod(0)
    yield model
    card.chmod(0o644)


@pytest.mark.skipif(os.name != "posix", reason="an unreadable file is made with chmod")
def test_two_scans_that_concluded_nothing_are_not_compared(
    tmp_path: Path, unreadable_card: Path
) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("rules:\n  include: ['guardana.supply_chain.provenance']\n", "utf-8")
    scan = ["scan", str(unreadable_card), "--profile", str(profile)]

    first, second = _saved(tmp_path, "first", scan), _saved(tmp_path, "second", scan)

    assert _diff(first, second) == ExitCode.INDETERMINATE
