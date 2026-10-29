"""`--max-requests-per-minute`: a pace from the command line, and the wall time it costs.

The flag wins over the profile as the other budget flags do, and sets only the pace;
`plan probe` states the wall time the estimated requests need at that pace and refuses a
duration ceiling that ends before the last of them is sent, before anything is sent.
"""

import json
import re
from collections.abc import Sequence
from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli._budget_flags import override
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.budget import Budgets
from guardana.core.target.endpoint import ChatMessage
from jsonschema import Draft202012Validator
from typer.testing import CliRunner, Result

runner = CliRunner()

_SCHEMA = Path(__file__).resolve().parents[3] / "schemas" / "plan-v4.schema.json"


class _RefusesToBeCalled:
    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        raise AssertionError("guardana plan must not send a request")


def _plain(text: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", text).split())


def _profile(tmp_path: Path, budgets: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(f"name: paced\nbudgets:\n{budgets}", encoding="utf-8")
    return path


def _plan(monkeypatch: pytest.MonkeyPatch, *args: str) -> Result:
    monkeypatch.setattr(endpoint_module, "transport_factory", _RefusesToBeCalled)
    return runner.invoke(app, ["plan", "probe", "--url", "http://fake", "--model", "m", *args])


def test_the_flag_wins_over_the_profiles_rate_and_leaves_the_other_ceilings() -> None:
    configured = Budgets(max_requests=50, max_duration_seconds=600.0, max_requests_per_minute=30)

    assert override(configured, max_requests_per_minute=120) == Budgets(
        max_requests=50, max_duration_seconds=600.0, max_requests_per_minute=120
    )


def test_a_rate_flag_left_out_keeps_the_profiles_rate() -> None:
    configured = Budgets(max_requests_per_minute=30)

    assert override(configured, max_requests=10).max_requests_per_minute == 30


def test_another_budget_flag_never_clears_the_profiles_rate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path, "  max_requests_per_minute: 6000\n")

    payload = json.loads(
        _plan(
            monkeypatch, "--profile", str(profile), "--max-requests", "100000", "--format", "json"
        ).output
    )

    assert payload["budgets"]["max_requests_per_minute"] == 6000


def test_the_rate_flag_reaches_the_plan_over_the_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path, "  max_requests_per_minute: 6000\n")

    payload = json.loads(
        _plan(
            monkeypatch,
            "--profile",
            str(profile),
            "--max-requests-per-minute",
            "60",
            "--format",
            "json",
        ).output
    )

    assert payload["budgets"]["max_requests_per_minute"] == 60
    assert payload["budgets"]["minimum_wall_time_seconds"] == float(payload["requests"]["max"] - 1)


def test_a_plan_states_the_wall_time_its_rate_needs(monkeypatch: pytest.MonkeyPatch) -> None:
    ceiling = json.loads(_plan(monkeypatch, "--format", "json").output)["requests"]["max"]

    result = _plan(monkeypatch, "--max-requests-per-minute", "60")

    assert result.exit_code == ExitCode.OK, result.output
    stated = f"wall time: {ceiling - 1}s for the estimated requests at 60 request(s) per minute"
    assert stated in _plain(result.output)


def test_a_duration_ceiling_below_the_floor_is_refused_before_anything_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _plan(monkeypatch, "--max-requests-per-minute", "1", "--max-duration", "1m")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "does not fit its time budget" in _plain(result.output)


def test_a_duration_ceiling_above_the_floor_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _plan(monkeypatch, "--max-requests-per-minute", "6000", "--max-duration", "1h")

    assert result.exit_code == ExitCode.OK, result.output


def test_a_refused_plan_says_it_does_not_fit_in_its_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _plan(
        monkeypatch, "--max-requests-per-minute", "1", "--max-duration", "1m", "--format", "json"
    )

    assert json.loads(result.stdout)["fits_budget"] is False


def test_a_paced_plan_document_satisfies_schema_four(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.loads(
        _plan(monkeypatch, "--max-requests-per-minute", "60", "--format", "json").output
    )

    Draft202012Validator(json.loads(_SCHEMA.read_text(encoding="utf-8"))).validate(payload)
    assert payload["schema_version"] == 4


def test_an_unpaced_plan_states_no_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.loads(_plan(monkeypatch, "--format", "json").output)

    assert payload["budgets"]["max_requests_per_minute"] is None
    assert payload["budgets"]["minimum_wall_time_seconds"] is None


def test_config_explain_lists_the_rate(tmp_path: Path) -> None:
    profile = _profile(tmp_path, "  max_requests_per_minute: 30\n")

    result = runner.invoke(
        app, ["config", "explain", "--profile", str(profile), "--format", "json"]
    )

    assert result.exit_code == ExitCode.OK, result.output
    assert json.loads(result.stdout)["budgets"]["max_requests_per_minute"] == 30


@pytest.mark.parametrize("command", ["probe", "grade"])
def test_the_run_commands_take_the_rate_flag(command: str) -> None:
    result = runner.invoke(app, [command, "--help"], env={"COLUMNS": "200"})

    assert "--max-requests-per-minute" in _plain(result.output)
