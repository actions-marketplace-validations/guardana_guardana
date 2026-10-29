"""What the judges configured under `evaluators:` spend lands in the run, apart from the target's.

Driven through `probe` against a fake endpoint and a fake judge, because the judges are
built from the profile there, meter their own calls there, and are read there once per
written run. A judge that fails, or runs out of budget, is named as the judge and never
as the target.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

import guardana.cli._endpoint as endpoint_module
import guardana.cli.monitor as monitor_module
import pytest
from _documents import run_manifest, scan_result
from guardana.cli._evaluators import JudgeMeters, wire_config_evaluators
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.profile import Profile
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.report.serialize import run_to_dict
from guardana.core.target import ChatMessage
from guardana.core.target.endpoint import ChatReply
from guardana.core.usage import TokenUsage
from typer.testing import CliRunner

runner = CliRunner()

_SUITE_ID = "acme.quality.answers"
_REPLY = "The answer is 42."
_JUDGE = "http://judge.test:8080/v1"
_TARGET = "http://model.test"


class _Priced:
    """A model and a judge that both answer, each reporting its own token cost."""

    target = 0
    judge = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer without saying what it cost."""
        return self.send_reporting_usage(base_url, model, messages, api_key).text

    def send_reporting_usage(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> ChatReply:
        """Answer, and say what it cost: the judge costs more going in than the model."""
        if "judge" in base_url:
            type(self).judge += 1
            return ChatReply("PASS: it answered", TokenUsage(input_tokens=40, output_tokens=3))
        type(self).target += 1
        return ChatReply(_REPLY, TokenUsage(input_tokens=10, output_tokens=5))


class _Unpriced:
    """A model and a judge that answer and never say what a request cost."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer the judge with a pass and the model with its reply."""
        return "PASS: it answered" if "judge" in base_url else _REPLY


class _JudgeRejects:
    """A model that answers fine, and a judge that refuses the key it was given."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer as the model; refuse as the judge."""
        if "judge" in base_url:
            raise HTTPError(f"{base_url}/v1/chat/completions", 401, "Unauthorized", {}, None)  # type: ignore[arg-type]
        return _REPLY


class _JudgeUnreachable:
    """A model that answers fine, and a judge nobody can connect to."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer as the model; fail to connect as the judge."""
        if "judge" in base_url:
            raise URLError(f"connection refused by {base_url}")
        return _REPLY


class _JudgeTimesOut:
    """A model that answers fine, and a judge whose reply never arrives."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Answer as the model; time out reading the reply as the judge."""
        if "judge" in base_url:
            raise TimeoutError("The read operation timed out")
        return _REPLY


def _suite(tmp_path: Path, *, cases: int, evaluator: str = "llm_judge") -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    header = {"guardana_dataset": 1, "name": "answers", "version": "1"}
    lines = [json.dumps(header)] + [json.dumps({"input": f"Q{n}?"}) for n in range(cases)]
    (rules / "answers.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    expect: dict[str, object] = (
        {"goal": "g"} if evaluator == "llm_judge" else {"contains_all": ["42"]}
    )
    rule = {
        "id": _SUITE_ID,
        "title": "The assistant still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": evaluator,
        "requires": ["chat"],
        "dataset": "./answers.jsonl",
        "expect": expect,
        "gate": {"min_pass_rate": 0.9, "min_sample": 1},
    }
    (rules / "answers.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _profile(tmp_path: Path, *extra: str, judge: str | None = _JUDGE, samples: int = 1) -> Path:
    lines = ["rules:", "  include: ['acme.*']", *extra]
    if judge is not None:
        lines += [
            "evaluators:",
            f"  llm_judge: {{endpoint: '{judge}', model: j, min_agreement: {samples}}}",
        ]
    path = tmp_path / "guardana.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _probe(
    monkeypatch: pytest.MonkeyPatch,
    transport: type,
    rules: Path,
    profile: Path,
    out: Path,
    *extra: str,
) -> Any:  # noqa: ANN401 — typer's Result
    monkeypatch.setattr(endpoint_module, "transport_factory", transport)
    return runner.invoke(
        app,
        [
            "probe",
            "--url",
            _TARGET,
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(out),
            *extra,
        ],
    )


def _usage(out: Path) -> dict[str, Any]:
    usage: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))["run"]["usage"]
    return usage


def _inspect(path: Path) -> list[str]:
    result = runner.invoke(app, ["run", "inspect", str(path)])
    assert result.exit_code == 0, result.output
    return result.output.splitlines()


# What a probe records


def test_a_probe_records_what_the_judge_spent_apart_from_the_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Four cases at K = 3 with three judge samples each: 12 model calls, 36 judge calls."""
    _Priced.target = _Priced.judge = 0
    out = tmp_path / "run.json"

    result = _probe(
        monkeypatch,
        _Priced,
        _suite(tmp_path, cases=4),
        _profile(tmp_path, samples=3),
        out,
        "--trials",
        "3",
    )

    # An uncalibrated judge's pass rate cannot be corrected, so the suite declines.
    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    usage = _usage(out)
    assert (usage["requests"], usage["input_tokens"], usage["output_tokens"]) == (12, 120, 60)
    assert usage["judge"] == {
        "llm_judge": {
            "requests": 36,
            "input_tokens": 36 * 40,
            "output_tokens": 36 * 3,
            "requests_missing_token_counts": 0,
            "budget_exhausted": False,
        }
    }
    assert (_Priced.target, _Priced.judge) == (12, 36), "the run counted what was sent"
    lines = _inspect(out)
    assert "  trials:    3 per case asked; 0 rule(s) and 1 suite(s) repeated" in lines
    assert "  judge:     llm_judge 36 request(s), tokens in 1440, out 108" in lines


def test_a_judge_that_reports_no_tokens_is_counted_as_unreported_never_as_free(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"

    result = _probe(monkeypatch, _Unpriced, _suite(tmp_path, cases=5), _profile(tmp_path), out)

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert _usage(out)["judge"]["llm_judge"] == {
        "requests": 5,
        "input_tokens": None,
        "output_tokens": None,
        "requests_missing_token_counts": 5,
        "budget_exhausted": False,
    }
    assert "  judge:     llm_judge 5 request(s), tokens in not recorded, out not recorded" in (
        _inspect(out)
    )


def test_a_probe_with_no_judge_configured_records_judge_usage_as_uncounted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"

    result = _probe(
        monkeypatch,
        _Unpriced,
        _suite(tmp_path, cases=3, evaluator="contains"),
        _profile(tmp_path, judge=None),
        out,
    )

    assert result.exit_code == 0, result.output
    assert _usage(out)["judge"] is None
    assert _usage(out)["requests"] == 3
    assert "  judge:     not counted" in _inspect(out)


def test_a_configured_judge_nobody_asked_is_counted_as_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"

    result = _probe(
        monkeypatch,
        _Unpriced,
        _suite(tmp_path, cases=3, evaluator="contains"),
        _profile(tmp_path),
        out,
    )

    assert result.exit_code == 0, result.output
    assert _usage(out)["judge"]["llm_judge"]["requests"] == 0


# A budget the judge ran out of


def test_a_run_stopped_by_the_judge_budget_says_so_and_never_reads_as_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Five cases and three judge samples each need fifteen judge calls under a ceiling of ten."""
    out = tmp_path / "run.json"

    result = _probe(
        monkeypatch,
        _Unpriced,
        _suite(tmp_path, cases=5),
        _profile(tmp_path, samples=3),
        out,
        "--max-requests",
        "10",
    )

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["run"]["result_summary"]["stopped_by"] == "budget_exhausted"
    judge = document["run"]["usage"]["judge"]["llm_judge"]
    assert judge["budget_exhausted"] is True
    assert judge["requests"] == 10, "the judge sent exactly its ceiling"
    assert document["run"]["usage"]["requests"] < 10, "the target's own meter never ran out"
    assert f"evaluators.llm_judge ({_JUDGE}) stopped the run: request budget of 10" in (
        result.stderr
    )
    lines = _inspect(out)
    assert "  stopped:   budget_exhausted (by evaluators.llm_judge) — coverage is partial" in lines
    assert (
        "  judge:     llm_judge 10 request(s), tokens in not recorded, out not recorded · "
        "its budget stopped the run"
    ) in lines


def test_a_run_stopped_by_the_target_budget_does_not_blame_the_judge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"

    result = _probe(
        monkeypatch,
        _Unpriced,
        _suite(tmp_path, cases=5),
        _profile(tmp_path),
        out,
        "--max-requests",
        "3",
        "--concurrency",
        "1",
    )

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    assert _usage(out)["judge"]["llm_judge"]["budget_exhausted"] is False
    assert "evaluators.llm_judge" not in result.stderr
    assert "  stopped:   budget_exhausted — coverage is partial" in _inspect(out)


def test_a_token_ceiling_the_judge_cannot_enforce_is_refused_in_the_judge_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"
    result = _probe(
        monkeypatch,
        _Unpriced,
        _suite(tmp_path, cases=1),
        _profile(tmp_path, judge=_JUDGE),
        out,
        "--max-input-tokens",
        "100",
    )

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"evaluators.llm_judge ({_JUDGE}): a token budget was set" in result.stderr


# A judge that cannot be used


@pytest.mark.parametrize(
    ("transport", "said"),
    [
        (
            _JudgeRejects,
            f"endpoint {_JUDGE} (evaluators.llm_judge) rejected the request (HTTP 401)",
        ),
        (_JudgeUnreachable, f"could not reach endpoint {_JUDGE} (evaluators.llm_judge)"),
        (_JudgeTimesOut, f"could not reach endpoint {_JUDGE} (evaluators.llm_judge)"),
    ],
    ids=["401", "unreachable", "timeout"],
)
def test_a_judge_failure_is_reported_as_the_judge_while_the_target_answers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, transport: type, said: str
) -> None:
    out = tmp_path / "run.json"
    result = _probe(
        monkeypatch,
        transport,
        _suite(tmp_path, cases=2),
        _profile(tmp_path, judge=_JUDGE),
        out,
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    errors = [line for line in result.stderr.splitlines() if line.startswith("error: ")]
    assert len(errors) == 1, result.stderr
    assert said in errors[0]
    assert _TARGET not in errors[0], "the target answered; it must not be blamed"
    assert "--api-key-env" not in errors[0], "the target's key is not the one that failed"
    assert not out.exists(), "a run whose grading failed writes no verdict"


# Monitor


def test_every_monitor_cycle_counts_its_own_judge_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each cycle grades three cases once; a meter carried over would read six on the second."""
    armed: list[JudgeMeters] = []

    def recording(registry: Registry, profile: Profile, budgets: Any = None) -> JudgeMeters:  # noqa: ANN401
        meters = wire_config_evaluators(registry, profile, budgets)
        armed.append(meters)
        return meters

    monkeypatch.setattr(monitor_module, "wire_config_evaluators", recording)
    monkeypatch.setattr(endpoint_module, "transport_factory", _Unpriced)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            _TARGET,
            "--model",
            "m",
            "--rules",
            str(_suite(tmp_path, cases=3)),
            "--profile",
            str(_profile(tmp_path)),
            "--max-cycles",
            "2",
            "--interval",
            "0",
        ],
    )

    # Every cycle's suite declines for want of a calibrated judge, so the watch ends
    # indeterminate, as a probe of the same cycle would.
    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    cycles = armed[1:]  # the first is wired before the loop, to refuse a bad config early
    assert len(cycles) == 2
    assert [meters.usage() for meters in cycles] == [cycles[0].usage()] * 2
    spent = cycles[1].usage()
    assert spent is not None
    assert spent["llm_judge"].requests == 3


# Inspecting a saved run


def test_inspect_counts_suites_among_what_repeated_and_prints_every_judge(
    tmp_path: Path,
) -> None:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(run_to_dict(scan_result(), run_manifest())), encoding="utf-8")

    lines = _inspect(path)

    assert "  trials:    3 per case asked; 1 rule(s) and 1 suite(s) repeated" in lines
    assert (
        "  judge:     llm_judge 30 request(s), tokens in 9000, out 600 · its budget stopped the run"
    ) in lines
    assert "  judge:     guard 12 request(s), tokens in not recorded, out not recorded" in lines
    assert "  stopped:   budget_exhausted (by evaluators.llm_judge) — coverage is partial" in lines


def test_a_spent_judge_budget_raises_in_the_judge_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _Unpriced)
    profile = Profile(
        name="t",
        policy=Policy(),
        evaluator_config={"llm_judge": {"endpoint": _JUDGE, "model": "j"}},
    )
    (meter,) = wire_config_evaluators(Registry(), profile, Budgets(max_requests=1)).meters

    meter.ask("grade this")
    with pytest.raises(BudgetExhausted, match=r"^evaluators\.llm_judge \(http://judge\.test"):
        meter.ask("grade this too")

    assert meter.usage().requests == 1
    assert meter.usage().budget_exhausted is True
