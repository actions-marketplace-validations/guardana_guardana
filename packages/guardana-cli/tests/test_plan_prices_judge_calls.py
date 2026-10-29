"""`plan probe` prices the judge calls a judge-graded run adds, and `plan scan` never does.

Each judge counts its calls on a meter of its own under the same request ceiling as
the target. A plan that priced the target alone said such a run fit a budget the
judge then exhausted, and the run stopped with no verdict.
"""

import json
from collections.abc import Sequence
from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import guardana.core.evaluator.config as evaluators_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.target import ChatMessage
from guardana.core.target.endpoint import ChatReply
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

runner = CliRunner()

_SCHEMA = Path(__file__).resolve().parents[3] / "schemas" / "plan-v4.schema.json"
_JUDGE = "  llm_judge: {endpoint: 'http://judge.test/v1', model: j, min_agreement: 3}"


class _RefusesToBeCalled:
    """Any request at all fails the test: a plan contacts neither the model nor the judge."""

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        raise AssertionError("guardana plan must not send a request")


class _ReportsUsageButRefuses(_RefusesToBeCalled):
    """A transport that could enforce a token ceiling, and still must not be called."""

    def send_reporting_usage(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> ChatReply:
        raise AssertionError("guardana plan must not send a request")


class _CountsJudgeCalls:
    """A model that answers, and a judge that passes, counting the judge's calls."""

    judge_calls = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        if "judge" in base_url:
            type(self).judge_calls += 1
            return "PASS: agrees"
        return "The answer is 42."


def _rules(tmp_path: Path, *, cases: int, evaluator: str, expect: dict[str, object]) -> Path:
    """A rules directory holding one suite of `cases` cases graded by `evaluator`."""
    rules = tmp_path / "rules"
    rules.mkdir()
    _suite(rules, "answers", cases=cases, evaluator=evaluator, expect=expect)
    return rules


def _suite(
    rules: Path, name: str, *, cases: int, evaluator: str, expect: dict[str, object]
) -> None:
    """Write suite `acme.quality.<name>` of `cases` cases graded by `evaluator` into `rules`."""
    header = {"guardana_dataset": 1, "name": name, "version": "1"}
    lines = [json.dumps(header)] + [json.dumps({"input": f"Q{n}?"}) for n in range(cases)]
    (rules / f"{name}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    common = {
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": evaluator,
        "requires": ["chat"],
        "expect": expect,
    }
    suite = {
        **common,
        "id": f"acme.quality.{name}",
        "title": f"The assistant still answers {name}",
        "dataset": f"./{name}.jsonl",
        "gate": {"min_pass_rate": 0.9, "min_sample": 1},
    }
    (rules / f"{name}.yaml").write_text(json.dumps(suite), encoding="utf-8")


def _profile(tmp_path: Path, *extra: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text("\n".join(["rules:", "  include: ['acme.*']", *extra]) + "\n", "utf-8")
    return path


def _plan(
    monkeypatch: pytest.MonkeyPatch,
    *args: str,
    transport: type[_RefusesToBeCalled] = _RefusesToBeCalled,
) -> tuple[int, str]:
    monkeypatch.setattr(endpoint_module, "transport_factory", transport)
    result = runner.invoke(
        app, ["plan", "probe", "--url", "http://model.test", "--model", "m", *args]
    )
    return result.exit_code, result.output


def _judged_suite(tmp_path: Path) -> tuple[Path, Path]:
    rules = _rules(tmp_path, cases=30, evaluator="reference_judge", expect={"reference": "42"})
    return rules, _profile(tmp_path, "evaluators:", _JUDGE)


def test_a_judged_suite_is_priced_at_cases_times_trials_times_samples(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules, profile = _judged_suite(tmp_path)

    code, output = _plan(
        monkeypatch,
        "--rules",
        str(rules),
        "--profile",
        str(profile),
        "--trials",
        "3",
        "--format",
        "json",
    )

    assert code == ExitCode.OK, output
    document = json.loads(output)
    Draft202012Validator(json.loads(_SCHEMA.read_text(encoding="utf-8"))).validate(document)
    assert document["requests"]["max"] == 90
    assert document["judge_calls"]["max"] == 270
    assert document["judge_calls"]["meters"] == [
        {"evaluators": ["llm_judge", "reference_judge"], "max": 270}
    ]
    assert document["judge_calls"]["complete"] is True


def _judge_and_guard(tmp_path: Path) -> tuple[Path, Path]:
    """Suites graded by each config-built evaluator, under a profile with a judge and a guard."""
    rules = tmp_path / "rules"
    rules.mkdir()
    _suite(rules, "goals", cases=4, evaluator="llm_judge", expect={"goal": "g"})
    _suite(rules, "answers", cases=5, evaluator="reference_judge", expect={"reference": "42"})
    _suite(rules, "safety", cases=6, evaluator="guard", expect={})
    guard = "  guard: {endpoint: 'http://guard.test/v1', model: g}"
    return rules, _profile(tmp_path, "evaluators:", _JUDGE, guard)


def _meters(monkeypatch: pytest.MonkeyPatch, rules: Path, profile: Path) -> object:
    code, output = _plan(
        monkeypatch, "--rules", str(rules), "--profile", str(profile), "--format", "json"
    )
    assert code == ExitCode.OK, output
    return json.loads(output)["judge_calls"]["meters"]


def test_the_judge_and_the_guard_are_priced_on_the_meters_the_run_uses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules, profile = _judge_and_guard(tmp_path)

    assert _meters(monkeypatch, rules, profile) == [
        {"evaluators": ["llm_judge", "reference_judge"], "max": (4 + 5) * 3},
        {"evaluators": ["guard"], "max": 6},
    ]


def test_judges_on_one_meter_share_it_in_the_plan_whatever_identity_they_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    build = evaluators_module._build_judges

    def drifted(
        cfg: object, judge: object, identity: str
    ) -> tuple[LlmJudgeEvaluator, ReferenceJudgeEvaluator]:
        security, reference = build(cfg, judge, identity)  # type: ignore[arg-type]
        reference.judge_identity = "model=elsewhere; endpoint=000000000000"
        return security, reference

    monkeypatch.setattr(evaluators_module, "_build_judges", drifted)
    rules, profile = _judge_and_guard(tmp_path)

    assert _meters(monkeypatch, rules, profile) == [
        {"evaluators": ["llm_judge", "reference_judge"], "max": (4 + 5) * 3},
        {"evaluators": ["guard"], "max": 6},
    ]


def test_a_judge_over_the_request_budget_does_not_fit_though_the_target_does(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules, profile = _judged_suite(tmp_path)
    args = ("--rules", str(rules), "--profile", str(profile), "--trials", "3")

    code, output = _plan(monkeypatch, *args, "--max-requests", "100", "--format", "json")
    human_code, human = _plan(monkeypatch, *args, "--max-requests", "100")

    assert code == human_code == ExitCode.INVALID_USAGE, output
    document = json.loads(output)
    assert document["requests"]["max"] <= document["budgets"]["max_requests"] == 100
    assert document["fits_budget"] is False
    assert "judge calls: at most 270" in human
    assert "at most 270 call(s) against a budget of 100" in human
    assert "does not fit" in human


def test_a_plan_without_a_judge_says_none_is_called_and_keeps_its_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _rules(tmp_path, cases=3, evaluator="contains", expect={"contains_all": ["42"]})

    code, output = _plan(
        monkeypatch,
        "--rules",
        str(rules),
        "--profile",
        str(_profile(tmp_path)),
        "--max-requests",
        "3",
    )

    assert code == ExitCode.OK, output
    assert "judge calls: none — no selected rule grades with a judge" in output


def test_a_token_ceiling_no_judge_transport_can_enforce_is_refused_as_probe_refuses_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules, profile = _judged_suite(tmp_path)

    code, output = _plan(
        monkeypatch, "--rules", str(rules), "--profile", str(profile), "--max-input-tokens", "10"
    )

    assert code == ExitCode.INVALID_USAGE, output
    assert "evaluators.llm_judge" in output
    assert "could never be enforced" in output


def test_a_token_ceiling_with_a_judge_says_judge_tokens_are_not_predicted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules, profile = _judged_suite(tmp_path)

    code, output = _plan(
        monkeypatch,
        "--rules",
        str(rules),
        "--profile",
        str(profile),
        "--max-input-tokens",
        "10000",
        transport=_ReportsUsageButRefuses,
    )

    assert code == ExitCode.OK, output
    assert "judge tokens are not predicted" in output


def test_the_plan_is_an_upper_bound_on_what_the_probe_asks_the_judge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _rules(tmp_path, cases=5, evaluator="llm_judge", expect={"goal": "g"})
    (rules / "prompts.yaml").write_text(
        json.dumps(
            {
                "id": "acme.prompts",
                "title": "Two prompts",
                "severity": "high",
                "target_kind": "endpoint",
                "taxonomy": ["LLM01:2025"],
                "evaluator": "llm_judge",
                "requires": ["chat"],
                "prompts": ["one?", "two?"],
                "expect": {"goal": "g"},
            }
        ),
        encoding="utf-8",
    )
    profile = _profile(tmp_path, "evaluators:", _JUDGE)
    args = ("--rules", str(rules), "--profile", str(profile), "--trials", "2")

    code, output = _plan(monkeypatch, *args, "--format", "json")
    assert code == ExitCode.OK, output
    planned = json.loads(output)["judge_calls"]["meters"][0]["max"]

    monkeypatch.setattr(endpoint_module, "transport_factory", _CountsJudgeCalls)
    _CountsJudgeCalls.judge_calls = 0
    probe = runner.invoke(app, ["probe", "--url", "http://model.test", "--model", "m", *args])

    assert _CountsJudgeCalls.judge_calls > 0, probe.output
    assert planned == (5 + 2) * 2 * 3
    assert _CountsJudgeCalls.judge_calls <= planned


def test_a_scan_plan_never_prices_a_judge_a_shared_profile_configures(tmp_path: Path) -> None:
    bare = tmp_path / "bare.yaml"
    bare.write_text("budgets:\n  max_requests: 1\n", encoding="utf-8")
    judged = tmp_path / "judged.yaml"
    judged.write_text(
        bare.read_text(encoding="utf-8") + "evaluators:\n" + _JUDGE + "\n", encoding="utf-8"
    )
    scanned = tmp_path / "project"
    scanned.mkdir()
    (scanned / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")

    def plan(profile: Path, *extra: str) -> tuple[int, str]:
        result = runner.invoke(
            app, ["plan", "scan", str(scanned), "--profile", str(profile), *extra]
        )
        return result.exit_code, result.output

    assert plan(judged) == plan(bare)
    code, output = plan(judged, "--format", "json")
    assert code == ExitCode.OK, output
    document = json.loads(output)
    assert document["rules"], "a scan plan with no rule selected would compare nothing"
    assert document["judge_calls"] is None
    assert "judge" not in plan(judged)[1]
