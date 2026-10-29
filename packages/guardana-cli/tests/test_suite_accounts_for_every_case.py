"""Every case a suite sets out to send is accounted for in the run it saves.

Driven through `probe` against a scripted endpoint and read back from the saved run
document, because the trial count, the budget, the judge's meter and the summary all
meet there: a case sent and graded is measured, a case sent and not graded stays in
the denominator, and a suite that could not finish never reads as a pass.
"""

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import ChatMessage
from typer.testing import CliRunner

runner = CliRunner()

_SUITE_ID = "acme.quality.answers"
_REPLY = "The answer is 42."
_WRONG = "I do not know."
_JUDGE = "http://judge.test/v1"


class _Scripted:
    """A model that answers each question as scripted, and a judge that passes every reply.

    Subclassed per test by `_endpoint`, so no count leaks from one test to the next.
    """

    empty: frozenset[str] = frozenset()
    wrong: frozenset[str] = frozenset()
    asked: list[str]
    judged: int

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        """Record the question and answer it: blank, wrong or right, as scripted."""
        cls = type(self)
        if "judge" in base_url:
            cls.judged += 1
            return "PASS: agrees"
        question = str(messages[-1].content)
        cls.asked.append(question)
        if question in cls.empty:
            return ""
        return _WRONG if question in cls.wrong else _REPLY


def _endpoint(*, empty: int = 0, wrong: int = 0) -> type[_Scripted]:
    """A fresh endpoint: `empty` questions answered blank, then `wrong` answered wrong."""

    class Endpoint(_Scripted):
        pass

    Endpoint.empty = frozenset(_question(n) for n in range(empty))
    Endpoint.wrong = frozenset(_question(n) for n in range(empty, empty + wrong))
    Endpoint.asked = []
    Endpoint.judged = 0
    return Endpoint


def _question(n: int) -> str:
    return f"Q{n}?"


def _suite(  # noqa: PLR0913 — one keyword per knob of the declaration under test
    tmp_path: Path,
    *,
    cases: int,
    evaluator: str = "contains",
    expect: dict[str, object] | None = None,
    min_sample: int = 30,
    sample: dict[str, int] | None = None,
) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    header = {"guardana_dataset": 1, "name": "answers", "version": "1"}
    lines = [json.dumps(header)] + [json.dumps({"input": _question(n)}) for n in range(cases)]
    (rules / "answers.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule: dict[str, object] = {
        "id": _SUITE_ID,
        "title": "The assistant still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": evaluator,
        "requires": ["chat"],
        "dataset": "./answers.jsonl",
        "expect": expect if expect is not None else {"contains_all": ["42"]},
        "gate": {"min_pass_rate": 0.9, "min_sample": min_sample},
    }
    if sample is not None:
        rule["sample"] = sample
    (rules / "answers.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _profile(tmp_path: Path, *, judge_samples: int | None = None) -> Path:
    lines = ["rules:", "  include: ['acme.*']"]
    if judge_samples is not None:
        lines += [
            "evaluators:",
            f"  llm_judge: {{endpoint: '{_JUDGE}', model: j, min_agreement: {judge_samples}}}",
        ]
    path = tmp_path / "guardana.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _probe(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: type[_Scripted],
    rules: Path,
    profile: Path,
    *extra: str,
) -> tuple[int, str]:
    monkeypatch.setattr(endpoint_module, "transport_factory", endpoint)
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://model.test",
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(profile),
            *extra,
        ],
    )
    return result.exit_code, result.output


def _saved(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: type[_Scripted],
    rules: Path,
    profile: Path,
    out: Path,
    *extra: str,
) -> tuple[int, dict[str, Any]]:
    """Probe, write the run as JSON to `out`, and read the document back from disk."""
    code, output = _probe(
        monkeypatch, endpoint, rules, profile, "--format", "json", "--output", str(out), *extra
    )
    assert out.exists(), output
    document: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return code, document


def _suite_record(document: dict[str, Any]) -> dict[str, Any] | None:
    return next((r for r in document["run"]["rules"] if r["id"] == _SUITE_ID), None)


def _summary(document: dict[str, Any]) -> dict[str, Any]:
    record = _suite_record(document)
    assert record is not None, "the suite left no record in the run"
    summary: dict[str, Any] = record["suite"]
    return summary


def _assessments(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [a for a in document["assessments"] if a["rule_id"] == _SUITE_ID]


def _trials_by_case(assessments: list[dict[str, Any]]) -> dict[str, list[int]]:
    by_case: dict[str, list[int]] = {}
    for assessment in assessments:
        by_case.setdefault(assessment["case_id"], []).append(assessment["trial"])
    return {case: sorted(trials) for case, trials in by_case.items()}


def _inspect(path: Path) -> list[str]:
    result = runner.invoke(app, ["run", "inspect", str(path)])
    assert result.exit_code == 0, result.output
    return result.output.splitlines()


# A deterministic suite that passes


def test_a_passing_suite_saves_one_graded_assessment_per_request_it_sent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Thirty-two cases at K = 3: ninety-six requests, ninety-six grades, no judge."""
    endpoint = _endpoint()
    out = tmp_path / "run.json"

    code, document = _saved(
        monkeypatch,
        endpoint,
        _suite(tmp_path, cases=32),
        _profile(tmp_path),
        out,
        "--trials",
        "3",
    )

    assert code == ExitCode.OK
    summary = _summary(document)
    assert (summary["outcome"], summary["reason"]) == ("pass", None)
    assert summary["cases"] == summary["measured"] == 32
    assert summary["ungraded"] == 0
    assessments = _assessments(document)
    assert len(assessments) == 32 * 3
    assert all(a["status"] == "measured" and a["passed"] is True for a in assessments)
    assert set(map(tuple, _trials_by_case(assessments).values())) == {(1, 2, 3)}
    assert len(_trials_by_case(assessments)) == 32
    usage = document["run"]["usage"]
    assert usage["requests"] == len(endpoint.asked) == 32 * 3
    assert usage["judge"] is None
    assert endpoint.judged == 0
    lines = _inspect(out)
    assert "  trials:    3 per case asked; 0 rule(s) and 1 suite(s) repeated" in lines
    assert "  judge:     not counted" in lines


# A budget that stops the suite part way


_STOPPED = "the budget ran out before every case was measured: 13 of 32 cases measured"


def _stopped_suite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *extra: str
) -> tuple[type[_Scripted], int, str]:
    """Probe thirty-two cases at K = 3 under a ceiling of forty requests."""
    endpoint = _endpoint()
    code, output = _probe(
        monkeypatch,
        endpoint,
        _suite(tmp_path, cases=32, min_sample=10),
        _profile(tmp_path),
        "--trials",
        "3",
        "--max-requests",
        "40",
        *extra,
    )
    return endpoint, code, output


def test_a_suite_stopped_by_the_budget_is_saved_declined_with_every_case_counted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Forty requests of ninety-six: thirteen cases whole, one case once, eighteen never sent.

    The bar is low enough that the thirteen whole cases alone would clear it, so a
    suite that concluded on what it reached would pass.
    """
    out = tmp_path / "run.json"

    endpoint, code, output = _stopped_suite(
        monkeypatch, tmp_path, "--format", "json", "--output", str(out)
    )

    assert code == ExitCode.BUDGET_EXHAUSTED, output
    document: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    result = document["run"]["result_summary"]
    assert result["stopped_by"] == "budget_exhausted"
    assert result["gate"] == "indeterminate"
    assert _SUITE_ID not in result["rules_run"]
    summary = _summary(document)
    assert (summary["outcome"], summary["reason"]) == ("inconclusive", _STOPPED)
    assert (summary["cases"], summary["measured"], summary["ungraded"]) == (32, 13, 19)
    assert summary["trials_per_case"] == 3
    assert document["run"]["evaluators"] == [], "a suite that did not finish claims no coverage"
    assessments = _assessments(document)
    assert len(assessments) == len(endpoint.asked) == document["run"]["usage"]["requests"] == 40
    trials = _trials_by_case(assessments)
    assert len(trials) == len(set(endpoint.asked)) == 14
    assert Counter(map(tuple, trials.values())) == {(1, 2, 3): 13, (1,): 1}
    assert all(a["status"] == "measured" and a["passed"] is True for a in assessments)
    assert "  stopped:   budget_exhausted — coverage is partial" in _inspect(out)


def test_a_suite_stopped_by_the_budget_reads_as_declined_in_the_terminal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, code, output = _stopped_suite(monkeypatch, tmp_path)

    assert code == ExitCode.BUDGET_EXHAUSTED, output
    assert "14/14 case(s) measured" not in output
    assert " 13/32 case(s) measured before the run stopped, 19 ungraded." in output
    measured = output.split("Measured\n", 1)[1].splitlines()[0]
    assert measured.startswith(f"  {_SUITE_ID}  answers@1: 13 of 32 cases measured, 3 trials each")
    assert measured.endswith(f"declined: {_STOPPED}")
    assert "Run stopped early: budget_exhausted." in output


def test_a_suite_stopped_by_the_budget_is_an_error_testcase_in_junit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.xml"

    _, code, output = _stopped_suite(
        monkeypatch, tmp_path, "--format", "junit", "--output", str(out)
    )

    assert code == ExitCode.BUDGET_EXHAUSTED, output
    root = ElementTree.fromstring(out.read_bytes())  # noqa: S314 — our own output
    assert root.get("failures") == "0"
    cases = [c for c in root.iter("testcase") if c.get("name") == _SUITE_ID]
    assert len(cases) == 1
    error = cases[0].find("error")
    assert error is not None
    assert error.get("message") == "suite declined"
    assert error.text == _STOPPED
    assert cases[0].find("skipped") is None
    assert int(root.get("errors") or 0) == len(
        [c for c in root.iter("testcase") if c.find("error") is not None]
    )


# Replies nobody could grade


@dataclass(frozen=True, slots=True)
class _Blank:
    """One row of the gate table: how many cases get a blank or wrong reply, and the answer."""

    empty: int
    wrong: int
    min_sample: int
    exit_code: ExitCode
    outcome: str
    reason: str | None


@pytest.mark.parametrize(
    "row",
    [
        _Blank(
            3,
            0,
            30,
            ExitCode.INDETERMINATE,
            "inconclusive",
            "27 of 30 cases measured; at least 30 needed to conclude",
        ),
        _Blank(
            5,
            0,
            20,
            ExitCode.INDETERMINATE,
            "inconclusive",
            "15 ungraded trial(s) put the pass rate between 83.3% and 100%, across 90%",
        ),
        _Blank(5, 5, 20, ExitCode.POLICY_FAILED, "fail", None),
    ],
    ids=["too-few-measured", "ungraded-straddle-the-bar", "below-the-bar-even-if-graded"],
)
def test_blank_replies_stay_in_the_denominator_and_the_suite_never_passes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, row: _Blank
) -> None:
    empty, wrong = row.empty, row.wrong
    out = tmp_path / "run.json"

    code, document = _saved(
        monkeypatch,
        _endpoint(empty=empty, wrong=wrong),
        _suite(tmp_path, cases=30, min_sample=row.min_sample),
        _profile(tmp_path),
        out,
        "--trials",
        "3",
    )

    assert code == row.exit_code
    summary = _summary(document)
    assert (summary["outcome"], summary["reason"]) == (row.outcome, row.reason)
    assert summary["cases"] == 30
    assert summary["measured"] == 30 - empty
    assert summary["ungraded"] == empty
    assert summary["worst"] == pytest.approx((30 - empty - wrong) / 30)
    assert summary["best"] == pytest.approx((30 - wrong) / 30)
    assessments = _assessments(document)
    assert len(assessments) == 30 * 3
    ungraded = [a for a in assessments if a["status"] != "measured"]
    assert len(ungraded) == empty * 3
    assert all(a["status"] == "inconclusive" and a["passed"] is None for a in ungraded)
    assert len({a["case_id"] for a in ungraded}) == empty
    channel = "findings" if row.outcome == "fail" else "unverified"
    assert [f["rule_id"] for f in document[channel]] == [_SUITE_ID]
    assert document["run"]["result_summary"]["gate"] != "pass"


# A judge-graded suite with no calibration


def test_an_uncalibrated_judged_suite_declines_and_counts_every_judge_call_the_plan_priced(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Thirty cases at K = 2 with three judge samples a verdict: 60 model calls, 180 judge calls."""
    endpoint = _endpoint()
    rules = _suite(
        tmp_path, cases=30, evaluator="reference_judge", expect={"reference": "The answer is 42."}
    )
    profile = _profile(tmp_path, judge_samples=3)
    out = tmp_path / "run.json"

    monkeypatch.setattr(endpoint_module, "transport_factory", endpoint)
    plan = runner.invoke(
        app,
        [
            "plan",
            "probe",
            "--url",
            "http://model.test",
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(profile),
            "--trials",
            "2",
            "--format",
            "json",
        ],
    )
    assert plan.exit_code == ExitCode.OK, plan.output
    assert endpoint.asked == [], "a plan sends nothing"
    assert endpoint.judged == 0, "a plan sends nothing"
    priced = json.loads(plan.output)
    assert priced["requests"]["max"] == 30 * 2
    assert priced["judge_calls"]["complete"] is True
    assert priced["judge_calls"]["max"] == 30 * 2 * 3
    assert priced["judge_calls"]["meters"] == [
        {"evaluators": ["llm_judge", "reference_judge"], "max": 30 * 2 * 3}
    ]

    code, document = _saved(monkeypatch, endpoint, rules, profile, out, "--trials", "2")

    assert code == ExitCode.INDETERMINATE
    summary = _summary(document)
    assert summary["outcome"] == "inconclusive"
    assert str(summary["reason"]).startswith("uncorrected — ")
    assert summary["correction"]["status"] == "uncorrected"
    assert summary["cases"] == summary["measured"] == 30
    assert len(_assessments(document)) == 30 * 2
    usage = document["run"]["usage"]
    assert usage["requests"] == len(endpoint.asked) == 30 * 2
    assert usage["judge"]["llm_judge"]["requests"] == endpoint.judged == 30 * 2 * 3
    assert usage["judge"]["llm_judge"]["budget_exhausted"] is False
    assert usage["judge"]["llm_judge"]["requests"] == priced["judge_calls"]["max"]


# JUnit


def test_junit_writes_a_passing_suite_as_one_clean_testcase(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = _probe(
        monkeypatch,
        _endpoint(),
        _suite(tmp_path, cases=30),
        _profile(tmp_path),
        "--format",
        "junit",
    )

    assert code == ExitCode.OK, output
    root = ElementTree.fromstring(output[output.index("<?xml") :].encode())  # noqa: S314 — our own output
    assert (root.get("failures"), root.get("errors"), root.get("skipped")) == ("0", "0", "0")
    cases = list(root.iter("testcase"))
    assert [c.get("name") for c in cases] == [_SUITE_ID]
    (case,) = cases
    assert [child.tag for child in case] == ["system-out"]
    said = case.findtext("system-out") or ""
    assert "30 of 30 cases measured" in said
    assert said.endswith("at or above the bar")


# A sampled subset


@pytest.mark.parametrize(
    ("size", "chosen", "tagged"),
    [(12, 12, True), (40, 40, False), (41, 40, False)],
    ids=["subset", "size-equals-cases", "size-above-cases"],
)
def test_a_sampled_suite_sends_exactly_its_sample_and_tags_every_grade(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, size: int, chosen: int, tagged: bool
) -> None:
    """Forty cases, a sample of `size` at seed 7, K = 2; a size at or above forty runs them all."""
    rules = _suite(tmp_path, cases=40, min_sample=10, sample={"size": size, "seed": 7})
    endpoint = _endpoint()

    code, document = _saved(
        monkeypatch, endpoint, rules, _profile(tmp_path), tmp_path / "run.json", "--trials", "2"
    )

    assert code == ExitCode.OK
    summary = _summary(document)
    assert (summary["sample_size"], summary["sample_seed"]) == (
        (size, 7) if tagged else (None, None)
    )
    assert summary["cases"] == summary["measured"] == chosen
    assessments = _assessments(document)
    assert len(assessments) == document["run"]["usage"]["requests"] == chosen * 2
    assert len(_trials_by_case(assessments)) == len(set(endpoint.asked)) == chosen
    assert all(("sample:7" in a["tags"]) is tagged for a in assessments)

    again = _endpoint()
    _, repeated = _saved(
        monkeypatch, again, rules, _profile(tmp_path), tmp_path / "again.json", "--trials", "2"
    )
    assert set(again.asked) == set(endpoint.asked), "the same seed chooses the same cases"
    assert _trials_by_case(_assessments(repeated)) == _trials_by_case(assessments)
