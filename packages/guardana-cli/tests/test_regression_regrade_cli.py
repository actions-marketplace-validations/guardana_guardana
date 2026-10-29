"""A regression pair is regraded by `rule test` and before every recipe command, sending nothing.

The pair is broken without moving a byte the lock pins — the evaluator changes under it —
so what refuses is the regrade, not a drift. Requests are counted at a local server.
"""

import json
import re
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from guardana.cli import recipe as recipe_cli
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.evaluator.base import Expectation, Verdict
from guardana.core.evaluator.contains import ContainsEvaluator
from guardana.core.exchange import Exchange
from typer.testing import CliRunner, Result

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_QUESTION = "How do I reset my password?"
_GOOD = "Open Settings and request a reset link."
_BAD = "I cannot help with passwords, sorry."
_LIVE = "Billing has a reset link."
"""What the application answers live: every case of the suite passes on it."""
_CASES = (
    {"input": "Where is my invoice?", "expect": {"contains_any": ["Billing"]}},
    {
        "input": _QUESTION,
        "expect": {"contains_any": ["reset link"]},
        "tags": ["regression"],
        "observed": _BAD,
        "accepted": _GOOD,
    },
)
_FIXTURES = [
    {"name": "answers", "reply": "Billing has a reset link.", "outcome": "clean"},
    {"name": "refuses", "reply": "No.", "outcome": "finding"},
    {"name": "silent", "reply": "", "outcome": "inconclusive"},
]


def normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def _suite(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    rule = {
        "id": "acme.quality.support",
        "title": "The support bot still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "contains",
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 1, "min_sample": 2},
        "fixtures": _FIXTURES,
    }
    header = {"guardana_dataset": 2, "name": "support", "version": "2026.10"}
    lines = [json.dumps(record) for record in (header, *_CASES)]
    (rules / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (rules / "suite.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _evaluating(
    monkeypatch: pytest.MonkeyPatch, grade: Callable[[str | None], Verdict | None]
) -> None:
    """Change what `contains` concludes on some replies, leaving every pinned file as it is."""
    original = ContainsEvaluator.evaluate

    def evaluate(self: ContainsEvaluator, exchange: Exchange, expectation: Expectation) -> Verdict:
        changed = grade(exchange.reply_text)
        return changed if changed is not None else original(self, exchange, expectation)

    monkeypatch.setattr(ContainsEvaluator, "evaluate", evaluate)


def _passes_the_failure(reply: str | None) -> Verdict | None:
    return Verdict("pass", 1.0, "changed", "contains") if reply == _BAD else None


def _rule_test(rules: Path) -> Result:
    return runner.invoke(app, ["rule", "test", "acme.*", "--rules", str(rules)])


def test_rule_test_regrades_every_pair_and_passes_while_they_hold(tmp_path: Path) -> None:
    result = _rule_test(_suite(tmp_path))

    assert result.exit_code == ExitCode.OK, result.output
    assert "1 of 1 regression pair(s) hold" in normalised(result.output)


def test_rule_test_fails_naming_a_case_whose_pair_no_longer_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _suite(tmp_path)
    _evaluating(monkeypatch, _passes_the_failure)

    result = _rule_test(rules)

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    text = normalised(result.output)
    assert "acme.quality.support — regression case at dataset line 3" in text
    assert "observed graded pass, accepted graded pass" in text
    assert "0 of 1 regression pair(s) hold" in text


def test_rule_test_is_indeterminate_over_a_side_that_declines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _suite(tmp_path)
    _evaluating(
        monkeypatch,
        lambda reply: (
            Verdict("inconclusive", 0.0, "unsure", "contains") if reply == _GOOD else None
        ),
    )

    result = _rule_test(rules)

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "accepted graded declined" in normalised(result.output)


def test_rule_test_refuses_a_suite_whose_evaluator_cannot_regrade_without_sending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules = _suite(tmp_path)
    monkeypatch.setattr(ContainsEvaluator, "deterministic", False)

    result = _rule_test(rules)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "cannot be regraded without sending" in normalised(result.output)


@dataclass
class _Wire:
    url: str = ""
    requests: list[str] = field(default_factory=list)


@pytest.fixture
def wire() -> Iterator[_Wire]:
    seen = _Wire()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            seen.requests.append(self.rfile.read(length).decode("utf-8"))
            data = json.dumps({"choices": [{"message": {"content": _LIVE}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    seen.url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield seen
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _pinned_distributions(monkeypatch: pytest.MonkeyPatch) -> None:
    """This checkout installs Guardana itself editable; a user's install is from an index."""
    monkeypatch.setattr(recipe_cli, "moves_under_one_version", lambda _distribution: False)


def _recipe(tmp_path: Path, url: str) -> Path:
    _suite(tmp_path)
    (tmp_path / "guardana.yaml").write_text(
        "rules:\n  paths: [rules]\n  include: ['acme.*']\n", encoding="utf-8"
    )
    recipe = tmp_path / "guardana-recipe.yaml"
    recipe.write_text(
        "schema_version: 1\nname: support-bot\nprofile: guardana.yaml\nsubject:\n"
        f"  kind: application\n  connection:\n    url: {url}\n    model: support-bot\n",
        encoding="utf-8",
    )
    return recipe


def _recipe_command(*args: str) -> Result:
    return runner.invoke(app, ["recipe", *args])


def test_a_recipe_with_holding_pairs_locks_checks_and_sends(tmp_path: Path, wire: _Wire) -> None:
    recipe = _recipe(tmp_path, wire.url)

    locked = _recipe_command("lock", str(recipe))
    checked = _recipe_command("lock", "--check", str(recipe))
    ran = _recipe_command("run", str(recipe))

    assert locked.exit_code == ExitCode.OK, locked.output
    assert checked.exit_code == ExitCode.OK, checked.output
    assert ran.exit_code != ExitCode.INVALID_USAGE, ran.output
    assert wire.requests


def test_a_broken_pair_refuses_lock_check_and_run_as_a_refusal_not_a_drift(
    tmp_path: Path, wire: _Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipe = _recipe(tmp_path, wire.url)
    assert _recipe_command("lock", str(recipe)).exit_code == ExitCode.OK
    lock = tmp_path / "guardana-recipe.lock.yaml"
    pinned = lock.read_bytes()
    _evaluating(monkeypatch, _passes_the_failure)

    relocked = _recipe_command("lock", str(recipe))
    checked = _recipe_command("lock", "--check", str(recipe))
    ran = _recipe_command("run", str(recipe))

    assert relocked.exit_code == ExitCode.POLICY_FAILED, relocked.output
    assert checked.exit_code == ExitCode.POLICY_FAILED, checked.output
    assert ran.exit_code == ExitCode.INVALID_USAGE, ran.output
    for result in (relocked, checked, ran):
        text = normalised(result.output)
        assert "regression case(s) of the selected suites no longer hold" in text
        assert "dataset line 3: observed graded pass, accepted graded pass" in text
        assert "pin(s) moved" not in text
    assert lock.read_bytes() == pinned
    assert wire.requests == []


def test_a_first_lock_over_a_broken_pair_writes_no_lock(
    tmp_path: Path, wire: _Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    recipe = _recipe(tmp_path, wire.url)
    _evaluating(monkeypatch, _passes_the_failure)

    result = _recipe_command("lock", str(recipe))

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert not (tmp_path / "guardana-recipe.lock.yaml").exists()


def _declines_the_correct_reply(reply: str | None) -> Verdict | None:
    return Verdict("inconclusive", 0.0, "unsure", "contains") if reply == _GOOD else None


def _raises_on_the_failure(reply: str | None) -> Verdict | None:
    if reply == _BAD:
        raise RuntimeError("the evaluator broke")
    return None


_Broken = tuple[Callable[[str | None], Verdict | None] | None, bool, str]


@pytest.mark.parametrize(
    "broken",
    [
        (_declines_the_correct_reply, True, "accepted graded declined"),
        (_raises_on_the_failure, True, "observed graded raised"),
        (None, False, "cannot be regraded without sending"),
    ],
    ids=["declined", "raised", "unprovable"],
)
def test_recipe_lock_refuses_every_state_of_a_pair_that_rule_test_tells_apart_with_one(
    tmp_path: Path, wire: _Wire, monkeypatch: pytest.MonkeyPatch, broken: _Broken
) -> None:
    grade, deterministic, says = broken
    recipe = _recipe(tmp_path, wire.url)
    if grade is not None:
        _evaluating(monkeypatch, grade)
    monkeypatch.setattr(ContainsEvaluator, "deterministic", deterministic)

    result = _recipe_command("lock", str(recipe))

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert says in normalised(result.output)
    assert not (tmp_path / "guardana-recipe.lock.yaml").exists()


def _profile(tmp_path: Path) -> Path:
    _suite(tmp_path)
    profile = tmp_path / "guardana.yaml"
    profile.write_text("rules:\n  paths: [rules]\n  include: ['acme.*']\n", encoding="utf-8")
    return profile


def _errors(result: Result) -> list[dict[str, str]]:
    document = json.loads(result.stdout)
    errors: list[dict[str, str]] = document["errors"]
    return errors


def _probe(profile: Path, url: str) -> Result:
    return runner.invoke(
        app, ["probe", "--url", url, "--model", "m", "--profile", str(profile), "--format", "json"]
    )


def test_probe_over_holding_pairs_passes(tmp_path: Path, wire: _Wire) -> None:
    result = _probe(_profile(tmp_path), wire.url)

    assert result.exit_code == ExitCode.OK, result.output
    assert _errors(result) == []


def test_probe_records_a_broken_pair_as_an_error_and_cannot_pass(
    tmp_path: Path, wire: _Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path)
    _evaluating(monkeypatch, _passes_the_failure)

    result = _probe(profile, wire.url)

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    (error,) = [e for e in _errors(result) if e["stage"] == "regression"]
    assert error["source"] == "acme.quality.support"
    assert "observed graded pass, accepted graded pass" in error["reason"]


def _kept(tmp_path: Path, url: str) -> Path:
    """Probe with holding pairs, keeping the exchanges, and return the recording kept."""
    run = tmp_path / "run.json"
    probed = runner.invoke(
        app,
        [
            "probe",
            "--url",
            url,
            "--model",
            "m",
            "--profile",
            str(_profile(tmp_path)),
            "--keep-exchanges",
            "--format",
            "json",
            "--output",
            str(run),
        ],
    )
    assert probed.exit_code == ExitCode.OK, probed.output
    return tmp_path / "run.exchanges.jsonl"


def _grade(recording: Path, profile: Path) -> Result:
    return runner.invoke(
        app, ["grade", str(recording), "--profile", str(profile), "--format", "json"]
    )


def test_grade_over_holding_pairs_passes(tmp_path: Path, wire: _Wire) -> None:
    recording = _kept(tmp_path, wire.url)

    result = _grade(recording, tmp_path / "guardana.yaml")

    assert result.exit_code == ExitCode.OK, result.output
    assert _errors(result) == []


def test_grade_records_a_broken_pair_as_an_error_and_cannot_pass(
    tmp_path: Path, wire: _Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    recording = _kept(tmp_path, wire.url)
    sent = len(wire.requests)
    _evaluating(monkeypatch, _passes_the_failure)

    result = _grade(recording, tmp_path / "guardana.yaml")

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    (error,) = [e for e in _errors(result) if e["stage"] == "regression"]
    assert error["source"] == "acme.quality.support"
    assert len(wire.requests) == sent
