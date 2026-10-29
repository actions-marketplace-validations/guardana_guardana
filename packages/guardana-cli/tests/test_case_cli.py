"""`guardana case add|list` — a failure becomes a case only when it is proven on both sides.

Every refusal exits `3` and writes nothing; a pair that does not separate exits `1` or `2`
and writes nothing; a dry run writes nothing; and reply text reaches the output only on a
terminal or with `--show`. The dataset file is read back, byte for byte, where it matters.
"""

import json
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import ClassVar

import pytest
from guardana.cli import case as case_cli
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core import promotion as promotion_module
from guardana.core.dataset import read_dataset, read_dataset_text
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange
from guardana.core.recording import messages_key
from guardana.core.registry import Registry
from guardana.core.regression import prove
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import ChatMessage
from typer.testing import CliRunner, Result

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_QUESTION = "How do I reset my password?"
_GOOD = "Open Settings and request a reset link."
_BAD = "I cannot help with passwords, sorry."
_EXPECT = '{"contains_any": ["reset link"]}'
_EXISTING = '{"input": "Where is my invoice?", "expect": {"contains_any": ["Billing"]}}'


def normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def _key(text: str) -> str:
    return messages_key((ChatMessage(role="user", content=text),))


def _suite(tmp_path: Path, **overrides: object) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    rule: dict[str, object] = {
        "id": "acme.quality.support",
        "title": "The support bot still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "contains",
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 1, "min_sample": 1},
    }
    rule.update(overrides)
    (rules / "support.jsonl").write_text(
        '{"guardana_dataset": 1, "name": "support", "version": "2026.09"}\n' + _EXISTING + "\n",
        encoding="utf-8",
    )
    path = rules / "suite.yaml"
    path.write_text(json.dumps(rule), encoding="utf-8")
    return path


def _line(text: str, reply: str, **extra: object) -> dict[str, object]:
    return {"rule": "acme.quality.support", "input": text, "reply": reply, **extra}


def _recording(tmp_path: Path, *lines: dict[str, object], verbatim: bool = True) -> Path:
    header = {
        "guardana_recording": 2,
        "name": "support-replies",
        "version": "r1",
        "verbatim": verbatim,
        "origin": {"run_id": "run-7", "target": "https://bot.invalid", "trials": {}, "rules": []},
    }
    path = tmp_path / "run.exchanges.jsonl"
    path.write_text(
        "\n".join(json.dumps(record) for record in (header, *lines)) + "\n", encoding="utf-8"
    )
    return path


def _file(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text + "\n", encoding="utf-8")
    return path


def _team(tmp_path: Path, *lines: dict[str, object], **overrides: object) -> tuple[Path, Path]:
    suite = _suite(tmp_path, **overrides)
    recording = _recording(tmp_path, *(lines or (_line(_QUESTION, _BAD, key=_key(_QUESTION)),)))
    _file(tmp_path, "accepted.txt", _GOOD)
    return suite, recording


def _add(suite: Path, recording: Path, *extra: str, line: str | None = "2") -> Result:
    args = [
        "case",
        "add",
        str(suite),
        "--from",
        str(recording),
        "--expect",
        _EXPECT,
        "--accepted-file",
        str(suite.parent.parent / "accepted.txt"),
        "--version",
        "2026.10",
    ]
    if line is not None:
        args += ["--line", line]
    return runner.invoke(app, [*args, *extra])


def _dataset(suite: Path) -> Path:
    return suite.parent / "support.jsonl"


def test_a_dry_run_proves_the_pair_writes_nothing_and_quotes_nothing_off_a_terminal(
    tmp_path: Path,
) -> None:
    suite, recording = _team(tmp_path)
    before = _dataset(suite).read_bytes()

    result = _add(suite, recording)

    assert result.exit_code == ExitCode.OK, result.output
    assert _dataset(suite).read_bytes() == before
    text = normalised(result.output)
    assert "proof: observed graded fail, accepted graded pass" in text
    assert "dry run: nothing was written" in text
    assert f"input: {len(_QUESTION)} characters, sha256:" in text
    for quoted in (_QUESTION, _BAD, _GOOD, "reset link"):
        assert quoted not in result.output


@pytest.mark.parametrize("how", ["--show", "terminal"])
def test_the_case_text_is_printed_on_a_terminal_or_with_show(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    suite, recording = _team(tmp_path)
    if how == "terminal":
        monkeypatch.setattr(case_cli, "_terminal", lambda: True)

    result = _add(suite, recording, *(["--show"] if how == "--show" else []))

    assert result.exit_code == ExitCode.OK, result.output
    assert _BAD in result.output
    assert _GOOD in result.output


def test_write_appends_one_proven_case_under_the_new_version_and_keeps_every_other_line(
    tmp_path: Path,
) -> None:
    suite, recording = _team(tmp_path)
    _dataset(suite).chmod(0o640)

    result = _add(suite, recording, "--write", "--label", "no reset link")

    assert result.exit_code == ExitCode.OK, result.output
    lines = _dataset(suite).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0]) == {
        "guardana_dataset": 2,
        "name": "support",
        "version": "2026.10",
    }
    assert lines[1] == _EXISTING
    assert json.loads(lines[2]) == {
        "input": _QUESTION,
        "expect": {"contains_any": ["reset link"]},
        "tags": ["regression", "label:no reset link", "origin:run-7"],
        "observed": _BAD,
        "accepted": _GOOD,
    }
    assert stat.S_IMODE(_dataset(suite).stat().st_mode) == 0o640
    assert not [p for p in suite.parent.iterdir() if p.name.endswith(".tmp")]
    (rule,) = load_yaml_rules(suite)
    assert isinstance(rule, SuiteRule)
    assert [case.line for case in rule.regression_cases] == [3]
    assert "case on line 3" in normalised(result.output)
    assert not _lock(suite).exists()


def test_a_redacted_reply_needs_a_reviewers_stand_in_and_is_tagged_synthetic(
    tmp_path: Path,
) -> None:
    leak = "Your key is [redacted:api-key]."
    suite, recording = _team(tmp_path, _line(_QUESTION, leak, key=_key(_QUESTION)))

    refused = _add(suite, recording, "--write")
    _file(tmp_path, "observed.txt", "Your key is sk-test-0000.")
    accepted = _add(suite, recording, "--write", "--observed-file", str(tmp_path / "observed.txt"))

    assert refused.exit_code == ExitCode.INVALID_USAGE
    assert "--observed-file" in normalised(refused.output)
    assert accepted.exit_code == ExitCode.OK, accepted.output
    (case,) = [c for c in read_dataset(_dataset(suite)).cases if c.pair is not None]
    assert "observed:synthetic" in case.tags
    assert case.pair is not None
    assert case.pair.observed == "Your key is sk-test-0000."


@pytest.mark.parametrize("flag", ["--input-file", "--observed-file", "--accepted-file"])
def test_a_reviewers_file_holding_a_redaction_placeholder_is_refused(
    tmp_path: Path, flag: str
) -> None:
    suite, recording = _team(tmp_path)
    before = _dataset(suite).read_bytes()
    texts = {
        "--input-file": "Mail [redacted:email] a reset link",
        "--observed-file": "Your key is [redacted:api-key].",
        "--accepted-file": "Mail [redacted:email] and request a reset link.",
    }
    written = _file(tmp_path, "reviewed.txt", texts[flag])

    refused = _add(suite, recording, "--write", flag, str(written))

    assert refused.exit_code == ExitCode.INVALID_USAGE, refused.output
    assert f"{flag} holds a redaction placeholder" in normalised(refused.output)
    assert _dataset(suite).read_bytes() == before


@pytest.mark.parametrize(
    ("line", "verbatim"),
    [
        (_line("Mail [redacted:email] a reset link", _BAD), True),
        (_line(_QUESTION, _BAD, key=_key("a question the rule really sent")), True),
        (_line(_QUESTION, _BAD), False),
    ],
    ids=["placeholder", "key-mismatch", "keyless-not-verbatim"],
)
def test_an_altered_input_is_refused_and_a_rewritten_one_is_tagged(
    tmp_path: Path, line: dict[str, object], verbatim: bool
) -> None:
    suite = _suite(tmp_path)
    recording = _recording(tmp_path, line, verbatim=verbatim)
    _file(tmp_path, "accepted.txt", _GOOD)
    _file(tmp_path, "observed.txt", _BAD)
    _file(tmp_path, "question.txt", _QUESTION)
    stand_in = ("--observed-file", str(tmp_path / "observed.txt"))

    refused = _add(suite, recording, *stand_in)
    rewritten = _add(suite, recording, *stand_in, "--input-file", str(tmp_path / "question.txt"))

    assert refused.exit_code == ExitCode.INVALID_USAGE, refused.output
    assert "another question" in normalised(refused.output)
    assert rewritten.exit_code == ExitCode.OK, rewritten.output
    assert "input:rewritten" in normalised(rewritten.output)


@pytest.mark.parametrize(
    ("selection", "refusal"),
    [
        (["--key", _key(_QUESTION)], "pick one with --line"),
        (["--key", _key("never asked")], "has key"),
        (["--line", "9"], "no kept exchange is on line 9"),
        (["--line", "2", "--key", _key(_QUESTION)], "exactly one of --key and --line"),
        ([], "exactly one of --key and --line"),
    ],
)
def test_an_exchange_that_is_not_named_exactly_once_is_refused(
    tmp_path: Path, selection: list[str], refusal: str
) -> None:
    twice = _line(_QUESTION, _BAD, key=_key(_QUESTION))
    suite, recording = _team(tmp_path, twice, twice)
    before = _dataset(suite).read_bytes()

    result = _add(suite, recording, "--write", *selection, line=None)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert refusal in normalised(result.output)
    assert _dataset(suite).read_bytes() == before


@pytest.mark.parametrize(
    ("extra", "overrides", "refusal"),
    [
        (["--version", "2026.09"], {}, "current version"),
        (["--expect", "[1]"], {}, "JSON object"),
        (["--expect", "{"], {}, "not valid JSON"),
        (["--expect", '{"pattern": "x"}'], {}, "does not use expect field"),
        ([], {"gate": {"min_pass_rate": 0.9, "min_sample": 1}}, "outvote"),
        (["--label", " "], {}, "blank"),
    ],
)
def test_a_refused_flag_rule_or_evaluator_exits_three_and_writes_nothing(
    tmp_path: Path, extra: list[str], overrides: dict[str, object], refusal: str
) -> None:
    suite, recording = _team(tmp_path, **overrides)
    before = _dataset(suite).read_bytes()

    result = _add(suite, recording, "--write", *extra)

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert refusal in normalised(result.output)
    assert _dataset(suite).read_bytes() == before


def test_an_evaluator_that_is_a_judge_is_refused_never_skipped(tmp_path: Path) -> None:
    suite, recording = _team(tmp_path, evaluator="keyword", expect={"goal": "complied"})
    _dataset(suite).write_text(
        '{"guardana_dataset": 1, "name": "support", "version": "2026.09"}\n'
        '{"input": "Where is my invoice?"}\n',
        encoding="utf-8",
    )
    before = _dataset(suite).read_bytes()

    result = _add(suite, recording, "--write", "--expect", "{}")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "does not declare itself deterministic" in normalised(result.output)
    assert _dataset(suite).read_bytes() == before


def test_a_case_already_in_the_dataset_is_refused(tmp_path: Path) -> None:
    suite, recording = _team(tmp_path)
    assert _add(suite, recording, "--write").exit_code == ExitCode.OK

    again = _add(suite, recording, "--write", "--version", "2026.11")

    assert again.exit_code == ExitCode.INVALID_USAGE
    assert "same case" in normalised(again.output)


def test_a_case_over_the_line_limit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite, recording = _team(tmp_path)
    monkeypatch.setattr(promotion_module, "MAX_RECORD_BYTES", 100)

    result = _add(suite, recording, "--write")

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "line limit" in normalised(result.output)


def test_a_rule_that_is_not_a_writable_suite_outside_a_distribution_is_refused(
    tmp_path: Path,
) -> None:
    suite, recording = _team(tmp_path)
    plain = tmp_path / "rules" / "plain.yaml"
    plain.write_text(
        "id: acme.x\ntitle: t\nseverity: low\ntarget_kind: endpoint\ntaxonomy: [LLM01:2025]\n"
        "evaluator: keyword\nrequires: [chat]\nprompts: [hi]\nexpect: {goal: complied}\n",
        encoding="utf-8",
    )
    installed = tmp_path / "site-packages" / "pack" / "suite.yaml"
    installed.parent.mkdir(parents=True)
    installed.write_text(suite.read_text(encoding="utf-8"), encoding="utf-8")

    outcomes = {
        name: _add(path, recording)
        for name, path in {
            "not yaml": tmp_path / "accepted.txt",
            "not a suite": plain,
            "installed": installed,
        }.items()
    }
    _dataset(suite).chmod(0o444)
    read_only = _add(suite, recording)

    for name, result in outcomes.items():
        assert result.exit_code == ExitCode.INVALID_USAGE, name
    assert "installed distribution" in normalised(outcomes["installed"].output)
    assert read_only.exit_code == ExitCode.INVALID_USAGE
    assert "not writable" in normalised(read_only.output)


@pytest.mark.parametrize(
    ("observed", "accepted", "code", "said"),
    [
        (_GOOD, _GOOD, ExitCode.POLICY_FAILED, "observed graded pass, accepted graded pass"),
        (_BAD, _BAD, ExitCode.POLICY_FAILED, "observed graded fail, accepted graded fail"),
    ],
)
def test_a_pair_that_does_not_separate_is_refused_with_the_side_that_failed_it(
    tmp_path: Path, observed: str, accepted: str, code: ExitCode, said: str
) -> None:
    suite, recording = _team(tmp_path, _line(_QUESTION, observed, key=_key(_QUESTION)))
    _file(tmp_path, "accepted.txt", accepted)
    before = _dataset(suite).read_bytes()

    result = _add(suite, recording, "--write")

    assert result.exit_code == code, result.output
    assert said in normalised(result.output)
    assert _dataset(suite).read_bytes() == before


class _Declines(Evaluator):
    id = "contains"
    deterministic: ClassVar[bool] = True
    judge_calls_per_verdict: ClassVar[int] = 0
    expects: ClassVar[Mapping[str, bool]] = {"contains_any": False}

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        if exchange.reply_text == _BAD:
            return Verdict("fail", 1.0, "bad", self.id)
        return Verdict("inconclusive", 0.0, "unsure", self.id)


class _Raises(_Declines):
    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise RuntimeError("the evaluator broke")


@pytest.mark.parametrize(
    ("evaluator", "code", "said"),
    [
        (_Declines(), ExitCode.INDETERMINATE, "accepted graded declined"),
        (_Raises(), ExitCode.INVALID_USAGE, "observed graded raised, accepted graded raised"),
    ],
)
def test_a_side_that_declines_exits_two_and_one_that_raises_exits_three(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    evaluator: Evaluator,
    code: ExitCode,
    said: str,
) -> None:
    registry = Registry()
    registry.register_evaluator(evaluator)
    monkeypatch.setattr(Registry, "discover", classmethod(lambda cls, trust: registry))
    suite, recording = _team(tmp_path)
    before = _dataset(suite).read_bytes()

    result = _add(suite, recording, "--write")

    assert result.exit_code == code, result.output
    assert said in normalised(result.output)
    assert _dataset(suite).read_bytes() == before


def test_a_dataset_changed_during_the_proof_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite, recording = _team(tmp_path)
    proven = prove

    def edited_meanwhile(*args: object, **kwargs: object) -> object:
        with _dataset(suite).open("a", encoding="utf-8") as handle:
            handle.write('{"input": "Another question?"}\n')
        return proven(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(case_cli, "prove", edited_meanwhile)

    result = _add(suite, recording, "--write")

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "changed while the case was being proven" in normalised(result.output)
    assert "Another question?" in _dataset(suite).read_text(encoding="utf-8")
    assert not _lock(suite).exists()


def _lock(suite: Path) -> Path:
    return suite.parent / ".support.jsonl.lock"


def test_a_suite_changed_during_the_proof_leaves_the_dataset_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite, recording = _team(tmp_path)
    before = _dataset(suite).read_bytes()
    proven = prove

    def edited_meanwhile(*args: object, **kwargs: object) -> object:
        rule = json.loads(suite.read_text(encoding="utf-8"))
        suite.write_text(json.dumps({**rule, "title": "Edited"}), encoding="utf-8")
        return proven(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(case_cli, "prove", edited_meanwhile)

    result = _add(suite, recording, "--write")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert f"{suite} changed while the case was being proven" in normalised(result.output)
    assert _dataset(suite).read_bytes() == before
    assert not _lock(suite).exists()


def test_a_second_case_add_while_one_is_writing_is_refused_and_the_first_case_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite, recording = _team(tmp_path)
    reread = read_dataset_text
    concurrent: list[Result] = []

    def while_holding_the_lock(path: Path) -> str:
        if not concurrent:
            concurrent.append(_add(suite, recording, "--write", "--label", "the second"))
        return reread(path)

    monkeypatch.setattr(case_cli, "read_dataset_text", while_holding_the_lock)

    first = _add(suite, recording, "--write", "--label", "the first")

    (second,) = concurrent
    assert second.exit_code == ExitCode.INVALID_USAGE, second.output
    assert "another `guardana case add` is writing" in normalised(second.output)
    assert first.exit_code == ExitCode.OK, first.output
    labels = [t for c in read_dataset(_dataset(suite)).cases for t in c.tags if "label:" in t]
    assert labels == ["label:the first"]
    assert not _lock(suite).exists()


def test_a_lock_left_by_another_writer_refuses_the_write_and_is_not_removed(
    tmp_path: Path,
) -> None:
    suite, recording = _team(tmp_path)
    before = _dataset(suite).read_bytes()
    _lock(suite).write_text("", encoding="utf-8")

    result = _add(suite, recording, "--write")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "if none is running, remove" in normalised(result.output).casefold()
    assert _dataset(suite).read_bytes() == before
    assert _lock(suite).exists()


def test_case_list_names_every_exchange_and_quotes_none_off_a_terminal(tmp_path: Path) -> None:
    recording = _recording(
        tmp_path,
        _line(_QUESTION, _BAD, key=_key(_QUESTION)),
        _line("Where is my invoice?", "Under [redacted:email]."),
    )

    listed = runner.invoke(app, ["case", "list", str(recording)])

    assert listed.exit_code == ExitCode.OK, listed.output
    text = normalised(listed.output)
    assert f"line 2 rule acme.quality.support key {_key(_QUESTION)} reply verbatim" in text
    assert "line 3 rule acme.quality.support key - reply altered" in text
    assert _BAD not in listed.output
    assert _QUESTION not in listed.output


def test_case_list_with_show_shortens_and_escapes_what_it_quotes(tmp_path: Path) -> None:
    reply = "\x1b[31mred\x1b[0m " + "y" * 300
    recording = _recording(tmp_path, _line(_QUESTION, reply))

    listed = runner.invoke(app, ["case", "list", str(recording), "--show"])

    assert listed.exit_code == ExitCode.OK
    assert "\x1b" not in listed.output
    assert "\\x1b[31mred" in listed.output
    assert "y" * 300 not in listed.output
    assert f"input: {_QUESTION}" in listed.output


def test_names_read_from_the_recording_are_escaped_like_its_text(tmp_path: Path) -> None:
    suite = _suite(tmp_path)
    recording = _recording(
        tmp_path, _line(_QUESTION, _BAD, key=_key(_QUESTION), rule="acme\x1b[2J.support")
    )
    header, line = recording.read_text(encoding="utf-8").splitlines()
    renamed = {**json.loads(header), "name": "replies\x1b]0;owned\x07"}
    recording.write_text(f"{json.dumps(renamed)}\n{line}\n", encoding="utf-8")
    _file(tmp_path, "accepted.txt", _GOOD)

    listed = runner.invoke(app, ["case", "list", str(recording)])
    shown = _add(suite, recording)
    refused = _add(suite, recording, line="9")

    assert listed.exit_code == ExitCode.OK, listed.output
    assert shown.exit_code == ExitCode.OK, shown.output
    assert refused.exit_code == ExitCode.INVALID_USAGE, refused.output
    for result in (listed, shown):
        assert "acme\\x1b[2J.support" in result.output
    for result in (listed, shown, refused):
        assert "\x1b" not in result.output
    for result in (shown, refused):
        assert "replies\\x1b]0;owned\\x07" in result.output


def test_case_list_refuses_an_unreadable_recording(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["case", "list", str(tmp_path / "absent.jsonl")])

    assert missing.exit_code == ExitCode.INVALID_USAGE


def _declined_recording(tmp_path: Path) -> Path:
    header = {"guardana_recording": 3, "name": "support-replies", "version": "r1", "verbatim": True}
    declined = {
        "rule": "acme.quality.support",
        "input": _QUESTION,
        "declined": {"name": "content_filter", "reading": "refusal", "status": 400},
        "key": _key(_QUESTION),
    }
    path = tmp_path / "run.exchanges.jsonl"
    path.write_text(
        "\n".join(json.dumps(record) for record in (header, declined)) + "\n", encoding="utf-8"
    )
    return path


@pytest.mark.parametrize("pick", [("--line", "2"), ("--key", _key(_QUESTION))])
def test_a_declined_line_is_refused_as_holding_no_reply_to_pair(
    tmp_path: Path, pick: tuple[str, str]
) -> None:
    suite = _suite(tmp_path)
    _file(tmp_path, "accepted.txt", _GOOD)
    before = _dataset(suite).read_bytes()

    refused = _add(suite, _declined_recording(tmp_path), *pick, "--write", line=None)

    assert refused.exit_code == ExitCode.INVALID_USAGE, refused.output
    text = normalised(refused.output)
    assert "declined by the application: content_filter (HTTP 400)" in text
    assert "no reply to pair" in text
    assert _dataset(suite).read_bytes() == before


def test_case_list_previews_a_declined_line_as_its_decline(tmp_path: Path) -> None:
    listed = runner.invoke(app, ["case", "list", str(_declined_recording(tmp_path)), "--show"])

    assert listed.exit_code == ExitCode.OK, listed.output
    text = normalised(listed.output)
    assert f"line 2 rule acme.quality.support key {_key(_QUESTION)} reply declined" in text
    assert "reply: [declined: content_filter (HTTP 400)]" in text
