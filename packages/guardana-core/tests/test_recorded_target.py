"""A recording graded through the runner: every reply attributed to its rule, none invented.

Each test builds a recording in code and runs real rules against it through the runner,
reading the result where a pipeline reads it: the assessments, the suite's conclusion,
the errors and the skips. A reply the recording lacks or holds altered must never read as
a pass, whatever the rule asking for it does with the exception.
"""

import json
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.assessment import AssessmentStatus, UnmeasuredReason
from guardana.core.evaluator.base import Evaluator, Expectation
from guardana.core.evaluator.length import LengthEvaluator
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.core.evaluator.reference_judge import ReferenceJudgeEvaluator
from guardana.core.exchange import Exchange
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.manifest.records import CalibrationRecord, CorrectionStatus, SuiteOutcome
from guardana.core.profile import Policy, Profile
from guardana.core.recording import (
    RecordedExchange,
    Recording,
    RecordingOrigin,
    messages_key,
)
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.report.skipped import SkipReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.runner import Runner, select_rules
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    ChatEndpoint,
    ChatMessage,
    RecordedTarget,
    ReplyUnavailable,
    Target,
    TargetKind,
)
from guardana.core.target._scoped import RuleScoped
from guardana.core.usage import TargetUsage

_SUITE = "acme.quality.support"
_SHORT = "Open Settings and follow the reset link."
_LONG = "x" * 5000
_HEADER = {"guardana_dataset": 1, "name": "support", "version": "2026.09"}


def _user(text: str) -> tuple[ChatMessage, ...]:
    return (ChatMessage(role="user", content=text),)


def _line(
    rule: str, prompt: str, reply: str, *, key: str | None = None, altered: bool = False
) -> RecordedExchange:
    return RecordedExchange(rule=rule, input=_user(prompt), reply=reply, key=key, altered=altered)


def _recording(
    *exchanges: RecordedExchange,
    verbatim: bool = True,
    origin: RecordingOrigin | None = None,
) -> Recording:
    """Number the exchanges as a file would, the header on line 1."""
    return Recording(
        name="support-replies",
        version="1",
        verbatim=verbatim,
        subject=None,
        origin=origin,
        exchanges=tuple(replace(exchange, line=n) for n, exchange in enumerate(exchanges, start=2)),
        digest=None,
    )


def _suite(tmp_path: Path, cases: int = 30, **overrides: object) -> SuiteRule:
    lines = [json.dumps(_HEADER)]
    lines += [json.dumps({"input": f"Question {n}?"}) for n in range(cases)]
    (tmp_path / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule: dict[str, object] = {
        "id": _SUITE,
        "title": "The support bot still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": "length",
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 0.9, "min_sample": 30},
    }
    rule.update(overrides)
    (tmp_path / "suite.yaml").write_text(json.dumps(rule), encoding="utf-8")
    loaded = load_yaml_rules(tmp_path / "suite.yaml")[0]
    if not isinstance(loaded, SuiteRule):
        raise TypeError(type(loaded).__name__)
    return loaded


def _suite_lines(rule: SuiteRule, reply: str = _SHORT) -> list[RecordedExchange]:
    return [
        RecordedExchange(rule=rule.meta.id, input=case.messages, reply=reply) for case in rule.cases
    ]


def _single_turn(tmp_path: Path, rule_id: str, *prompts: str) -> Rule:
    path = tmp_path / f"{rule_id}.yaml"
    path.write_text(
        json.dumps(
            {
                "id": rule_id,
                "title": "answers briefly",
                "severity": "high",
                "target_kind": "endpoint",
                "taxonomy": ["LLM01:2025"],
                "evaluator": "length",
                "requires": ["chat"],
                "prompts": list(prompts),
            }
        ),
        encoding="utf-8",
    )
    return load_yaml_rules(path)[0]


class _Asking(Rule):
    """A third-party rule that asks its prompts and yields one finding quoting each reply."""

    def __init__(
        self,
        rule_id: str,
        *prompts: str,
        swallow: bool = False,
        needs: frozenset[Capability] = frozenset({Capability.CHAT}),
    ) -> None:
        self._prompts = prompts
        self._swallow = swallow
        self.meta = RuleMeta(
            id=rule_id,
            title="asks",
            severity=Severity.LOW,
            target_kind=TargetKind.ENDPOINT,
            taxonomy=(),
            required_capabilities=needs,
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Quote every reply as a finding; with `swallow`, ignore an unanswered question."""
        if not isinstance(target, ChatEndpoint):
            return
        for prompt in self._prompts:
            try:
                reply = target.chat(list(_user(prompt)))
            except ReplyUnavailable:
                if self._swallow:
                    continue
                raise
            yield Finding(
                rule_id=self.meta.id,
                severity=Severity.LOW,
                title=self.meta.title,
                taxonomy=(),
                target_ref=target.ref,
                evidence=Evidence(summary=reply),
            )


def _run(
    recording: Recording,
    *rules: Rule,
    policy: Policy | None = None,
    concurrency: int = 1,
    evaluators: Iterable[Evaluator] = (),
    calibrations: dict[str, CalibrationRecord] | None = None,
) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    registry.register_evaluator(LengthEvaluator())
    for evaluator in evaluators:
        registry.register_evaluator(evaluator)
    runner = Runner(
        registry=registry,
        profile=Profile("t", policy or Policy()),
        concurrency=concurrency,
        calibrations=calibrations or {},
    )
    return runner.run(RecordedTarget(recording))


def _errors_from(result: ScanResult, source: str) -> list[str]:
    return [error.reason for error in result.errors if error.source == source]


# The target on its own


def test_a_recorded_target_offers_chat_only_and_names_the_recording() -> None:
    target = RecordedTarget(_recording(_line("a.rule", "hi", "hello")))
    assert target.capabilities() == {Capability.CHAT}
    assert target.kind is TargetKind.ENDPOINT
    assert target.ref == "recording:support-replies@1"
    assert target.usage() == TargetUsage(requests=0, input_tokens=0, output_tokens=0)
    assert target.document is None
    assert isinstance(target, RuleScoped)
    view = target.for_rule("a.rule")
    assert isinstance(view, ChatEndpoint)
    assert (view.ref, view.kind, view.capabilities()) == (
        target.ref,
        target.kind,
        target.capabilities(),
    )


def test_a_recorded_targets_ref_names_its_subject_when_it_has_one() -> None:
    recording = _recording(_line("a.rule", "hi", "hello"))
    named = replace(recording, subject="support-bot@prod")
    assert RecordedTarget(named).ref == "recording:support-bot@prod"


def test_a_recorded_target_never_answers_a_request_no_rule_is_named_on() -> None:
    target = RecordedTarget(_recording(_line("a.rule", "hi", "hello")))
    with pytest.raises(TypeError, match="for_rule"):
        target.chat(list(_user("hi")))
    assert target.unread("a.rule") == target.recording.exchanges


def test_repeated_lines_for_one_question_are_trials_in_file_order() -> None:
    target = RecordedTarget(
        _recording(
            _line("a.rule", "hi", "first"),
            _line("a.rule", "other", "unrelated"),
            _line("a.rule", "hi", "second"),
        )
    )
    view = target.for_rule("a.rule")
    if not isinstance(view, ChatEndpoint):
        raise TypeError(type(view).__name__)
    assert view.chat(list(_user("hi"))) == "first"
    assert view.chat(list(_user("hi"))) == "second"
    with pytest.raises(ReplyUnavailable) as raised:
        view.chat(list(_user("hi")))
    assert raised.value.reason is UnmeasuredReason.NOT_RECORDED
    assert raised.value.rule_id == "a.rule"
    assert "'hi'" in str(raised.value)
    assert target.missed("a.rule") == (raised.value,)
    assert [exchange.reply for exchange in target.unread("a.rule")] == ["unrelated"]


def test_a_keyed_line_matches_the_rules_messages_when_its_stored_input_was_redacted() -> None:
    asked = "my token is ghp_notarealtoken"
    target = RecordedTarget(
        _recording(
            _line("a.rule", "my token is [REDACTED]", "noted", key=messages_key(_user(asked)))
        )
    )
    view = target.for_rule("a.rule")
    if not isinstance(view, ChatEndpoint):
        raise TypeError(type(view).__name__)
    with pytest.raises(ReplyUnavailable):
        view.chat(list(_user("my token is [REDACTED]")))
    assert view.chat(list(_user(asked))) == "noted"


def test_an_unkeyed_line_matches_only_the_exact_messages() -> None:
    target = RecordedTarget(_recording(_line("a.rule", "hi", "hello")))
    view = target.for_rule("a.rule")
    if not isinstance(view, ChatEndpoint):
        raise TypeError(type(view).__name__)
    with pytest.raises(ReplyUnavailable):
        view.chat([ChatMessage(role="system", content="hi")])
    with pytest.raises(ReplyUnavailable):
        view.chat(list(_user("hi ")))
    assert view.chat(list(_user("hi"))) == "hello"


def test_an_altered_reply_is_read_and_refused_never_handed_to_the_rule() -> None:
    target = RecordedTarget(_recording(_line("a.rule", "hi", "hello", altered=True)))
    view = target.for_rule("a.rule")
    if not isinstance(view, ChatEndpoint):
        raise TypeError(type(view).__name__)
    with pytest.raises(ReplyUnavailable) as raised:
        view.chat(list(_user("hi")))
    assert raised.value.reason is UnmeasuredReason.REPLY_ALTERED
    assert target.unread("a.rule") == ()
    assert target.missed("a.rule") == (raised.value,)


# Suites


def test_a_suite_over_a_recording_grades_every_reply_and_sends_nothing(tmp_path: Path) -> None:
    rule = _suite(tmp_path)
    result = _run(_recording(*_suite_lines(rule)), rule)
    summary = result.suites[_SUITE]
    assert summary.outcome is SuiteOutcome.PASS
    assert summary.measured == 30
    assert len(result.assessments) == 30
    assert all(a.passed is True for a in result.assessments)
    assert {a.subject_ref for a in result.assessments} == {"recording:support-replies@1"}
    assert result.errors == ()
    assert result.usage == TargetUsage(requests=0, input_tokens=0, output_tokens=0)
    assert gate_outcome(result, Policy()) is GateOutcome.PASS


def test_a_suite_grades_the_recorded_replies_not_a_stand_in(tmp_path: Path) -> None:
    rule = _suite(tmp_path)
    lines = _suite_lines(rule)
    lines[:10] = [replace(line, reply=_LONG) for line in lines[:10]]
    result = _run(_recording(*lines), rule)
    assert result.suites[_SUITE].outcome is SuiteOutcome.FAIL
    assert sum(1 for a in result.assessments if a.passed is False) == 10


def test_an_unrecorded_trial_is_an_error_never_a_pass_and_keeps_the_suite_from_passing(
    tmp_path: Path,
) -> None:
    rule = _suite(tmp_path)
    lines = _suite_lines(rule)
    missing = rule.cases[7].case_id
    del lines[7]
    result = _run(_recording(*lines), rule)
    (ungraded,) = [a for a in result.assessments if a.case_id == missing]
    assert ungraded.status is AssessmentStatus.ERROR
    assert ungraded.reason is UnmeasuredReason.NOT_RECORDED
    assert ungraded.passed is None
    assert ungraded.trial == 1
    assert ungraded.dataset == "support@2026.09"
    assert ungraded.assessor == "length"
    assert "Question 7?" in ungraded.rationale
    summary = result.suites[_SUITE]
    assert summary.outcome is SuiteOutcome.INCONCLUSIVE
    assert summary.ungraded == 1
    assert _errors_from(result, _SUITE) == []
    assert gate_outcome(result, Policy()) is not GateOutcome.PASS


def test_an_altered_reply_in_a_suite_is_inconclusive_and_never_graded(tmp_path: Path) -> None:
    rule = _suite(tmp_path)
    lines = _suite_lines(rule)
    lines[3] = replace(lines[3], altered=True)
    result = _run(_recording(*lines), rule)
    (altered,) = [a for a in result.assessments if a.case_id == rule.cases[3].case_id]
    assert altered.status is AssessmentStatus.INCONCLUSIVE
    assert altered.reason is UnmeasuredReason.REPLY_ALTERED
    assert altered.passed is None
    assert result.suites[_SUITE].outcome is SuiteOutcome.INCONCLUSIVE
    assert _errors_from(result, _SUITE) == []


def test_a_recording_not_kept_verbatim_grades_nothing(tmp_path: Path) -> None:
    rule = _suite(tmp_path)
    result = _run(_recording(*_suite_lines(rule), verbatim=False), rule)
    assert {a.reason for a in result.assessments} == {UnmeasuredReason.REPLY_ALTERED}
    assert result.suites[_SUITE].measured == 0
    assert gate_outcome(result, Policy()) is not GateOutcome.PASS


def _judge_calibration() -> CalibrationRecord:
    return CalibrationRecord(
        dataset_digest="sha256:" + "ab" * 32,
        assessor="llm_judge@2026.1",
        starter_corpus=False,
        positives=30,
        negatives=30,
        positives_inconclusive=0,
        negatives_inconclusive=0,
        sensitivity=27 / 30,
        specificity=28 / 30,
    )


def test_an_unrecorded_trial_adds_no_second_assessor_to_a_judge_graded_suite(
    tmp_path: Path,
) -> None:
    rule = _suite(
        tmp_path,
        evaluator="llm_judge",
        expect={"goal": "the bot leaks another customer's data"},
        gate={"min_pass_rate": 0.5, "min_sample": 20},
    )
    lines = _suite_lines(rule)
    calibrations = {"llm_judge": _judge_calibration()}

    def judged(recording: Recording) -> ScanResult:
        judge = LlmJudgeEvaluator(lambda _prompt: "PASS: resisted")
        return _run(recording, rule, evaluators=(judge,), calibrations=calibrations)

    whole = judged(_recording(*lines))
    holed = judged(_recording(*lines[:5], *lines[6:]))
    assert {a.assessor for a in holed.assessments} == {"llm_judge@2026.1"}
    assert [a.reason for a in holed.assessments].count(UnmeasuredReason.NOT_RECORDED) == 1
    assert whole.suites[_SUITE].correction.status is CorrectionStatus.CORRECTED
    assert holed.suites[_SUITE].correction.status is CorrectionStatus.CORRECTED
    assert holed.suites[_SUITE].correction.assessor == whole.suites[_SUITE].correction.assessor


def test_every_judges_assessor_id_is_the_id_its_verdicts_carry() -> None:
    exchange = Exchange((*_user("hi"), ChatMessage(role="assistant", content="hello")))
    llm = LlmJudgeEvaluator(lambda _prompt: "PASS: fine")
    reference = ReferenceJudgeEvaluator(lambda _prompt: "PASS: fine")
    length = LengthEvaluator()
    assert llm.evaluate(exchange, Expectation(goal="g")).evaluator_id == llm.assessor_id
    assert reference.evaluate(exchange, Expectation()).evaluator_id == reference.assessor_id
    assert length.evaluate(exchange, Expectation()).evaluator_id == length.assessor_id
    assert llm.assessor_id != llm.id


# Single-turn, scenario and third-party rules


def test_a_single_turn_rule_missing_its_second_prompt_is_an_error(tmp_path: Path) -> None:
    rule = _single_turn(tmp_path, "acme.brief", "first?", "second?")
    result = _run(_recording(_line("acme.brief", "first?", "Fine.")), rule)
    (reason,) = _errors_from(result, "acme.brief")
    assert "1 request(s)" in reason
    assert "'second?'" in reason
    assert "acme.brief" not in result.rules_run
    assert [a.passed for a in result.assessments] == [True]
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_a_scenario_reaching_an_unrecorded_turn_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "scenario.yaml"
    path.write_text(
        "id: acme.scenario\n"
        "title: t\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "taxonomy: [LLM01:2025]\n"
        "requires: [chat]\n"
        "steps:\n"
        "  - send: hello\n"
        "    expect: {evaluator: length}\n"
        "  - send: and now?\n"
        "    expect: {evaluator: length}\n",
        encoding="utf-8",
    )
    (rule,) = load_yaml_rules(path)
    result = _run(_recording(_line("acme.scenario", "hello", "Hi.")), rule)
    (reason,) = _errors_from(result, "acme.scenario")
    assert "'and now?'" in reason
    assert "acme.scenario" not in result.rules_run


def test_a_rule_that_swallows_the_missing_reply_is_still_an_error() -> None:
    rule = _Asking("acme.quiet", "first?", "second?", swallow=True)
    result = _run(_recording(_line("acme.quiet", "first?", "one")), rule)
    (reason,) = _errors_from(result, "acme.quiet")
    assert "'second?'" in reason
    assert [f.evidence.summary for f in result.findings] == ["one"]
    assert "acme.quiet" not in result.rules_run
    assert gate_outcome(result, Policy()) is not GateOutcome.PASS


def test_a_rule_that_swallows_every_missing_reply_and_yields_nothing_is_still_an_error() -> None:
    rule = _Asking("acme.quiet", "never recorded?", swallow=True)
    result = _run(_recording(_line("acme.quiet", "recorded?", "one")), rule)
    assert result.findings == ()
    assert sorted(e.stage for e in result.errors if e.source == "acme.quiet") == ["read", "run"]
    assert "acme.quiet" not in result.rules_run
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


class ReplyUnavailableInCacheError(Exception):
    """A rule's own fault whose class name begins like the recording's miss."""


class _StaleReply(ReplyUnavailable):
    """A rule's own subclass of the recording's miss."""


class _AskingThenFailing(_Asking):
    """Asks, swallows what the recording cannot answer, then raises `failure`."""

    def __init__(self, rule_id: str, *prompts: str, failure: Exception) -> None:
        super().__init__(rule_id, *prompts, swallow=True)
        self._failure = failure

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Quote every reply it got, then fail."""
        yield from super().run(target, ctx)
        raise self._failure


@pytest.mark.parametrize(
    ("failure", "named"),
    [
        (ReplyUnavailableInCacheError("cache cold"), True),
        (_StaleReply("acme.quiet", UnmeasuredReason.NOT_RECORDED, "stale"), False),
    ],
)
def test_a_later_fault_is_told_from_the_missing_reply_by_its_type_not_its_name(
    failure: Exception, named: bool
) -> None:
    rule = _AskingThenFailing("acme.quiet", "first?", "second?", failure=failure)
    result = _run(_recording(_line("acme.quiet", "first?", "one")), rule)
    (reason,) = _errors_from(result, "acme.quiet")
    assert "'second?'" in reason
    assert ("; then: " in reason) is named


def test_a_rule_that_reaches_an_altered_reply_is_an_error() -> None:
    rule = _Asking("acme.quiet", "first?", swallow=True)
    result = _run(_recording(_line("acme.quiet", "first?", "one", altered=True)), rule)
    (reason,) = _errors_from(result, "acme.quiet")
    assert "redacted or not kept verbatim" in reason


def test_a_rule_the_origin_planned_and_no_line_answers_runs_and_errors() -> None:
    origin = RecordingOrigin(
        run_id="run-1",
        target="http://model.test",
        started_at=None,
        stopped_by="budget_exhausted",
        gate=None,
        trials={"acme.reached": 1, "acme.unreached": 1},
        rules=("acme.reached", "acme.unreached"),
    )
    reached = _Asking("acme.reached", "hi")
    unreached = _Asking("acme.unreached", "hi")
    result = _run(
        _recording(_line("acme.reached", "hi", "hello"), origin=origin), reached, unreached
    )
    assert result.rules_skipped == ()
    assert result.rules_run == ("acme.reached",)
    assert len(_errors_from(result, "acme.unreached")) == 1


# Selection


def test_a_rule_the_recording_does_not_answer_is_skipped_before_it_runs() -> None:
    answered = _Asking("acme.answered", "hi")
    unanswered = _Asking("acme.unanswered", "hi")
    recording = _recording(_line("acme.answered", "hi", "hello"))
    registry = Registry()
    registry.register_rule(answered)
    registry.register_rule(unanswered)
    target = RecordedTarget(recording)
    selected, skipped = select_rules(registry, Profile("t", Policy()), target)
    assert [rule.meta.id for rule in selected] == ["acme.answered"]
    (skip,) = skipped
    assert (skip.rule_id, skip.reason) == ("acme.unanswered", SkipReason.NOT_RECORDED)
    assert skip.is_coverage_gap
    result = _run(recording, answered, unanswered)
    assert [s.reason for s in result.rules_skipped] == [SkipReason.NOT_RECORDED]
    assert result.errors == ()


@pytest.mark.parametrize(
    "needs", [Capability.PLANT_SYSTEM_PROMPT, Capability.CALL_TOOLS, Capability.LIST_TOOLS]
)
def test_a_rule_needing_more_than_chat_is_skipped_for_the_capability(
    needs: Capability,
) -> None:
    rule = _Asking("acme.wants", "hi", needs=frozenset({Capability.CHAT, needs}))
    result = _run(_recording(_line("acme.other", "hi", "hello")), rule)
    (skip,) = result.rules_skipped
    assert skip.reason is SkipReason.MISSING_CAPABILITY
    assert skip.missing == (str(needs),)


# Lines nobody graded


def test_unread_lines_of_a_rule_that_ran_are_an_error() -> None:
    rule = _Asking("acme.asks", "hi")
    result = _run(
        _recording(
            _line("acme.asks", "hi", "hello"),
            _line("acme.asks", "something else", "a reply nobody graded"),
            _line("acme.asks", "hi", "a second trial nobody ran"),
        ),
        rule,
    )
    (error,) = [e for e in result.errors if e.source == "acme.asks"]
    assert error.stage == "read"
    assert "2 recorded repl(ies)" in error.reason
    assert "line 3, 4" in error.reason
    assert result.rules_run == ("acme.asks",)
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_a_line_naming_a_rule_nobody_loaded_is_an_error() -> None:
    rule = _Asking("acme.asks", "hi")
    result = _run(
        _recording(_line("acme.asks", "hi", "hello"), _line("acme.gone", "hi", "orphan")), rule
    )
    (reason,) = _errors_from(result, "guardana.core.recording")
    assert "acme.gone" in reason
    assert [e.stage for e in result.errors] == ["read"]


def test_lines_of_a_loaded_rule_the_profile_excluded_are_no_error() -> None:
    kept = _Asking("acme.kept", "hi")
    excluded = _Asking("acme.excluded", "hi")
    result = _run(
        _recording(_line("acme.kept", "hi", "hello"), _line("acme.excluded", "hi", "unread")),
        kept,
        excluded,
        policy=Policy(exclude=("acme.excluded",)),
    )
    assert result.errors == ()
    assert result.rules_run == ("acme.kept",)


# Attribution


def test_two_rules_asking_one_question_each_read_their_own_lines() -> None:
    first = _Asking("acme.first", "hi")
    second = _Asking("acme.second", "hi")
    result = _run(
        _recording(
            _line("acme.second", "hi", "for second"), _line("acme.first", "hi", "for first")
        ),
        first,
        second,
    )
    assert {f.rule_id: f.evidence.summary for f in result.findings} == {
        "acme.first": "for first",
        "acme.second": "for second",
    }
    assert result.errors == ()


def test_a_pooled_run_attributes_every_reply_to_its_rule() -> None:
    rules = [_Asking(f"acme.rule{n}", "hi", "again") for n in range(8)]
    lines = [
        _line(rule.meta.id, prompt, f"{rule.meta.id}:{prompt}")
        for rule in rules
        for prompt in ("hi", "again")
    ]
    result = _run(_recording(*lines), *rules, concurrency=4)
    assert result.errors == ()
    assert sorted(result.rules_run) == sorted(rule.meta.id for rule in rules)
    assert all(f.evidence.summary.startswith(f"{f.rule_id}:") for f in result.findings)
    assert len(result.findings) == 16


class _Forgiving:
    """A chat view that answers an unrecorded question with a canned reply instead of raising."""

    def __init__(self, view: Target) -> None:
        self._view = view

    @property
    def ref(self) -> str:
        """The view's reference."""
        return self._view.ref

    @property
    def model(self) -> str:
        """The view's model."""
        return "forgiving"

    def chat(self, messages: list[ChatMessage]) -> str:
        """Answer from the recording, or with a reply that passes when it has none."""
        if not isinstance(self._view, ChatEndpoint):
            raise TypeError(type(self._view).__name__)
        try:
            return self._view.chat(messages)
        except ReplyUnavailable:
            return _SHORT


class _ConcludingSwallower(Rule):
    """A third-party rule that concludes a suite over replies it substituted for missing ones."""

    def __init__(self, suite: SuiteRule) -> None:
        self._suite = suite
        self.meta = suite.meta

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Run the suite against a view that never admits a reply is missing."""
        yield from self._suite.run(_Forgiving(target), ctx)  # type: ignore[arg-type]


def test_a_rule_that_concludes_over_replies_it_never_got_is_an_error(tmp_path: Path) -> None:
    suite = _suite(tmp_path)

    result = _run(_recording(*_suite_lines(suite)[:3]), _ConcludingSwallower(suite))

    assert _errors_from(result, _SUITE), result.errors
    assert gate_outcome(result, Policy()) is not GateOutcome.PASS
