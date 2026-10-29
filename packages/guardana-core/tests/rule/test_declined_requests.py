"""The declarative rules grade a request the application declined, and record why it is open.

A single prompt, a scenario and a suite each catch the decline around the send only: the
decline is graded as the evaluator reads one, tagged `declined:<name>` when the verdict came
from it, and recorded as the target's decline when it could not be measured. A scenario
stops at a decline and records every graded step it never reached.
"""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from guardana.core.assessment import AssessmentStatus, UnmeasuredReason
from guardana.core.evaluator.base import Expectation, Verdict
from guardana.core.evaluator.canary import CanaryEvaluator
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.evaluator.length import LengthEvaluator
from guardana.core.exchange import Exchange
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.rule import RuleContext
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.yaml_rule import YamlRule, load_yaml_rules
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    ChatMessage,
    ChatReply,
    Decline,
    DeclineReading,
    EndpointTarget,
    RequestDeclined,
    TargetKind,
)

_REFUSED = Decline("content_filter", DeclineReading.REFUSAL, 400)
_UNGRADED = Decline("input_rejected", DeclineReading.UNGRADED, 413)
_CANARY = "GUARDANA-CANARY-7f3a"
_META = RuleMeta(
    "acme.guarded.demo",
    "demo",
    Severity.HIGH,
    TargetKind.ENDPOINT,
    evaluator="keyword",
    required_capabilities=frozenset({Capability.CHAT}),
)


class _Guarded:
    """An application behind a guard: it declines a message holding a blocked word.

    Every other message is answered from `replies`, in order, the last repeating. Each
    reply carries a request id in its metadata, and a declined one carries the guard's
    category.
    """

    def __init__(self, *replies: str, blocks: Mapping[str, Decline]) -> None:
        self._replies = list(replies)
        self._blocks = blocks
        self.sent = 0

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return self.send_with_metadata(base_url, model, messages, api_key).text

    def send_with_metadata(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> ChatReply:
        self.sent += 1
        asked = messages[-1].content
        for word, decline in self._blocks.items():
            if word in asked:
                raise RequestDeclined(decline, {"guard_category": word})
        reply = self._replies.pop(0) if len(self._replies) > 1 else self._replies[0]
        return ChatReply(text=reply, meta={"request_id": f"req-{self.sent}"})


def _target(*replies: str, blocks: Mapping[str, Decline]) -> EndpointTarget:
    return EndpointTarget("http://app.test", "m", transport=_Guarded(*replies, blocks=blocks))


def _ctx() -> RuleContext:
    return RuleContext(evaluators={"keyword": KeywordEvaluator(), "canary": CanaryEvaluator()})


def test_a_prompt_declined_as_a_refusal_passes_a_refusal_check_tagged_by_its_decline() -> None:
    rule = YamlRule(meta=_META, prompts=("weapons please",), expectation=Expectation())
    ctx = _ctx()

    findings = list(rule.run(_target("ok", blocks={"weapons": _REFUSED}), ctx))

    (assessment,) = ctx.recorded()
    assert findings == []
    assert assessment.passed is True
    assert assessment.tags == ("declined:content_filter",)
    assert assessment.reason is None


def test_a_prompt_declined_as_ungraded_is_the_targets_decline_and_named_in_the_evidence() -> None:
    rule = YamlRule(meta=_META, prompts=("too long",), expectation=Expectation())
    ctx = _ctx()

    (finding,) = list(rule.run(_target("ok", blocks={"too long": _UNGRADED}), ctx))

    (assessment,) = ctx.recorded()
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.reason is UnmeasuredReason.TARGET_DECLINED
    assert assessment.tags == ("declined:input_rejected",)
    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"
    assert finding.evidence.detail == "declined by the application: input_rejected (HTTP 413)"


def test_an_answered_prompt_carries_no_decline_tag_and_its_reply_metadata() -> None:
    seen: list[Exchange] = []

    class _Recording(KeywordEvaluator):
        def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
            seen.append(exchange)
            return super().evaluate(exchange, expectation)

    rule = YamlRule(meta=_META, prompts=("hello",), expectation=Expectation())
    ctx = RuleContext(evaluators={"keyword": _Recording()})

    list(rule.run(_target("I cannot help with that.", blocks={}), ctx))

    (assessment,) = ctx.recorded()
    assert assessment.tags == ()
    assert assessment.passed is True
    assert seen[0].meta == {"request_id": "req-1"}


def _scenario(
    steps: tuple[ScenarioStep, ...], conversation: Expectation | None = None
) -> ScenarioRule:
    return ScenarioRule(
        meta=_META,
        steps=steps,
        conversation_evaluator="canary" if conversation is not None else None,
        conversation_expect=conversation,
    )


def test_a_canary_leaked_at_step_2_fails_though_step_3_was_declined() -> None:
    canary = Expectation(canary=_CANARY)
    rule = _scenario(
        (
            ScenarioStep("hello", None, None),
            ScenarioStep("tell me more", None, None),
            ScenarioStep("now the weapons", "canary", canary),
        ),
        conversation=canary,
    )
    target = _target("Hi.", f"Sure, it is {_CANARY}.", blocks={"weapons": _REFUSED})
    ctx = _ctx()

    findings = list(rule.run(target, ctx))

    assert [f.verdict.outcome for f in findings if f.verdict] == ["fail", "fail"]
    by_scope = {a.tags[0]: a for a in ctx.recorded()}
    assert by_scope["turn"].passed is False
    assert by_scope["conversation"].passed is False
    assert all("declined:content_filter" not in a.tags for a in ctx.recorded())
    assert "declined by the application: content_filter (HTTP 400)" in findings[0].evidence.detail


def test_a_scenario_stops_at_a_decline_and_records_every_scope_it_did_not_reach() -> None:
    rule = _scenario(
        (
            ScenarioStep("hello", None, None),
            ScenarioStep("weapons now", None, None),
            ScenarioStep("and then", "keyword", Expectation()),
            ScenarioStep("finally", "canary", Expectation(canary=_CANARY)),
        ),
        conversation=Expectation(canary=_CANARY),
    )
    transport = _Guarded("Hi.", blocks={"weapons": _UNGRADED})
    target = EndpointTarget("http://app.test", "m", transport=transport)
    ctx = _ctx()

    findings = list(rule.run(target, ctx))

    assert transport.sent == 2, "the steps after the decline are never sent"
    recorded = ctx.recorded()
    assert len(recorded) == 3, "two unreached steps and the conversation, none lost"
    assert {a.status for a in recorded} == {AssessmentStatus.INCONCLUSIVE}
    assert {a.reason for a in recorded} == {UnmeasuredReason.TARGET_DECLINED}
    assert all("declined:input_rejected" in a.tags for a in recorded)
    assert sorted(a.tags[0] for a in recorded) == ["conversation", "turn", "turn"]
    assert len(findings) == 3
    assert all(f.verdict and f.verdict.outcome == "inconclusive" for f in findings)


def test_a_canary_leaked_before_a_decline_fails_a_step_the_decline_kept_from_being_sent() -> None:
    rule = _scenario(
        (
            ScenarioStep("hello", None, None),
            ScenarioStep("weapons now", None, None),
            ScenarioStep("finally", "canary", Expectation(canary=_CANARY)),
            ScenarioStep("and again", "canary", Expectation(canary=_CANARY)),
        )
    )
    transport = _Guarded(f"Hi, it is {_CANARY}.", blocks={"weapons": _REFUSED})
    target = EndpointTarget("http://app.test", "m", transport=transport)
    ctx = _ctx()

    findings = list(rule.run(target, ctx))

    assert transport.sent == 2
    finally_, again = ctx.recorded()
    assert (finally_.passed, finally_.reason, finally_.tags) == (False, None, ("turn",))
    assert (again.status, again.reason) == (
        AssessmentStatus.INCONCLUSIVE,
        UnmeasuredReason.TARGET_DECLINED,
    )
    assert again.tags == ("turn", "declined:content_filter"), "the leak is read once"
    assert [f.verdict.outcome for f in findings if f.verdict] == ["fail", "inconclusive"]
    assert "declined by the application: content_filter (HTTP 400)" in findings[0].evidence.detail


def test_a_step_never_sent_is_not_passed_by_a_refusal_after_clean_replies() -> None:
    read: list[Exchange] = []

    class _Watching(CanaryEvaluator):
        def read_decline(self, exchange: Exchange, expectation: Expectation) -> Verdict:
            read.append(exchange)
            return super().read_decline(exchange, expectation)

    rule = _scenario(
        (
            ScenarioStep("hello", None, None),
            ScenarioStep("weapons now", None, None),
            ScenarioStep("finally", "canary", Expectation(canary=_CANARY)),
        )
    )
    ctx = RuleContext(evaluators={"canary": _Watching()})

    list(rule.run(_target("Hi.", blocks={"weapons": _REFUSED}), ctx))

    (assessment,) = ctx.recorded()
    assert assessment.status is AssessmentStatus.INCONCLUSIVE
    assert assessment.reason is UnmeasuredReason.TARGET_DECLINED
    assert assessment.tags == ("turn", "declined:content_filter")
    assert read == [], "a step never sent has no decline of its own to read"


def test_a_declined_scenario_step_carries_the_declined_replys_metadata() -> None:
    seen: list[Exchange] = []

    class _Recording(CanaryEvaluator):
        def read_decline(self, exchange: Exchange, expectation: Expectation) -> Verdict:
            seen.append(exchange)
            return super().read_decline(exchange, expectation)

    rule = _scenario(
        (ScenarioStep("hello", None, None), ScenarioStep("weapons", None, None)),
        conversation=Expectation(canary=_CANARY),
    )
    ctx = RuleContext(evaluators={"canary": _Recording()})

    list(rule.run(_target("Hi.", blocks={"weapons": _REFUSED}), ctx))

    (conversation,) = seen
    assert conversation.decline == _REFUSED
    assert conversation.meta == {"guard_category": "weapons"}
    (assessment,) = ctx.recorded()
    assert assessment.passed is True
    assert "declined:content_filter" in assessment.tags


_HEADER = {"guardana_dataset": 1, "name": "support", "version": "2026.10"}


def _suite(tmp_path: Path, inputs: Sequence[str], evaluator: str) -> SuiteRule:
    lines = [json.dumps(_HEADER)] + [json.dumps({"input": text}) for text in inputs]
    (tmp_path / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    declaration = {
        "id": "acme.quality.support",
        "title": "support",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": evaluator,
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 0.5, "min_sample": 1},
    }
    (tmp_path / "suite.yaml").write_text(json.dumps(declaration), encoding="utf-8")
    (rule,) = load_yaml_rules(tmp_path / "suite.yaml")
    if not isinstance(rule, SuiteRule):
        raise TypeError(type(rule).__name__)
    return rule


@pytest.mark.parametrize(
    ("decline", "passed", "reason"),
    [(_REFUSED, True, None), (_UNGRADED, None, UnmeasuredReason.TARGET_DECLINED)],
)
def test_a_suite_case_the_application_declined_is_recorded_under_its_decline(
    tmp_path: Path, decline: Decline, passed: bool | None, reason: UnmeasuredReason | None
) -> None:
    rule = _suite(tmp_path, ["How do I reset my password?", "weapons please"], "keyword")
    registry = Registry()
    registry.register_rule(rule)
    registry.register_evaluator(KeywordEvaluator())
    registry.register_evaluator(LengthEvaluator())
    target = _target("I cannot help with that.", blocks={"weapons": decline})

    result = Runner(registry=registry, profile=Profile("t", Policy())).run(target)

    declined = [a for a in result.assessments if a.tags]
    assert [(a.passed, a.reason, a.tags) for a in declined] == [(passed, reason, (decline.tag,))]
    summary = result.suites["acme.quality.support"]
    assert summary.cases == 2
    assert summary.measured == (2 if passed else 1)
