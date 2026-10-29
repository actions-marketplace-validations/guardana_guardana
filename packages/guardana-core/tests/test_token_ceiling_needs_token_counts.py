"""A token ceiling is enforced only while replies say what they cost.

A transport that *can* report usage is accepted under a token ceiling, but a reply
that carries no counts never advances the sum the ceiling is checked against. A run
against such a provider would send request after request under a ceiling of one
token and pass. The first reply that leaves a bounded count unknown therefore stops
the run as a budget stop: the ceiling can no longer be held.
"""

from collections.abc import Iterable, Sequence

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, StopReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.target.endpoint import ChatMessage, ChatReply, ToolCallReply, ToolSpec
from guardana.core.usage import TokenUsage

_HELLO = [ChatMessage(role="user", content="hello")]


class _Reporting:
    """A usage-reporting transport whose replies carry exactly the counts it is given."""

    def __init__(self, usage: TokenUsage | None) -> None:
        self.sent = 0
        self._usage = usage

    def send(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> str:
        return self.send_reporting_usage(base_url, model, messages, api_key).text

    def send_reporting_usage(
        self, base_url: str, model: str, messages: Sequence[ChatMessage], api_key: str | None
    ) -> ChatReply:
        self.sent += 1
        return ChatReply("ok", self._usage)

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        self.sent += 1
        return ToolCallReply(text="ok", tool_calls=(), usage=self._usage)


def test_a_reply_without_token_counts_under_a_token_ceiling_stops_the_run() -> None:
    transport = _Reporting(None)
    target = EndpointTarget(
        "http://x", "m", transport=transport, budgets=Budgets(max_input_tokens=1)
    )

    with pytest.raises(BudgetExhausted, match="token"):
        target.chat(_HELLO)

    assert transport.sent == 1
    usage = target.usage()
    assert usage.requests == 1
    assert usage.requests_missing_token_counts == 1


def test_a_reply_missing_the_bounded_count_stops_the_run_even_with_the_other_one() -> None:
    target = EndpointTarget(
        "http://x",
        "m",
        transport=_Reporting(TokenUsage(input_tokens=None, output_tokens=3)),
        budgets=Budgets(max_input_tokens=1000),
    )

    with pytest.raises(BudgetExhausted, match="input token"):
        target.chat(_HELLO)


def test_replies_that_report_their_tokens_run_until_the_ceiling() -> None:
    transport = _Reporting(TokenUsage(input_tokens=4, output_tokens=2))
    target = EndpointTarget(
        "http://x", "m", transport=transport, budgets=Budgets(max_input_tokens=10)
    )

    for _ in range(3):
        assert target.chat(_HELLO) == "ok"
    with pytest.raises(BudgetExhausted, match="input tokens is spent"):
        target.chat(_HELLO)

    assert transport.sent == 3


def test_a_reply_without_token_counts_is_fine_when_no_token_ceiling_is_set() -> None:
    target = EndpointTarget(
        "http://x", "m", transport=_Reporting(None), budgets=Budgets(max_requests=5)
    )

    assert target.chat(_HELLO) == "ok"
    assert target.usage().requests_missing_token_counts == 1


def test_a_tool_offer_answered_without_token_counts_stops_a_token_bounded_run() -> None:
    target = EndpointTarget(
        "http://x", "m", transport=_Reporting(None), budgets=Budgets(max_output_tokens=1)
    )

    with pytest.raises(BudgetExhausted, match="output token"):
        target.offer_tools(_HELLO, [ToolSpec("read_file", "Read a file")])


def test_a_tool_offer_that_reports_its_tokens_counts_them() -> None:
    target = EndpointTarget(
        "http://x",
        "m",
        transport=_Reporting(TokenUsage(input_tokens=5, output_tokens=7)),
        budgets=Budgets(max_input_tokens=100, max_output_tokens=100),
    )

    target.offer_tools(_HELLO, [ToolSpec("read_file", "Read a file")])

    usage = target.usage()
    assert (usage.input_tokens, usage.output_tokens) == (5, 7)
    assert usage.requests_missing_token_counts == 0


class _Chatty(Rule):
    """Asks the model far more often than a one-token ceiling could ever allow."""

    meta = RuleMeta(
        "guardana.test.chatty",
        "chatty",
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        if not isinstance(target, EndpointTarget):
            return
        for _ in range(30):
            target.chat(_HELLO)
        yield Finding(self.meta.id, self.meta.severity, "chatty", (), target.ref, Evidence("x"))


def test_a_run_whose_replies_carry_no_token_counts_ends_as_a_budget_stop() -> None:
    transport = _Reporting(None)
    registry = Registry()
    registry.register_rule(_Chatty())
    target = EndpointTarget("http://x", "m", transport=transport)

    result = Runner(
        registry=registry, profile=Profile("t", Policy(), budgets=Budgets(max_input_tokens=1))
    ).run(target)

    assert result.stopped_by is StopReason.BUDGET_EXHAUSTED
    assert transport.sent == 1
