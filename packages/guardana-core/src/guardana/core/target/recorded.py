"""Replay a recording through the chat surface, one rule at a time.

A rule talks to a `RecordedTarget` exactly as it talks to a live endpoint, through a view
the runner asks for with `for_rule`. Each view answers only from its own rule's lines, so
two rules asking the same question each read their own replies. A question the recording
cannot answer, or a reply it holds only in altered form, raises `ReplyUnavailable` and is
kept in the target's ledger, so the runner can refuse to read the rule as passed even when
the rule swallowed the exception. A line the application declined raises `RequestDeclined`,
as the live endpoint did, so a regrade reads the decline as the probe read it.
"""

import threading
from collections import deque
from collections.abc import Sequence

from guardana.core.assessment import UnmeasuredReason
from guardana.core.budget import Budgets
from guardana.core.fingerprint import DocumentDigest
from guardana.core.recording import RecordedExchange, Recording, messages_key
from guardana.core.target.base import Capability, Target, TargetKind, WireProtocol
from guardana.core.target.decline import RequestDeclined
from guardana.core.target.endpoint import ChatMessage, ChatReply
from guardana.core.usage import TargetUsage

_PREVIEW = 80
"""How much of the unanswered question a message quotes: enough to find it, never a flood."""

_Signature = tuple[tuple[str, str], ...]


class ReplyUnavailable(Exception):  # noqa: N818 — named for what the rule meets, not as a fault
    """A rule asked a recording for a reply it does not hold, or holds only altered.

    Deliberately not an `EndpointError`: the runner ends a run whose endpoint is gone, and
    one unanswered question says nothing about the next rule's.
    """

    def __init__(self, rule_id: str, reason: UnmeasuredReason, message: str) -> None:
        """Name the rule that asked and why it got no gradable reply."""
        super().__init__(message)
        self.rule_id = rule_id
        self.reason = reason


class RecordedTarget(Target):
    """A chat endpoint whose replies come from a recording; nothing leaves the machine.

    Only `chat` is offered, so a rule needing a planted canary or offered tools is skipped
    for the missing capability as on any endpoint lacking it; an MCP or A2A rule examines
    a protocol a recording does not speak and is skipped as not applicable. The ref
    names the recording, so it never shares a fingerprint or a baseline waiver with a live
    target.
    """

    kind = TargetKind.ENDPOINT

    def __init__(self, recording: Recording) -> None:
        """Index `recording`'s lines by rule and question, every line unread."""
        self._recording = recording
        self._lock = threading.Lock()
        self._keyed: dict[str, dict[str, deque[int]]] = {}
        self._plain: dict[str, dict[_Signature, deque[int]]] = {}
        self._missed: dict[str, list[ReplyUnavailable]] = {}
        for index, exchange in enumerate(recording.exchanges):
            if exchange.key is not None:
                questions = self._keyed.setdefault(exchange.rule, {})
                questions.setdefault(exchange.key, deque()).append(index)
            else:
                plain = self._plain.setdefault(exchange.rule, {})
                plain.setdefault(_signature(exchange.input), deque()).append(index)

    @property
    def recording(self) -> Recording:
        """The recording this target replays."""
        return self._recording

    @property
    def document(self) -> DocumentDigest | None:
        """The recording file's digest, or None for a recording built in memory."""
        return self._recording.digest

    @property
    def ref(self) -> str:
        """`recording:` and the recording's subject, or its `name@version` without one."""
        return f"recording:{self.model}"

    @property
    def model(self) -> str:
        """What answered, as the recording names it."""
        return self._recording.subject or self._recording.identity

    @property
    def recorded_rules(self) -> frozenset[str]:
        """Every rule the recording answers for: named on a line or planned by its origin."""
        return self._recording.rules

    def capabilities(self) -> set[Capability]:
        """Declare `chat` and nothing else."""
        return {Capability.CHAT}

    def speaks(self) -> frozenset[WireProtocol]:
        """Speak chat: a recording replays a chat endpoint's answers."""
        return frozenset({WireProtocol.CHAT})

    def usage(self) -> TargetUsage:
        """Report zero requests and tokens: replaying a recording sends nothing."""
        return TargetUsage(requests=0, input_tokens=0, output_tokens=0)

    def apply_budgets(self, budgets: Budgets) -> None:
        """Accept any ceiling: no request is ever sent through this target."""

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        """Refuse to answer a request no rule is named on; rules ask through `for_rule`."""
        raise TypeError(
            f"{self.ref} answers rules only through for_rule(rule_id); a reply handed out "
            f"without its rule could be graded against another rule's question"
        )

    def for_rule(self, rule_id: str) -> Target:
        """Return a chat view that answers from `rule_id`'s lines only."""
        return _RecordedView(self, rule_id)

    def missed(self, rule_id: str) -> tuple[ReplyUnavailable, ...]:
        """Every request of `rule_id` that got no gradable reply, in the order it was made."""
        with self._lock:
            return tuple(self._missed.get(rule_id, ()))

    def unread(self, rule_id: str) -> tuple[RecordedExchange, ...]:
        """Every line of `rule_id` no request has reached yet, in file order."""
        with self._lock:
            remaining = [
                index
                for queues in (self._keyed.get(rule_id, {}), self._plain.get(rule_id, {}))
                for queue in queues.values()
                for index in queue
            ]
        return tuple(self._recording.exchanges[index] for index in sorted(remaining))

    def answer(self, rule_id: str, messages: Sequence[ChatMessage]) -> str:
        """Hand `rule_id` the text of the next unread reply to `messages`; see `answer_reply`."""
        return self.answer_reply(rule_id, messages).text

    def answer_reply(self, rule_id: str, messages: Sequence[ChatMessage]) -> ChatReply:
        """Hand `rule_id` the next unread reply to `messages` with its metadata.

        A line with a `key` matches the digest of the messages; one without matches the
        messages exactly. Of the two candidates the earlier line wins, so repeated lines
        for one question are trials in file order. A question with no line left raises
        `ReplyUnavailable`; a declined line raises `RequestDeclined`, before any check of
        the reply, since it holds none; an altered reply raises `ReplyUnavailable`.
        """
        key = messages_key(messages)
        signature = _signature(messages)
        with self._lock:
            keyed = self._keyed.get(rule_id, {}).get(key)
            plain = self._plain.get(rule_id, {}).get(signature)
            queue = _earliest(keyed, plain)
            if queue is None:
                missed = ReplyUnavailable(
                    rule_id,
                    UnmeasuredReason.NOT_RECORDED,
                    f"{rule_id}: {self.ref} holds no reply to {_preview(messages)} "
                    f"(or no reply left for one trial more)",
                )
                self._missed.setdefault(rule_id, []).append(missed)
                raise missed
            exchange = self._recording.exchanges[queue.popleft()]
            if exchange.declined is not None:
                raise RequestDeclined(exchange.declined, exchange.meta)
            if exchange.reply is None or self._recording.reply_altered(exchange):
                altered = ReplyUnavailable(
                    rule_id,
                    UnmeasuredReason.REPLY_ALTERED,
                    f"{rule_id}: the reply on line {exchange.line} of {self.ref} was redacted "
                    f"or not kept verbatim, so it is not what the application said",
                )
                self._missed.setdefault(rule_id, []).append(altered)
                raise altered
            return ChatReply(text=exchange.reply, meta=dict(exchange.meta))


class _RecordedView(Target):
    """One rule's view of a `RecordedTarget`: the same endpoint, attributed to that rule."""

    kind = TargetKind.ENDPOINT

    def __init__(self, base: RecordedTarget, rule_id: str) -> None:
        self._base = base
        self._rule_id = rule_id

    @property
    def ref(self) -> str:
        """Return the base target's ref: a view is the same subject."""
        return self._base.ref

    @property
    def model(self) -> str:
        """Return the base target's model."""
        return self._base.model

    def capabilities(self) -> set[Capability]:
        """Return the base target's capabilities."""
        return self._base.capabilities()

    def speaks(self) -> frozenset[WireProtocol]:
        """Return the base target's protocol: chat."""
        return self._base.speaks()

    def usage(self) -> TargetUsage:
        """Return the base target's usage: nothing sent."""
        return self._base.usage()

    def apply_budgets(self, budgets: Budgets) -> None:
        """Accept any ceiling, as the base target does."""
        self._base.apply_budgets(budgets)

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        """Answer from this view's rule's lines, or raise `ReplyUnavailable`."""
        return self._base.answer(self._rule_id, messages)

    def chat_reply(self, messages: Sequence[ChatMessage]) -> ChatReply:
        """Answer as `chat` does, with the metadata the line kept beside the reply."""
        return self._base.answer_reply(self._rule_id, messages)


def _signature(messages: Sequence[ChatMessage]) -> _Signature:
    """Reduce messages to role and content, the exact form an unkeyed line matches on."""
    return tuple((message.role, message.content) for message in messages)


def _earliest(*queues: deque[int] | None) -> deque[int] | None:
    """Pick the non-empty queue whose next line comes first in the file, or None."""
    waiting = [queue for queue in queues if queue]
    return min(waiting, key=lambda queue: queue[0]) if waiting else None


def _preview(messages: Sequence[ChatMessage]) -> str:
    """Quote the start of the last user message, so a missing line can be found."""
    asked = next((m.content for m in reversed(messages) if m.role == "user"), "")
    quoted = asked if len(asked) <= _PREVIEW else f"{asked[:_PREVIEW]}…"
    return repr(quoted)
