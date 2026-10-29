"""Send one chat request for a declarative rule, a declined request included.

A rule catches `RequestDeclined` here, around the send and nowhere else: a judge cannot
decline, so an exception raised while grading is never read as the application's answer.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from guardana.core.assessment import UnmeasuredReason
from guardana.core.exchange import Exchange
from guardana.core.target import ChatMessage, Decline, RequestDeclined
from guardana.core.target.protocols import ChatEndpoint, ChatWithMetadata


@dataclass(frozen=True, slots=True)
class Sent:
    """What one request got: reply text, or the application's decline, and the reply's metadata."""

    text: str | None
    decline: Decline | None = None
    meta: Mapping[str, str] = field(default_factory=dict)

    @property
    def evidence(self) -> str:
        """The reply as a finding quotes it, or the decline in its place."""
        if self.decline is not None:
            return self.decline.described
        return self.text or ""


def send(target: ChatEndpoint, messages: Sequence[ChatMessage]) -> Sent:
    """Send `messages`, through `chat_reply` when the target reports reply metadata."""
    try:
        if isinstance(target, ChatWithMetadata):
            reply = target.chat_reply(messages)
            return Sent(text=reply.text, meta=dict(reply.meta))
        return Sent(text=target.chat(messages))
    except RequestDeclined as declined:
        return Sent(text=None, decline=declined.decline, meta=dict(declined.meta))


def answered(messages: Sequence[ChatMessage], sent: Sent, graded_from: int = 0) -> Exchange:
    """Build the exchange `messages` and what they got make: a reply turn, or the decline."""
    if sent.decline is not None:
        return Exchange(
            tuple(messages), meta=sent.meta, graded_from=graded_from, decline=sent.decline
        )
    reply = ChatMessage(role="assistant", content=sent.text or "")
    return Exchange((*messages, reply), meta=sent.meta, graded_from=graded_from)


def decline_tags(exchange: Exchange, from_decline: bool) -> tuple[str, ...]:
    """Return the tag an assessment graded from a decline carries; none for any other."""
    if from_decline and exchange.decline is not None:
        return (exchange.decline.tag,)
    return ()


def decline_reason(exchange: Exchange) -> UnmeasuredReason | None:
    """Why an inconclusive verdict on `exchange` went unmeasured, when the application declined."""
    return UnmeasuredReason.TARGET_DECLINED if exchange.decline is not None else None
