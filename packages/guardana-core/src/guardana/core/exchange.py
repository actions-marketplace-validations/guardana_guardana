from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.target import ChatMessage, Decline

if TYPE_CHECKING:  # `trajectory` imports `target`, which `exchange` also imports
    from guardana.core.trajectory.model import Trajectory


class Provenance(StrEnum):
    """How an exchange was produced.

    Only `PROBE` exists today; a future out-of-band tap would reuse `Exchange` with
    its own provenance — designed for, not built.
    """

    PROBE = "probe"


@dataclass(frozen=True, slots=True)
class Exchange:
    """One conversation under evaluation: the messages sent and the replies received.

    Replaces the old single-string observation so a rule can grade a whole
    multi-turn conversation, not just the last reply. A check of the answer reads
    `reply_text`; a check for something that must never be said reads
    `graded_replies`; conversation-aware ones walk `messages`.
    """

    messages: tuple[ChatMessage, ...]
    provenance: Provenance = Provenance.PROBE
    meta: Mapping[str, str] = field(default_factory=dict)
    trajectory: "Trajectory | None" = None
    """The whole agent run, when there was one.

    Hung here rather than replacing `Exchange` so `Evaluator.evaluate` never
    changes shape: every evaluator that reads text keeps working on a run, and an
    evaluator that needs the structure reads this. Finding it None when it needs
    it is `inconclusive` — the structure it grades against is absent, which is not
    evidence of good behaviour.
    """

    graded_from: int = 0
    """Index into `messages` where the turns under grade begin.

    The messages before it are context a grader may read and must not grade: a
    scenario step grades its own reply, and the replies before it were each graded
    by their own step. `0` puts every turn under grade, as a whole conversation and
    an agent run do.
    """

    decline: Decline | None = None
    """How the application declined the last request, when it did.

    A declined exchange ends on the user turn the application declined, so it has no
    `reply_text`; `evaluator.base.grade` reads the decline instead.
    """

    def __post_init__(self) -> None:
        """Refuse a `graded_from` outside the conversation, and a decline after a reply."""
        start = self.graded_from
        if isinstance(start, bool) or not isinstance(start, int):
            raise TypeError(f"graded_from must be an int, got {start!r}")
        if not 0 <= start <= len(self.messages):
            raise ValueError(
                f"graded_from must lie in [0, {len(self.messages)}] for this conversation, "
                f"got {start}"
            )
        if self.decline is not None and (not self.messages or self.messages[-1].role != "user"):
            raise ValueError("a declined exchange ends on the user turn the application declined")

    @property
    def graded_replies(self) -> tuple[str, ...]:
        """Every assistant turn under grade, in order, blank ones included.

        What a check for something that must never be said reads: a forbidden string
        in any of them has been said, whatever the final reply says. Blank turns stay
        in so that turn numbers in a rationale match the conversation.
        """
        return tuple(m.content for m in self.messages[self.graded_from :] if m.role == "assistant")

    @property
    def reply_text(self) -> str | None:
        """The reply to grade — the final assistant turn — or None when none is under grade.

        A conversation left on a user turn (or empty, or with nothing under grade) has
        no reply, so this is None, which an evaluator must read as inconclusive:
        silence is never a pass.

        **A turn whose content is blank is silence too.** The transport already
        refuses `content: null`, because `str(None)` would be graded as the word
        "None"; `content: ""` is the same absence in a shape that types fine — an
        Azure content filter returns it, and so does an assistant turn that carried
        only tool calls. Passed on as a string it reached `canary`, which found no
        marker in it and reported a pass at 0.95 on a reply that carried no evidence
        in either direction. This is the seam where that decision belongs: one
        answer, and every evaluator inherits it.
        """
        if len(self.messages) <= self.graded_from or self.messages[-1].role != "assistant":
            return None
        content = self.messages[-1].content
        return content if content.strip() else None

    @property
    def transcript(self) -> str:
        """The conversation as readable lines — for evidence and judge input.

        A tool-calling turn carries its calls in a field, not in `content`, so a
        transcript built from content alone renders it as an empty `assistant:`
        line and hides the half a reader needs. When the exchange came from an
        agent run, the run itself is rendered. A declined exchange ends with the decline.
        """
        if self.trajectory is not None:
            return self.trajectory.render()
        lines = [_line(m) for m in self.messages]
        if self.decline is not None:
            lines.append(f"[{self.decline.described}]")
        return "\n".join(lines)

    @classmethod
    def single_reply(cls, reply: str) -> "Exchange":
        """Build a minimal exchange carrying just a model reply — the single-turn case."""
        return cls((ChatMessage(role="assistant", content=reply),))

    @classmethod
    def from_trajectory(cls, trajectory: "Trajectory") -> "Exchange":
        """Build an exchange over a whole agent run.

        `messages` keeps the model's prose so a text evaluator has something to
        read; the structured run travels alongside for the evaluators that grade
        tool calls.

        The final step is kept even when it carried no text: dropping it would make
        an earlier prose step the run's reply, and a text evaluator would grade that
        as the model's final answer instead of reading `reply_text` as None.
        """
        last = len(trajectory.steps) - 1
        replies = tuple(
            ChatMessage(role="assistant", content=step.text or "")
            for index, step in enumerate(trajectory.steps)
            if step.text or index == last
        )
        return cls(messages=replies, trajectory=trajectory)


def _line(message: ChatMessage) -> str:
    if message.tool_calls:
        calls = ", ".join(f"{c.name}({c.arguments})" for c in message.tool_calls)
        return f"{message.role}: {message.content}\n{message.role} tool_calls: {calls}"
    return f"{message.role}: {message.content}"
