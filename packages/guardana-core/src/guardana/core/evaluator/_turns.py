"""Find and name the reply a verdict is about, when a conversation holds several."""

from collections.abc import Callable, Sequence


def first_matching(replies: Sequence[str], test: Callable[[str], bool]) -> int | None:
    """Return the 1-based position of the first non-blank reply `test` accepts, or None."""
    return next((n for n, text in enumerate(replies, start=1) if text.strip() and test(text)), None)


def which_turn(position: int, total: int, *, alone: str) -> str:
    """Name a reply in a rationale: `alone` when it is the only one, else its position."""
    return alone if total == 1 else f"assistant turn {position} of {total}"
