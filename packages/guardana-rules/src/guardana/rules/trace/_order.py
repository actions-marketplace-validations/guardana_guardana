"""Placing a record or a step by its clock where the order spans were written cannot.

A trace's order is the producer's (`Trace.after`), and a producer that writes a span when
it ends puts a child before its parent. So write order is evidence only until a clock
contradicts it: a record in a later span can have been given before the step, and one in
the same or an earlier span can have been given after it. Effects and hops carry no time
of their own, so a record inside a step's window may have come before the action or after
it, and is left unplaced, as it is when a clock is missing.
"""

from datetime import datetime
from enum import Enum

from guardana.core.trace import Span


class Placement(Enum):
    """Where a record or a step falls against another step's window."""

    BEFORE = "before"
    AFTER = "after"
    UNKNOWN = "unknown"


def placed(recorded_at: datetime | None, step: Span) -> Placement:
    """Place a record against `step`'s window by the record's own time.

    `BEFORE` when it is no later than the step's start, `AFTER` only when it is later
    than the step's end, and `UNKNOWN` otherwise. Two clocks that cannot be compared —
    one with a zone and one without — place nothing, because guessing the zone would
    decide the verdict.
    """
    if recorded_at is None:
        return Placement.UNKNOWN
    began, ended = step.started_at, step.ended_at
    if began is not None and _comparable(recorded_at, began) and recorded_at <= began:
        return Placement.BEFORE
    if ended is not None and _comparable(recorded_at, ended) and recorded_at > ended:
        return Placement.AFTER
    return Placement.UNKNOWN


def began(step: Span, window: Span) -> Placement:
    """Place `step` against `window` by the time `step` began.

    `AFTER` when it began later than `window` ended, `BEFORE` only when it began strictly
    earlier than `window` started, and `UNKNOWN` otherwise. A shared instant is `UNKNOWN`
    because a record without a time of its own may sit anywhere in `window`.
    """
    start = step.started_at
    if start is None:
        return Placement.UNKNOWN
    opened, closed = window.started_at, window.ended_at
    if closed is not None and _comparable(start, closed) and start > closed:
        return Placement.AFTER
    if opened is not None and _comparable(start, opened) and start < opened:
        return Placement.BEFORE
    return Placement.UNKNOWN


def _comparable(one: datetime, other: datetime) -> bool:
    return (one.tzinfo is None) == (other.tzinfo is None)
