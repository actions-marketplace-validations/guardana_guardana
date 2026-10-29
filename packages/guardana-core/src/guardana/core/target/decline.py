"""A request the application under test declined, as the team declared a decline to look.

A guard in front of a model answers some requests with its own verdict instead of the
model's reply: an HTTP `400` naming a content policy, a `200` carrying `blocked: true`.
Read as a reply, the block text would be graded as if the model had said it; read as a
failure, it would end the run. An adapter file's `declines:` names which replies are
declines and what each one means, and the transport raises `RequestDeclined` for them.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

JsonScalar = str | int | float | bool
"""A value `equals:` may hold, compared with what the reply carries at `path:`."""

_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*")
DECLINED_TAG_PREFIX = "declined:"
"""Opens the tag every assessment graded from a decline carries, `declined:<name>`."""

_SUCCESS = range(200, 300)
_CLIENT_ERROR = range(400, 500)

NEVER_A_DECLINE = frozenset({401, 403, 404, 407, 408, 425, 429})
"""Statuses that name credentials, an address, a timeout or a rate limit, never a guard."""


class DeclineReading(StrEnum):
    """What a declared decline means for the check that sent the request."""

    REFUSAL = "refusal"
    """The application refused on policy; an evaluator that says how reads it."""

    UNGRADED = "ungraded"
    """The request was not answered and says nothing about the policy; never a pass."""


@dataclass(frozen=True, slots=True)
class Decline:
    """A reply the application under test declined to answer, by the entry it matched."""

    name: str
    reading: DeclineReading
    status: int

    @property
    def described(self) -> str:
        """The decline as evidence states it, in place of a reply the application never gave."""
        return f"declined by the application: {self.name} (HTTP {self.status})"

    @property
    def tag(self) -> str:
        """The tag an assessment graded from this decline carries."""
        return f"{DECLINED_TAG_PREFIX}{self.name}"


def is_valid_decline_name(name: object) -> bool:
    """Whether `name` may name a decline: `[a-z0-9][a-z0-9_.-]*`."""
    return isinstance(name, str) and _NAME.fullmatch(name) is not None


class RequestDeclined(Exception):  # noqa: N818 — a decline is an answer, not an error
    """The application declined the request as a `declines:` entry describes.

    Not an `EndpointError`: the target answered, so a run never ends on it, and no reply
    text is invented for it. `meta` holds the metadata read from the declining reply.
    """

    def __init__(self, decline: Decline, meta: Mapping[str, str] | None = None) -> None:
        self.decline = decline
        self.meta: Mapping[str, str] = dict(meta or {})
        super().__init__(decline.described)


@dataclass(frozen=True, slots=True)
class DeclaredDecline:
    """One entry of an adapter's `declines:`: which reply is a decline, and how it reads.

    An entry that cannot be honoured raises `ValueError` at construction, and
    `AdapterConfig` checks each against its retried statuses, so an adapter built in Python
    is held to what an adapter file is held to.
    """

    name: str
    statuses: frozenset[int]
    reading: DeclineReading
    path: str | None = None
    equals: JsonScalar | None = None

    def __post_init__(self) -> None:
        """Refuse an entry that could read a broken request, or a guard's pass, as a decline."""
        if not _NAME.fullmatch(self.name):
            raise ValueError(f"decline name {self.name!r} must match [a-z0-9][a-z0-9_.-]*")
        if not self.statuses:
            raise ValueError(f"decline {self.name}: 'status' names no status")
        for status in sorted(self.statuses):
            if isinstance(status, bool) or (status not in _SUCCESS and status not in _CLIENT_ERROR):
                raise ValueError(
                    f"decline {self.name}: status {status} is outside 200-299 and 400-499"
                )
        if (self.path is None) != (self.equals is None):
            raise ValueError(f"decline {self.name}: 'path' and 'equals' are given together")
        if self.path is not None and not self.path:
            raise ValueError(f"decline {self.name}: 'path' must be a non-empty string")
        if self.equals is not None and not isinstance(self.equals, str | int | float):
            raise ValueError(f"decline {self.name}: 'equals' must be a string, number or boolean")
        if self.path is None and self.reading is DeclineReading.REFUSAL:
            raise ValueError(
                f"decline {self.name}: 'as: refusal' needs 'path' and 'equals'; a status "
                f"alone cannot tell a policy block from a malformed request"
            )
        if self.path is None and any(status in _SUCCESS for status in self.statuses):
            raise ValueError(
                f"decline {self.name}: a 2xx status needs 'path' and 'equals'; a status "
                f"alone would read every answer as a decline"
            )

    def check_against(self, retried: frozenset[int]) -> None:
        """Refuse a status this adapter retries, or one that is never a decline."""
        overlap = sorted(self.statuses & retried)
        if overlap:
            raise ValueError(
                f"decline {self.name}: status {', '.join(map(str, overlap))} is also in "
                f"retry_statuses; a reply is either asked again or a decline"
            )
        refused = sorted(self.statuses & NEVER_A_DECLINE)
        if refused:
            raise ValueError(
                f"decline {self.name}: status {', '.join(map(str, refused))} is never a "
                f"decline; credentials, a wrong address, a timeout and a rate limit are "
                f"failures of the target"
            )

    def matches(self, status: int, payload: object) -> bool:
        """Whether a reply with `status` and parsed `payload` is this decline.

        `payload` is the parsed JSON body, or `NOT_JSON` when the body did not parse.
        """
        if status not in self.statuses:
            return False
        if self.path is None:
            return True
        found = value_at(payload, self.path)
        return found is not _ABSENT and _same_json_value(found, self.equals)


class _Absent:
    """The value at a path that does not resolve."""


_ABSENT: object = _Absent()
NOT_JSON: object = _Absent()
"""Stands for a body that did not parse as JSON; no path resolves in it."""


def value_at(payload: object, path: str) -> object:
    """Return the value at a dotted `path` (list indices allowed), or a marker when absent."""
    if payload is NOT_JSON:
        return _ABSENT
    current = payload
    for key in path.split("."):
        if isinstance(current, Mapping) and key in current:
            current = current[key]
        elif (
            isinstance(current, list)
            and key.lstrip("-").isdigit()
            and -len(current) <= int(key) < len(current)
        ):
            current = current[int(key)]
        else:
            return _ABSENT
    return current


def is_absent(value: object) -> bool:
    """Whether `value_at` found nothing at its path."""
    return value is _ABSENT


def _same_json_value(found: object, expected: object) -> bool:
    """Compare as JSON does: a string, a number and a boolean never equal one another."""
    if isinstance(expected, bool) or isinstance(found, bool):
        return isinstance(expected, bool) and isinstance(found, bool) and found is expected
    if isinstance(expected, str):
        return isinstance(found, str) and found == expected
    if isinstance(expected, int | float):
        return isinstance(found, int | float) and found == expected
    return False


__all__ = [
    "DECLINED_TAG_PREFIX",
    "NEVER_A_DECLINE",
    "NOT_JSON",
    "DeclaredDecline",
    "Decline",
    "DeclineReading",
    "JsonScalar",
    "RequestDeclined",
    "is_absent",
    "is_valid_decline_name",
    "value_at",
]
