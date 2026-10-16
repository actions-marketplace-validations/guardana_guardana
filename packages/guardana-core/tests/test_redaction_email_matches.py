"""E-mail addresses are found from their `@`, at the same spans a pattern search reports."""

import random
import re
from collections.abc import Iterator

import pytest
from guardana.core import redaction
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy

# The pattern as the redactor searched with it; `_email_matches` must report its spans.
_OLD_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_AT = "@"
_ADDRESS = "someone" + _AT + "example.com"
_TAGGED = "first.last+billing" + _AT + "mail.example-corp.co.uk"
_UPPER = "Ops_Team" + _AT + "EXAMPLE.ORG"

# (text, how many addresses the search reports)
_PROSE = [
    (f"write to {_ADDRESS} for a refund", 1),
    (f"({_ADDRESS})", 1),
    (f"<{_ADDRESS}>, or {_TAGGED}.", 2),
    (f"{_ADDRESS};{_TAGGED};{_UPPER}", 3),
    (f"mailto:{_ADDRESS}?subject=hi", 1),
    (f'"{_UPPER}"', 1),
    (f"[redacted:email]{_ADDRESS}", 1),
    (f"{_ADDRESS}[redacted:ip]", 1),
    (f"[redacted:email:0123456789ab] and {_TAGGED}", 1),
    (f"zażółć {_ADDRESS} gęślą", 1),
    (f"zażółć{_ADDRESS}", 0),
    (f"-.{_ADDRESS}", 1),
    (f"x{_AT}example.com.y{_AT}example.org", 2),
    (f"{_ADDRESS}{_AT}example.org", 1),
    (f"{_AT}{_ADDRESS}", 1),
    ("someone" + _AT + "localhost", 0),
    ("someone" + _AT + "example.c", 0),
    ("someone" + _AT + "example.com1", 0),
    ("someone" + _AT + ".com", 0),
    ("an " + _AT + " sign alone", 0),
    ("version 1.2.3 of a.b.c, no address", 0),
    ("", 0),
]


def _spans(matches: Iterator[re.Match[str]]) -> list[tuple[int, int]]:
    return [match.span() for match in matches]


@pytest.mark.parametrize(("text", "addresses"), _PROSE)
def test_addresses_are_found_at_the_spans_a_search_reports(text: str, addresses: int) -> None:
    found = _spans(redaction._email_matches(text))

    assert found == _spans(_OLD_EMAIL.finditer(text))
    assert len(found) == addresses


@pytest.mark.parametrize(("text", "addresses"), _PROSE)
def test_redacted_text_is_what_the_search_produced(
    text: str, addresses: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))
    redacted = redactor.redact_spans(text)

    monkeypatch.setattr(redaction, "_email_matches", _OLD_EMAIL.finditer)

    assert redacted == redactor.redact_spans(text)
    assert redacted.count("[redacted:email:") == text.count("[redacted:email:") + addresses


def test_addresses_are_found_as_a_search_finds_them_in_generated_text() -> None:
    pieces = ["a", "Z", "1", ".", "-", "_", "%", "+", _AT, _AT, " ", "é", "\n", "com", "x.io", "ß"]
    rng = random.Random(1)  # noqa: S311 — seeded generated text, not a secret
    for _ in range(50_000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 30)))

        assert _spans(redaction._email_matches(text)) == _spans(_OLD_EMAIL.finditer(text)), text


class _CountingPattern:
    """Stands in for the address pattern and counts the starts it is tried from."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self.pattern = pattern
        self.attempts = 0

    def match(self, text: str, pos: int) -> re.Match[str] | None:
        """Match from `pos`, counting the attempt."""
        self.attempts += 1
        return self.pattern.match(text, pos)


_MEBIBYTE = 2**20


@pytest.mark.parametrize(
    "text",
    [
        "a." * (_MEBIBYTE // 2),
        "a." * (_MEBIBYTE // 2) + " " + _AT + "example.com",
        "a." * (_MEBIBYTE // 2) + _AT,
        "a.@" * (_MEBIBYTE // 3),
        _AT + "a." * (_MEBIBYTE // 2),
        "a......" * (_MEBIBYTE // 7),
    ],
    ids=[
        "dotted",
        "dotted-then-detached-at",
        "dotted-then-at",
        "at-per-word",
        "long-domain",
        "sparse",
    ],
)
def test_the_address_pattern_is_tried_at_most_once_per_at_sign(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    counting = _CountingPattern(redaction._EMAIL)
    monkeypatch.setattr(redaction, "_EMAIL", counting)

    assert list(redaction._email_matches(text)) == []
    assert counting.attempts <= text.count(_AT)


def test_a_mebibyte_of_dotted_text_is_redacted() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))
    text = "a." * (_MEBIBYTE // 2) + _ADDRESS

    redacted = redactor.redact_spans(text)

    assert redacted.startswith("[redacted:email:")
    assert _ADDRESS not in redacted
