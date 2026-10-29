"""A redacted name is recognised as the name it came from, and as nothing else."""

import pytest
from guardana.core.redaction import (
    EvidenceMode,
    EvidenceRedactor,
    RedactionPolicy,
    is_redaction_of,
)

_REF = "http://10.20.30.40:8080/v1#demo"


def _redacted(text: str, *, hash_identifiers: bool = True) -> str:
    policy = RedactionPolicy(
        mode=EvidenceMode.REDACTED, redact_ip_addresses=True, hash_identifiers=hash_identifiers
    )
    return EvidenceRedactor(policy).redact_spans(text)


def test_a_ref_with_its_address_redacted_is_a_redaction_of_the_ref() -> None:
    shown = _redacted(_REF)

    assert shown != _REF
    assert is_redaction_of(shown, _REF)
    assert is_redaction_of(f"recording:{shown}", f"recording:{_REF}")


def test_a_digest_names_only_the_address_it_was_taken_of() -> None:
    assert not is_redaction_of(_redacted(_REF), "http://10.20.30.41:8080/v1#demo")


def test_without_a_digest_any_address_in_that_place_matches() -> None:
    shown = _redacted(_REF, hash_identifiers=False)

    assert is_redaction_of(shown, "http://192.0.2.7:8080/v1#demo")
    assert not is_redaction_of(shown, "http://192.0.2.7:9090/v1#demo")


@pytest.mark.parametrize(
    ("shown", "original"),
    [
        ("http://[redacted:ip]:8080#demo", "http://:8080#demo"),
        ("[redacted:ip][redacted:ip]", "10.0.0.110.0.0.2"),
        ("http://[redacted:ip]:8080#demo", "https://10.0.0.1:8080#demo"),
        ("a[redacted:ip]b", "ab"),
    ],
)
def test_nothing_is_guessed(shown: str, original: str) -> None:
    assert not is_redaction_of(shown, original)


def test_text_without_a_placeholder_must_be_equal() -> None:
    assert is_redaction_of(_REF, _REF)
    assert not is_redaction_of(_REF, _REF + "x")


def test_text_shaped_like_a_placeholder_the_redactor_never_writes_is_literal() -> None:
    assert not is_redaction_of("http://[redacted:anything]:8080", "http://10.0.0.1:8080")
