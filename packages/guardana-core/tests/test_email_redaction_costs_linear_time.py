"""Redacting e-mail addresses costs time linear in the evidence, whatever its shape."""

from _cost import growth
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy

_SMALL, _LARGE = 4000, 16000


def _growth(unit: str) -> float:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))
    return growth(redactor.redact_text, unit * _SMALL, unit * _LARGE)


def test_control_prose_costs_linear_time() -> None:
    assert _growth("word ") < 1.3


def test_dotted_text_without_an_at_sign_costs_linear_time() -> None:
    assert _growth("a.") < 1.3
