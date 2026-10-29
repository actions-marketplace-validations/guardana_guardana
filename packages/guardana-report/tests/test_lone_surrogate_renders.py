"""A reply carrying an unpaired surrogate is reported, not a crash in every renderer.

JSON read from a target can hold one (`"\\ud800"`); a string with it cannot be encoded
as UTF-8, so the first encoder in the path raised before this was scrubbed at the
redaction boundary.
"""

import pytest
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.report import get_renderer


def _result() -> ScanResult:
    finding = Finding("r", Severity.HIGH, "title\udc00", (), "ref", Evidence("a\ud800b"))
    return ScanResult((finding,), ("r",), ())


@pytest.mark.parametrize("mode", list(EvidenceMode))
def test_redaction_replaces_an_unpaired_surrogate(mode: EvidenceMode) -> None:
    redacted = EvidenceRedactor(RedactionPolicy(mode=mode)).redact_result(_result())

    for text in (redacted.findings[0].title, redacted.findings[0].evidence.summary):
        text.encode("utf-8")


@pytest.mark.parametrize("name", ["human", "json", "sarif", "junit"])
def test_every_renderer_writes_a_report_over_an_unpaired_surrogate(name: str) -> None:
    rendered = get_renderer(name).render(_result())

    rendered.encode("utf-8")
