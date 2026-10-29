"""The redactor covers every text a finding, an assessment and an observation carry.

Evidence is not the only place target-shaped text lands: a judge's reply becomes a
verdict's rationale, an imported claim supplies a title and a ref, and a file name
becomes an observation. Each is checked here at the redactor itself; the renderer
seam is pinned in `guardana-report`.
"""

from dataclasses import astuple, replace

import pytest
from guardana.core import redaction
from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.evaluator.base import Verdict
from guardana.core.observation import Observation, ObservationKind
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.testing import fake_aws_key, fake_llm_key

_KEY = fake_llm_key()
_AWS = fake_aws_key()
_REDACTED = RedactionPolicy(mode=EvidenceMode.REDACTED)


def _finding(text: str = "") -> Finding:
    return Finding(
        rule_id="acme.leaky.rule",
        severity=Severity.HIGH,
        title=f"judge quoted {text}" if text else "a clean title",
        taxonomy=(),
        target_ref=f"configs/{text}/settings.py:12" if text else "configs/settings.py:12",
        evidence=Evidence(summary="nothing secret here"),
        verdict=Verdict(
            outcome="inconclusive",
            confidence=0.0,
            rationale=f"the judge replied: {text}" if text else "the judge declined",
            evaluator_id="llm_judge",
        ),
    )


def _result(
    *,
    findings: tuple[Finding, ...] = (),
    unverified: tuple[Finding, ...] = (),
    assessments: tuple[Assessment, ...] = (),
    observations: tuple[Observation, ...] = (),
) -> ScanResult:
    return ScanResult(
        findings=findings,
        rules_run=("acme.leaky.rule",),
        rules_skipped=(),
        unverified=unverified,
        assessments=assessments,
        observations=observations,
    )


def test_a_finding_title_location_and_rationale_lose_the_secret() -> None:
    cleaned = EvidenceRedactor(_REDACTED).redact(_finding(_KEY))

    assert cleaned.verdict is not None
    for text in (cleaned.title, cleaned.target_ref, cleaned.verdict.rationale):
        assert _KEY not in text
        assert "[redacted:openai-key:" in text


def test_a_location_keeps_its_shape_and_loses_only_the_secret() -> None:
    redactor = EvidenceRedactor(_REDACTED)

    cleaned = redactor.redact(_finding(_KEY))
    untouched = redactor.redact(_finding())

    assert cleaned.target_ref.startswith("configs/[redacted:openai-key:")
    assert cleaned.target_ref.endswith("]/settings.py:12")
    assert untouched.target_ref == "configs/settings.py:12"


def test_a_finding_with_nothing_to_redact_is_returned_as_it_was() -> None:
    clean = _finding()

    assert EvidenceRedactor(_REDACTED).redact(clean) is clean


def test_metadata_only_keeps_the_title_and_location_and_withholds_the_rationale() -> None:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    cleaned = redactor.redact(_finding(_KEY))

    assert cleaned.verdict is not None
    assert cleaned.title.startswith("judge quoted [redacted:openai-key:")
    assert cleaned.target_ref.endswith("/settings.py:12")
    assert cleaned.verdict.rationale == "[reason withheld: metadata_only]"


def test_full_mode_still_removes_a_secret_from_the_rationale() -> None:
    cleaned = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.FULL)).redact(_finding(_AWS))

    assert cleaned.verdict is not None
    assert _AWS not in cleaned.verdict.rationale


def test_an_assessment_rationale_loses_the_secret() -> None:
    assessment = Assessment(
        case_id="acme.leaky.rule#0123456789ab",
        assessor="llm_judge",
        subject_ref="http://model.invalid",
        status=AssessmentStatus.MEASURED,
        passed=True,
        rationale=f"passed, though the reply quoted {_KEY}",
    )

    cleaned = EvidenceRedactor(_REDACTED).redact_result(_result(assessments=(assessment,)))

    assert _KEY not in cleaned.assessments[0].rationale
    assert cleaned.assessments[0].case_id == assessment.case_id
    assert cleaned.assessments[0].passed is True


def test_an_observation_name_ref_and_attributes_lose_the_secret() -> None:
    observation = Observation(
        kind=ObservationKind.MODEL,
        name=f"model-{_KEY}",
        ref=f"models/{_KEY}.gguf",
        attributes={"format": "gguf", "source": f"token={_AWS}"},
    )

    cleaned = EvidenceRedactor(_REDACTED).redact_result(_result(observations=(observation,)))

    seen = cleaned.observations[0]
    assert _KEY not in seen.name
    assert _KEY not in seen.ref
    assert seen.ref.startswith("models/[redacted:openai-key:")
    assert seen.ref.endswith("].gguf")
    assert all(_AWS not in value for value in seen.attributes.values())
    assert seen.attributes["format"] == "gguf"
    assert seen.kind is ObservationKind.MODEL


def test_redacting_a_result_twice_changes_nothing_the_first_pass_wrote() -> None:
    redactor = EvidenceRedactor(_REDACTED)
    result = _result(findings=(_finding(_KEY),), unverified=(_finding(_AWS),))

    once = redactor.redact_result(result)

    assert redactor.redact_result(once) == once


@pytest.mark.parametrize("mode", [EvidenceMode.REDACTED, EvidenceMode.FULL])
def test_redaction_claims_each_match_with_a_bounded_number_of_span_checks(
    mode: EvidenceMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Many matches cost a bounded number of span checks each, not one per earlier match.

    Every match is checked against the spans already claimed; scanning all of them made
    a reply full of addresses quadratic in its own length, before the size bound applied.
    """
    checks = 0
    original = redaction._overlaps

    def counting(start: int, end: int, taken_start: int, taken_end: int) -> bool:
        nonlocal checks
        checks += 1
        return original(start, end, taken_start, taken_end)

    monkeypatch.setattr(redaction, "_overlaps", counting)
    redactor = EvidenceRedactor(RedactionPolicy(mode=mode, max_evidence_bytes=64))

    counts = []
    for n in (500, 1000, 2000):
        checks = 0
        # The credential-assignment pattern overlaps every key claimed before it, so
        # each of its matches has to be checked against the claimed spans.
        redactor.redact_text(" ".join(f"u{i}@x.test token={_KEY[:-4]}{i:04d}" for i in range(n)))
        counts.append(checks)

    assert counts[0] > 0
    matches = 2000 * (2 if mode is not EvidenceMode.FULL else 1)
    assert counts[-1] <= 4 * matches
    assert counts[2] <= 2.2 * counts[1]
    assert counts[1] <= 2.2 * counts[0]


def test_a_broad_custom_pattern_leaves_rule_ids_and_framework_references_alone() -> None:
    """A finding keeps the rule and the mapping it belongs to whatever a team redacts."""
    from guardana.core.redaction import (  # noqa: PLC0415
        EvidenceMode,
        EvidenceRedactor,
        RedactionPolicy,
    )
    from guardana.core.report import Evidence, Finding  # noqa: PLC0415
    from guardana.core.severity import Severity  # noqa: PLC0415
    from guardana.core.taxonomy import OWASP_LLM03_2025  # noqa: PLC0415

    policy = RedactionPolicy(
        mode=EvidenceMode.REDACTED, custom_patterns=(r"[A-Z]{3}\d{2}", "supply_chain")
    )
    finding = Finding(
        "guardana.supply_chain.pickle_opcode",
        Severity.HIGH,
        "title",
        (OWASP_LLM03_2025,),
        "model.pkl",
        Evidence(summary="ABC12 in the reply"),
    )

    redacted = EvidenceRedactor(policy).redact(finding)

    assert redacted.rule_id == finding.rule_id
    assert redacted.taxonomy == finding.taxonomy
    assert "ABC12" not in redacted.evidence.summary


_SENT = "gw-live-7Q2mZp9XvR4tL8kN3bW6"
"""A key no built-in pattern recognises, so only its declaration as sent withholds it."""


@pytest.mark.parametrize("mode", list(EvidenceMode))
def test_a_value_the_target_sends_is_withheld_from_every_text_in_every_mode(
    mode: EvidenceMode,
) -> None:
    finding = replace(_finding(_SENT), evidence=Evidence(summary=f"leaked {_SENT}", detail=_SENT))
    redactor = EvidenceRedactor(RedactionPolicy(mode=mode), secrets=(_SENT,))

    cleaned = redactor.redact_result(_result(findings=(finding,)))

    (seen,) = cleaned.findings
    assert seen.verdict is not None
    texts = (seen.title, seen.target_ref, seen.verdict.rationale, *astuple(seen.evidence))
    assert all(_SENT not in text for text in texts)
    assert seen.title == "judge quoted [redacted:credential]"
    assert seen.target_ref == "configs/[redacted:credential]/settings.py:12"
    assert EvidenceRedactor(RedactionPolicy(mode=mode)).redact_result(cleaned) == cleaned


def test_a_sent_value_too_short_to_tell_apart_is_not_withheld() -> None:
    redactor = EvidenceRedactor(_REDACTED, secrets=("abc",))

    assert redactor.redact_spans("abc def") == "abc def"
