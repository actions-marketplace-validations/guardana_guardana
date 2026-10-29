"""The collector's own API key is never stored in evidence, and never kept by the engine."""

import pytest
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.testing import fake_aws_key
from guardana.server.auth import Scope, generate_key
from guardana.server.envelope import EvidenceIn, FindingIn, Submission, SummaryIn
from guardana.server.redaction import redact_submission


def _synthetic_key() -> str:
    issued, _digest = generate_key("synthetic", (Scope.INGEST,))
    return issued.token


def _stored(secret: str) -> str:
    submission = Submission(
        source="ci",
        schema_version=8,
        findings=[
            FindingIn(
                rule_id="acme.leak",
                severity="HIGH",
                title="leak",
                target_ref="app.py",
                evidence=EvidenceIn(summary=f"the reply quoted {secret} verbatim"),
            )
        ],
        unverified=[],
        errors=[],
        summary=SummaryIn(rules_run=1, max_severity="HIGH"),
    )
    return redact_submission(submission).findings[0].evidence.summary


def _kept_by_the_engine(secret: str) -> str:
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.REDACTED))
    return redactor.redact_text(f"the reply quoted {secret} verbatim")


def test_control_a_recognised_key_is_redacted_on_both_sides() -> None:
    key = fake_aws_key()

    assert key not in _stored(key)
    assert key not in _kept_by_the_engine(key)


@pytest.mark.parametrize("side", ["collector", "engine"])
def test_a_collector_key_in_evidence_is_redacted(side: str) -> None:
    key = _synthetic_key()
    kept = _stored(key) if side == "collector" else _kept_by_the_engine(key)

    leaked = key in kept

    assert not leaked, kept.replace(key, "<the key>")
