"""A waiver on one finding never carries over to a finding at another location."""

import datetime

import psycopg
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.reporter import HttpReporter
from guardana.core.severity import Severity
from guardana.core.taxonomy import OWASP_LLM03_2025
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import Submission
from guardana.server.lifecycle import ACCEPTED_RISK, list_tracked, waive
from guardana.server.postgres_store import PostgresStore
from guardana.server.redaction import redact_submission
from guardana.server.tenancy import TenantScope, create_organization, create_project

_ROOT = "/srv/models"


def _envelope(customer: str, *, hashed: bool) -> Submission:
    finding = Finding(
        rule_id="guardana.supply_chain.pickle_opcode",
        severity=Severity.CRITICAL,
        title="Pickle runs code",
        taxonomy=(OWASP_LLM03_2025,),
        target_ref=f"{_ROOT}/{customer}@example.com/model.pkl",
        evidence=Evidence(summary="os.system"),
    )
    sent: list[bytes] = []
    policy = RedactionPolicy(mode=EvidenceMode.REDACTED, hash_identifiers=hashed)
    HttpReporter(
        "https://collector.example.com",
        transport=lambda _url, body: sent.append(body),
        redactor=EvidenceRedactor(policy),
    ).submit(ScanResult((finding,), ("guardana.supply_chain.pickle_opcode",), ()), source=_ROOT)
    return redact_submission(Submission.model_validate_json(sent[0]))


def _status_of_b_after_waiving_a(database_url: str, *, hashed: bool) -> list[str]:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web").id
    store = PostgresStore(database_url)
    scope = TenantScope.for_project(project)
    first = _envelope("customer-a", hashed=hashed)
    store.add(scope, first)
    identity_a = first.findings[0].identity
    if identity_a is None:
        raise RuntimeError("precondition: the reporter should send an identity")
    with psycopg.connect(database_url) as connection:
        waive(
            connection,
            "acme/web",
            identity_a,
            approver="owner",
            reason="customer A's model is quarantined",
            expires=datetime.date(2099, 12, 31),
        )
        connection.commit()
    second = _envelope("customer-b", hashed=hashed)
    store.add(scope, second)
    with psycopg.connect(database_url) as connection:
        tracked = list_tracked(connection, "acme/web")
    return [entry.status for entry in tracked if entry.identity == second.findings[0].identity]


def test_control_with_hashed_placeholders_b_stays_open(database_url: str) -> None:
    assert _status_of_b_after_waiving_a(database_url, hashed=True) == ["open"]


def test_with_bare_placeholders_b_never_inherits_the_waiver_on_a(database_url: str) -> None:
    statuses = _status_of_b_after_waiving_a(database_url, hashed=False)

    assert ACCEPTED_RISK not in statuses, statuses
    assert statuses == ["open"], statuses
