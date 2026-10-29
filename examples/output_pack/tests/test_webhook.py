"""`acme-webhook` refuses what it will not send to, and its body says what the run concluded.

Nothing here reaches a receiver: `prepare` runs with the network refused, and the body
is read as built.
"""

import base64
import dataclasses
import json
import socket
from datetime import UTC, datetime
from typing import Any

import pytest
from acme_outputs import webhook
from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.gate import gate_outcome
from guardana.core.manifest.identity import DeploymentRef
from guardana.core.output import DeliveryStatus, ReporterRequest
from guardana.core.profile import Policy
from guardana.core.report import (
    CheckError,
    CoverageShortfall,
    Evidence,
    Finding,
    ScanResult,
    ShortfallKind,
    SkippedRule,
    SkipReason,
    StopReason,
)
from guardana.core.severity import Severity
from guardana.core.testing import manifest_for
from guardana.core.testing.manifests import suite_summary
from guardana.core.verify import Verification
from standardwebhooks.webhooks import Webhook

_KEY = b"acme webhook unit key"
_SECRET = "whsec_" + base64.b64encode(_KEY).decode("ascii")
_ENV = {webhook.SECRET_VARIABLE: _SECRET}


def _finding(rule_id: str, severity: Severity = Severity.HIGH, title: str = "fired") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        taxonomy=(),
        target_ref="app.py:3",
        evidence=Evidence(summary="the reply quoted the system prompt"),
    )


def _verification(result: ScanResult, **manifest_changes: Any) -> Verification:  # noqa: ANN401 — any manifest field
    gate = gate_outcome(result, Policy())
    manifest = dataclasses.replace(manifest_for(result, gate=gate), **manifest_changes)
    return Verification(result=result, manifest=manifest, gate=gate)


def _body(verification: Verification) -> dict[str, Any]:
    built = webhook.build_body(verification)
    assert isinstance(built, bytes), built
    decoded: dict[str, Any] = json.loads(built)
    return decoded


def _prepare(locator: str, env: dict[str, str] | None = None) -> webhook.Webhook:
    return webhook.prepare(ReporterRequest(locator=locator), environ=_ENV if env is None else env)


@pytest.mark.parametrize(
    ("locator", "env", "reason"),
    [
        ("env:ACME_WEBHOOK_URL", _ENV, "ACME_WEBHOOK_URL is not set"),
        ("", _ENV, "no destination"),
        ("http://hooks.example.com/guardana", _ENV, "plain http is accepted only for localhost"),
        ("ftp://hooks.example.com/guardana", _ENV, "must be an https:// URL"),
        ("https://user:token@hooks.example.com/guardana", _ENV, "must not carry credentials"),
        ("https://hooks.example.com:99999/guardana", _ENV, "is not a URL"),
        ("https://hooks.example.com/guardana", {}, "ACME_WEBHOOK_SECRET is not set"),
        (
            "https://hooks.example.com/guardana",
            {webhook.SECRET_VARIABLE: base64.b64encode(_KEY).decode()},
            "must start with whsec_",
        ),
        (
            "https://hooks.example.com/guardana",
            {webhook.SECRET_VARIABLE: "whsec_not base64!"},
            "whsec_ followed by base64",
        ),
        (
            "https://hooks.example.com/guardana",
            {webhook.SECRET_VARIABLE: "whsec_"},
            "whsec_ followed by base64",
        ),
    ],
)
def test_prepare_refuses_with_a_reason_that_never_repeats_the_url(
    locator: str, env: dict[str, str], reason: str
) -> None:
    with pytest.raises(webhook.WebhookRefusedError, match=reason) as refused:
        _prepare(locator, env)

    assert "token" not in str(refused.value)
    assert "/guardana" not in str(refused.value)


@pytest.mark.parametrize(
    ("url", "destination"),
    [
        ("https://hooks.example.com/guardana?token=abc#frag", "https://hooks.example.com"),
        ("https://Hooks.Example.com:8443/guardana", "https://hooks.example.com:8443"),
        ("http://localhost:8080/hook", "http://localhost:8080"),
        ("http://127.0.0.1/hook", "http://127.0.0.1"),
        ("http://[::1]:9000/hook", "http://[::1]:9000"),
    ],
)
def test_the_destination_shows_scheme_host_and_port_only(url: str, destination: str) -> None:
    assert _prepare(url).destination == destination


def test_a_destination_read_from_the_environment_is_shown_the_same_way() -> None:
    prepared = _prepare(
        "env:ACME_WEBHOOK_URL", {**_ENV, "ACME_WEBHOOK_URL": "https://hooks.example.com/t/abc"}
    )

    assert prepared.destination == "https://hooks.example.com"
    assert prepared.sent_secrets() == (_SECRET, "https://hooks.example.com/t/abc")


def test_a_url_with_nothing_past_its_host_withholds_only_the_secret() -> None:
    """Withholding the URL would also withhold the destination it equals."""
    assert _prepare("https://hooks.example.com").sent_secrets() == (_SECRET,)


def test_prepare_sends_nothing(no_network: list[object]) -> None:
    prepared = _prepare("https://hooks.example.com/guardana")
    prepared.sent_secrets()

    assert no_network == []


def test_the_body_has_the_standard_webhooks_shape_and_every_count_key() -> None:
    result = ScanResult(
        findings=(_finding("acme.high"),),
        rules_run=("acme.high",),
        rules_skipped=(SkippedRule("acme.tools", SkipReason.MISSING_CAPABILITY, ("tools",), ""),),
        unverified=(_finding("acme.unsure"), _finding("acme.unsure2")),
    )
    verification = _verification(
        result, deployment=DeploymentRef(environment="staging", commit_sha="abc123")
    )

    body = _body(verification)

    assert set(body) == {"type", "timestamp", "data"}
    assert body["type"] == "run.completed"
    assert body["timestamp"] == "2026-01-01T00:00:00+00:00"
    data = body["data"]
    assert data == {
        "run_id": verification.manifest.run_id,
        "tool_version": "0.0.0-test",
        "gate": str(verification.gate),
        "exit_code": verification.exit_code,
        "stopped_by": None,
        "open_questions": ["unverified", "skipped"],
        "counts": {
            "findings": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "unverified": 2,
            "waived": 0,
            "errors": 0,
            "skipped": 1,
            "shortfalls": 0,
            "cases": {
                "passed": 0,
                "failed": 0,
                "measured": 0,
                "inconclusive": 0,
                "error": 0,
                "skipped": 0,
            },
            "suites": {"pass": 0, "fail": 0, "inconclusive": 0},
        },
        "target": {"kind": "artifact", "ref": "."},
        "deployment": {"environment": "staging", "commit_sha": "abc123"},
        "findings": [{"rule_id": "acme.high", "severity": "HIGH", "title": "fired"}],
        "findings_truncated": False,
    }


def test_the_body_carries_no_evidence() -> None:
    built = webhook.build_body(_verification(ScanResult((_finding("acme.x"),), ("acme.x",), ())))

    assert isinstance(built, bytes)
    assert b"system prompt" not in built
    assert b"app.py" not in built


def test_findings_are_listed_most_severe_first_at_most_fifty() -> None:
    findings = (
        *(_finding(f"acme.low{n}", Severity.LOW) for n in range(60)),
        _finding("acme.critical", Severity.CRITICAL),
    )

    data = _body(_verification(ScanResult(findings, (), ())))["data"]

    assert len(data["findings"]) == 50
    assert data["findings"][0]["rule_id"] == "acme.critical"
    assert data["findings"][1]["rule_id"] == "acme.low0"
    assert data["findings_truncated"] is True
    assert data["counts"]["findings"]["LOW"] == 60


def test_findings_are_dropped_from_the_end_until_the_body_fits() -> None:
    findings = tuple(_finding(f"acme.r{n}", title="t" * 900) for n in range(30))

    built = webhook.build_body(_verification(ScanResult(findings, (), ())))

    assert isinstance(built, bytes)
    assert len(built) <= webhook.MAX_BODY_BYTES
    data = json.loads(built)["data"]
    assert 0 < len(data["findings"]) < 30
    assert [f["rule_id"] for f in data["findings"]] == [
        f"acme.r{n}" for n in range(len(data["findings"]))
    ]
    assert data["findings_truncated"] is True


def test_a_body_that_cannot_fit_is_not_sent() -> None:
    verification = _verification(
        ScanResult((), (), ()), deployment=DeploymentRef(ai_system="x" * webhook.MAX_BODY_BYTES)
    )

    delivery = _prepare("https://hooks.example.com/guardana").deliver(verification)

    assert delivery.status is DeliveryStatus.NOT_SENT
    assert "larger than 20480 bytes" in delivery.detail


def test_the_timestamp_falls_back_to_the_start() -> None:
    result = ScanResult((), (), ())
    started = manifest_for(result).started_at

    body = _body(_verification(result, completed_at=None))

    assert started is not None
    assert body["timestamp"] == started.isoformat()


def test_a_run_with_neither_time_is_not_sent(no_network: list[object]) -> None:
    result = ScanResult((), (), ())
    verification = _verification(result, completed_at=None)
    verification = dataclasses.replace(
        verification,
        manifest=dataclasses.replace(verification.manifest, started_at=None, migrated_from=1),
    )

    delivery = _prepare("https://hooks.example.com/guardana").deliver(verification)

    assert delivery.status is DeliveryStatus.NOT_SENT
    assert delivery.attempts == 0
    assert no_network == []


def test_a_stopped_run_says_what_stopped_it() -> None:
    data = _body(_verification(ScanResult((), (), (), stopped_by=StopReason.BUDGET_EXHAUSTED)))[
        "data"
    ]

    assert data["stopped_by"] == "budget_exhausted"
    assert data["exit_code"] == 6
    assert data["open_questions"][0] == "stopped"


# Each channel of `ScanResult` and where the body accounts for it. A channel in neither
# map was added after the body was written, and would be dropped without a count.
_COUNTED = {
    "findings": ("counts", "findings", "HIGH"),
    "unverified": ("counts", "unverified"),
    "waived": ("counts", "waived"),
    "errors": ("counts", "errors"),
    "rules_skipped": ("counts", "skipped"),
    "coverage_shortfall": ("counts", "shortfalls"),
    "assessments": ("counts", "cases", "inconclusive"),
    "suites": ("counts", "suites", "pass"),
    "stopped_by": ("stopped_by",),
}
_UNCOUNTED = {"rules_run", "observations", "usage", "protocols", "trials_per_case", "scope"}
_ONE_OF_EACH: dict[str, Any] = {
    "findings": (_finding("acme.x"),),
    "unverified": (_finding("acme.y"),),
    "waived": (_finding("acme.z"),),
    "errors": (CheckError(source="acme.e", stage="run", reason="raised"),),
    "rules_skipped": (SkippedRule("acme.s", SkipReason.NOT_APPLICABLE, (), ""),),
    "coverage_shortfall": (CoverageShortfall(ShortfallKind.DEMANDED_CHECK, "acme.d", "absent"),),
    "assessments": (
        Assessment(
            case_id="c", assessor="a", subject_ref="s", status=AssessmentStatus.INCONCLUSIVE
        ),
    ),
    "suites": {"acme.suite": suite_summary()},
    "stopped_by": StopReason.INTERRUPTED,
}


def test_every_result_channel_is_counted_or_excluded_by_name() -> None:
    names = {item.name for item in dataclasses.fields(ScanResult)}

    assert names == set(_COUNTED) | _UNCOUNTED
    assert set(_COUNTED).isdisjoint(_UNCOUNTED)


@pytest.mark.parametrize("name", sorted(_COUNTED))
def test_every_counted_channel_moves_its_count(name: str) -> None:
    empty = ScanResult((), (), ())
    filled = dataclasses.replace(empty, **{name: _ONE_OF_EACH[name]})

    before = _body(_verification(empty))["data"]
    after = _body(_verification(filled))["data"]

    for key in _COUNTED[name]:
        before, after = before[key], after[key]
    assert before in {0, None}
    assert after not in {0, None}


def test_the_webhook_id_is_stable_for_a_run_and_differs_between_runs() -> None:
    first = webhook.webhook_id("run.completed", "run-1")

    assert first == webhook.webhook_id("run.completed", "run-1")
    assert first.startswith("msg_")
    assert first != webhook.webhook_id("run.completed", "run-2")


def test_the_signature_is_what_the_reference_verifier_expects() -> None:
    body = b'{"type":"run.completed"}'
    timestamp = "1767225600"

    signature = webhook.sign(_KEY, "msg_1", timestamp, body)

    moment = datetime.fromtimestamp(int(timestamp), tz=UTC)
    assert signature == Webhook(_SECRET).sign("msg_1", moment, body.decode())


def test_the_network_guard_refuses_a_connection(no_network: list[object]) -> None:
    """Without this, a guard that patched the wrong thing would make every test above vacuous."""
    with socket.socket() as attempt, pytest.raises(AssertionError, match="the network is off"):
        attempt.connect(("127.0.0.1", 9))

    assert no_network == [("127.0.0.1", 9)]
