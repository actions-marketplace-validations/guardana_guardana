import importlib
import json
import pkgutil
import sys

import guardana.core
import pytest
from guardana.core.evaluator.base import Verdict
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.reporter import ENVELOPE_SCHEMA_VERSION, HttpReporter
from guardana.core.severity import Severity
from guardana.core.taxonomy import OWASP_LLM01_2025


def _make_result() -> ScanResult:
    finding = Finding(
        rule_id="prompt-injection-basic",
        severity=Severity.HIGH,
        title="Prompt injection succeeded",
        taxonomy=(OWASP_LLM01_2025,),
        target_ref="https://target#model",
        evidence=Evidence(summary="model followed injected instruction"),
        verdict=Verdict(
            outcome="fail",
            confidence=0.9,
            rationale="canary leaked",
            evaluator_id="canary",
        ),
    )
    return ScanResult(findings=(finding,), rules_run=("r0",), rules_skipped=())


def test_http_reporter_submits_serialized_findings() -> None:
    captured: list[tuple[str, bytes]] = []

    def fake_transport(url: str, body: bytes) -> None:
        captured.append((url, body))

    reporter = HttpReporter("https://collector/x", transport=fake_transport)
    reporter.submit(_make_result(), source="ci")

    assert len(captured) == 1
    url, body = captured[0]
    assert url == "https://collector/x"

    payload = json.loads(body)
    assert payload["source"] == "ci"
    assert len(payload["findings"]) == 1

    finding = payload["findings"][0]
    assert finding["rule_id"] == "prompt-injection-basic"
    assert finding["severity"] == "HIGH"
    assert finding["verdict"]["outcome"] == "fail"


def test_http_reporter_forwards_the_unverified_channel() -> None:
    # A check that ran but could not grade must reach the collector, or a
    # dashboard renders a false all-clear. Envelope v1 dropped these entirely.
    inconclusive = Finding(
        rule_id="guardana.prompt.system_prompt_leak.canary",
        severity=Severity.CRITICAL,
        title="System prompt leak",
        taxonomy=(OWASP_LLM01_2025,),
        target_ref="https://target#model",
        evidence=Evidence(summary="judge unreachable"),
        verdict=Verdict(
            outcome="inconclusive", confidence=0.0, rationale="no reply", evaluator_id="canary"
        ),
    )
    result = ScanResult(
        findings=(), rules_run=("r0",), rules_skipped=(), unverified=(inconclusive,)
    )
    captured: list[bytes] = []
    HttpReporter("https://c/x", transport=lambda _u, b: captured.append(b)).submit(
        result, source="ci"
    )

    payload = json.loads(captured[0])
    assert payload["schema_version"] == ENVELOPE_SCHEMA_VERSION
    assert payload["findings"] == []
    assert payload["summary"]["unverified"] == 1
    assert len(payload["unverified"]) == 1
    assert payload["unverified"][0]["verdict"]["outcome"] == "inconclusive"


def test_non_http_reporter_url_rejected() -> None:
    with pytest.raises(ValueError, match="scheme"):
        HttpReporter("file:///tmp/findings.json")


def test_core_does_not_depend_on_server() -> None:
    # Snapshot first: pytest's collection phase may have already imported
    # `guardana.server` via its own test modules, independent of anything
    # `guardana.core` does. Only new imports triggered by the loop below would
    # indicate a real core -> server dependency.
    pre_existing = {name for name in sys.modules if name.startswith("guardana.server")}

    for module_info in pkgutil.walk_packages(guardana.core.__path__, prefix="guardana.core."):
        importlib.import_module(module_info.name)

    server_modules = {name for name in sys.modules if name.startswith("guardana.server")}
    assert server_modules - pre_existing == set()


def _submitted_source(source: str, redactor: EvidenceRedactor | None = None) -> str:
    captured: list[bytes] = []
    HttpReporter(
        "https://c/x", transport=lambda _u, b: captured.append(b), redactor=redactor
    ).submit(ScanResult((), (), ()), source=source)
    submitted = json.loads(captured[0])["source"]
    assert isinstance(submitted, str)
    return submitted


def test_a_credential_in_the_source_never_reaches_the_collector() -> None:
    secret = "sk-" + "A" * 20

    submitted = _submitted_source(f"/builds/{secret}/model")

    assert secret not in submitted
    assert "[redacted:openai-key" in submitted


def test_a_source_without_a_credential_reaches_the_collector_unchanged() -> None:
    assert _submitted_source("http://127.0.0.1:8000#llama3") == "http://127.0.0.1:8000#llama3"


def test_metadata_only_still_names_the_source_and_still_strips_its_credential() -> None:
    # The source is what a collector groups runs by, so blanking it would merge every
    # target into one; it is redacted, never withheld.
    secret = "sk-" + "B" * 20
    redactor = EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    submitted = _submitted_source(f"/builds/{secret}/model", redactor)

    assert secret not in submitted
    assert submitted.startswith("/builds/")
