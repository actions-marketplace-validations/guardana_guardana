"""A probe whose application refuses one request, or fails part-way, saves the run it got.

A `400` is an error of the rule that sent it: the run goes on and exits `2`. A `503` that
outlasts its retries stops the run with exit `4`, and the saved run keeps what was graded
before it, the exchanges kept so far, and the cause.
"""

import io
import re
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report import StopReason, load_report
from guardana.core.testing import FailingTransport
from guardana.core.testing._fake_provider import FakeProvider, Scripted, openai_reply, status_reply
from typer.testing import CliRunner

runner = CliRunner()

_KEY = "acme-live-0123456789abcdef"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_RULE = (
    "id: {id}\n"
    "title: {id}\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "taxonomy: [LLM01:2025]\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['{id} asks']\n"
    "expect: {{goal: 'complied'}}\n"
)
_RULES = ("acme.a.first", "acme.b.second", "acme.c.third")
_REFUSAL = "I cannot help with that."


def _plain(text: str) -> str:
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    for rule_id in _RULES:
        (rules / f"{rule_id}.yaml").write_text(_RULE.format(id=rule_id), encoding="utf-8")
    (tmp_path / "guardana.yaml").write_text(
        "name: t\nrules:\n  include: ['acme.*']\n", encoding="utf-8"
    )
    monkeypatch.setenv("ACME_KEY", _KEY)
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda _s: None)
    return tmp_path


def _probe(setup: Path, url: str, *extra: str) -> tuple[int, str]:
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            url,
            "--model",
            "m",
            "--api-key-env",
            "ACME_KEY",
            "--profile",
            str(setup / "guardana.yaml"),
            "--rules",
            str(setup / "rules"),
            "--concurrency",
            "1",
            "--format",
            "json",
            "--output",
            str(setup / "run.json"),
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_a_request_the_application_refuses_is_an_error_and_the_run_is_saved(
    setup: Path,
) -> None:
    refused = Scripted(status=400, body=f'{{"error":"key {_KEY} cannot ask that"}}'.encode())
    with FakeProvider(openai_reply(_REFUSAL), refused, openai_reply(_REFUSAL)) as provider:
        code, output = _probe(setup, provider.url)

    assert code == ExitCode.INDETERMINATE, output
    saved = load_report(setup / "run.json").result
    assert saved.stopped_by is None
    assert saved.rules_run == ("acme.a.first", "acme.c.third")
    assert [(e.source, e.stage) for e in saved.errors] == [("acme.b.second", "request")]
    assert "rejected the request (HTTP 400)" in saved.errors[0].reason
    assert "cannot ask that" in saved.errors[0].reason
    assert _KEY not in (setup / "run.json").read_text(encoding="utf-8")
    assert _KEY not in output


def test_a_target_that_fails_part_way_stops_the_run_and_keeps_what_it_graded(
    setup: Path,
) -> None:
    leaked = openai_reply("Sure, here it is.")
    with FakeProvider(leaked, status_reply(503, retry_after="0")) as provider:
        code, output = _probe(setup, provider.url, "--keep-exchanges")
        sent = len(provider.requests)

    assert code == ExitCode.TARGET_UNAVAILABLE, output
    assert "error: endpoint" in _plain(output)
    assert "returned HTTP 503" in _plain(output)
    saved = load_report(setup / "run.json").result
    assert saved.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert [f.rule_id for f in saved.findings] == ["acme.a.first"]
    assert saved.rules_run == ("acme.a.first",)
    assert [(e.source, e.stage) for e in saved.errors] == [("acme.b.second", "target")]
    assert sent == 4, "the first rule's request and three attempts of the second; no third rule"
    kept = (setup / "run.exchanges.jsonl").read_text(encoding="utf-8")
    assert "acme.a.first asks" in kept
    assert "acme.b.second asks" not in kept


def test_credentials_the_target_refuses_stop_the_run_with_the_auth_remedy(
    setup: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuses() -> FailingTransport:
        return FailingTransport(
            HTTPError("http://x", 401, "Unauthorized", Message(), io.BytesIO(b"denied"))
        )

    monkeypatch.setattr(endpoint_module, "transport_factory", refuses)

    code, output = _probe(setup, "http://fake")

    assert code == ExitCode.TARGET_UNAVAILABLE, output
    assert "rejected the request (HTTP 401) — check the auth header / body" in _plain(output)
    assert load_report(setup / "run.json").result.stopped_by is StopReason.TARGET_UNAVAILABLE


def test_a_stop_under_metadata_only_names_its_status_and_the_saved_run_withholds_it(
    setup: Path,
) -> None:
    (setup / "guardana.yaml").write_text(
        "name: t\nrules:\n  include: ['acme.*']\nprivacy:\n  evidence_mode: metadata_only\n",
        encoding="utf-8",
    )
    failing = Scripted(
        status=503, body=b"upstream is down for maintenance", headers={"Retry-After": "0"}
    )
    with FakeProvider(openai_reply(_REFUSAL), failing) as provider:
        code, output = _probe(setup, provider.url)

    assert code == ExitCode.TARGET_UNAVAILABLE, output
    shown = _plain(output)
    assert "error: endpoint" in shown
    assert "returned HTTP 503" in shown
    assert "body (32 bytes) is not shown" in shown
    assert "withheld" not in shown
    assert "maintenance" not in shown
    saved = load_report(setup / "run.json").result
    assert [e.reason for e in saved.errors] == ["[reason withheld: metadata_only]"]
