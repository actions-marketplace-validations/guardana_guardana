"""The two checks over seeded data, run through the installed CLI against the reference application.

Each test renders the documents with `guardana fixtures render`, serves the application
over them on a local port, and probes it with `--fixtures` as a team would in CI. The
application counts every request it receives, so the run's own count is checked against
something Guardana did not write.
"""

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from retrieval_pilot import ORDER_TOOL, ReferenceApplication, Switches, make_server

EXAMPLE = Path(__file__).resolve().parent.parent
FIXTURES = EXAMPLE / "guardana-fixtures.yaml"
PROFILE = EXAMPLE / "guardana.yaml"
TENANCY = "guardana.tenancy.cross_tenant_answer"
POISONING = "guardana.retrieval.poisoned_document"
_KEYS = {"ACME_KEY": "acme-ci-key", "GLOBEX_KEY": "globex-ci-key"}


def _guardana() -> str:
    """The `guardana` console script installed beside this interpreter."""
    script = Path(sys.executable).parent / "guardana"
    if not script.exists():
        pytest.fail(f"no guardana command beside {sys.executable}; install guardana-cli")
    return str(script)


@pytest.fixture
def environ() -> dict[str, str]:
    """The environment of the CLI and the application: each tenant's key, nothing else secret."""
    return {**os.environ, **_KEYS}


def _cli(environ: Mapping[str, str], cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — the installed CLI with arguments built here
        [_guardana(), *args],
        env=dict(environ),
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.fixture
def documents(tmp_path: Path, environ: dict[str, str]) -> Path:
    """Render the fixtures' documents as a team would before seeding its index."""
    result = _cli(environ, tmp_path, "fixtures", "render", str(FIXTURES), "--out", "seed")
    assert result.returncode == 0, result.stdout + result.stderr
    rendered = tmp_path / "seed" / "documents.jsonl"
    assert rendered.is_file()
    return rendered


@dataclass
class Served:
    """A running application, its URL and the trace its doubles write."""

    application: ReferenceApplication
    url: str
    trace: Path


@contextmanager
def _serving(
    tmp_path: Path, documents: Path, environ: Mapping[str, str], switches: Switches
) -> Iterator[Served]:
    trace = tmp_path / "doubles.jsonl"
    application = ReferenceApplication(
        FIXTURES, documents, trace=trace, switches=switches, environ=environ
    )
    server = make_server(application, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Served(application, f"http://127.0.0.1:{server.server_address[1]}", trace)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        application.close()


def _probe(
    served: Served, environ: Mapping[str, str], tmp_path: Path
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    output = tmp_path / "run.json"
    result = _cli(
        environ,
        tmp_path,
        "probe",
        "--url",
        served.url,
        "--model",
        "reference",
        "--fixtures",
        str(FIXTURES),
        "--profile",
        str(PROFILE),
        "--format",
        "json",
        "--output",
        str(output),
    )
    document: dict[str, Any] = json.loads(output.read_text("utf-8")) if output.exists() else {}
    return result, document


def _findings(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = document["findings"]
    return [f for f in findings if f["verdict"]["outcome"] == "fail"]


def test_the_fixed_application_passes_and_the_run_counts_what_it_received(
    tmp_path: Path, documents: Path, environ: dict[str, str]
) -> None:
    with _serving(tmp_path, documents, environ, Switches()) as served:
        result, document = _probe(served, environ, tmp_path)
        received = served.application.received

    assert result.returncode == 0, result.stdout + result.stderr
    assert _findings(document) == []
    assert document["run"]["coverage"]["shortfall"] == []
    assert document["run"]["usage"]["requests"] == received

    plan = _cli(
        {k: v for k, v in environ.items() if k not in _KEYS},
        tmp_path,
        "plan",
        "probe",
        "--url",
        served.url,
        "--model",
        "reference",
        "--fixtures",
        str(FIXTURES),
        "--profile",
        str(PROFILE),
        "--format",
        "json",
    )
    assert plan.returncode == 0, plan.stdout + plan.stderr
    assert json.loads(plan.stdout)["requests"]["max"] == received


def test_the_doubles_trace_records_every_order_lookup(
    tmp_path: Path, documents: Path, environ: dict[str, str]
) -> None:
    with _serving(tmp_path, documents, environ, Switches()) as served:
        result, _document = _probe(served, environ, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    inspected = _cli(environ, tmp_path, "trace", "inspect", str(served.trace), "--format", "json")
    assert inspected.returncode == 0, inspected.stdout + inspected.stderr
    report = json.loads(inspected.stdout)
    dimensions = {row["dimension"]: row for row in report["dimensions"]}
    # Each of the two orders is asked about as each of the two tenants, once.
    assert report["producer"] == "guardana.doubles"
    assert report["spans"] == 4
    assert report["truncated"] is None
    assert dimensions["tools"]["declared"] is True
    assert dimensions["tools"]["records"] == 4

    lines = [json.loads(line) for line in served.trace.read_text("utf-8").splitlines()]
    calls = [line for line in lines if line.get("kind") == "tool_execution"]
    assert sorted(json.loads(call["tool"]["arguments"])["id"] for call in calls) == [
        "A-100",
        "A-100",
        "G-200",
        "G-200",
    ]
    assert {call["name"] for call in calls} == {ORDER_TOOL}
    assert lines[-1] == {"guardana_trace_end": 3, "spans": 4}


def test_a_broken_tenant_filter_fails_through_documents_and_orders(
    tmp_path: Path, documents: Path, environ: dict[str, str]
) -> None:
    with _serving(tmp_path, documents, environ, Switches(break_tenant_filter=True)) as served:
        result, document = _probe(served, environ, tmp_path)

    assert result.returncode == 1, result.stdout + result.stderr
    findings = _findings(document)
    assert {f["rule_id"] for f in findings} == {TENANCY}
    summaries = " ".join(f["evidence"]["summary"] for f in findings)
    assert "documents/globex-shipping" in summaries
    assert "records/orders/A-100" in summaries
    assert "records/orders/G-200" in summaries


def test_a_model_that_obeys_a_document_fails_the_poisoning_check(
    tmp_path: Path, documents: Path, environ: dict[str, str]
) -> None:
    with _serving(tmp_path, documents, environ, Switches(obey_documents=True)) as served:
        result, document = _probe(served, environ, tmp_path)

    assert result.returncode == 1, result.stdout + result.stderr
    assert {f["rule_id"] for f in _findings(document)} == {POISONING}


def test_an_index_seeded_without_one_tenants_documents_is_indeterminate(
    tmp_path: Path, documents: Path, environ: dict[str, str]
) -> None:
    partial = tmp_path / "partial.jsonl"
    kept = [
        line
        for line in documents.read_text("utf-8").splitlines()
        if json.loads(line)["tenant"] != "globex"
    ]
    partial.write_text("\n".join(kept) + "\n", encoding="utf-8")

    with _serving(tmp_path, partial, environ, Switches()) as served:
        result, document = _probe(served, environ, tmp_path)

    assert result.returncode == 2, result.stdout + result.stderr
    assert _findings(document) == []
    shortfall = document["run"]["coverage"]["shortfall"]
    unreached = [gap["name"] for gap in shortfall if gap["kind"] == "seed_not_reached"]
    assert unreached
    assert any("globex" in name for name in unreached)
