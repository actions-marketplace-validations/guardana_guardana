"""A saved run of any schema reads back as a `Verification`, its verdict the one it recorded.

This is how a run is exported after the fact, so the gate must never be re-derived: a run
that recorded no verdict, as a migrated schema-1 run did not, is refused rather than read.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from _documents import (
    run_manifest,
    saved_run_at_v7,
    saved_run_at_v8,
    saved_run_at_v9,
    saved_run_at_v10,
    saved_run_at_v11,
    saved_run_at_v12,
    saved_run_at_v13,
    saved_run_at_v14,
    saved_run_at_v15,
    saved_run_at_v16,
    scan_result,
)
from guardana.core.gate import GateOutcome
from guardana.core.report import ReportLoadError, load_report
from guardana.core.report.serialize import run_to_dict
from guardana.core.verify import load_verification

_SAVED_RUNS = Path(__file__).parent / "saved_runs"


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize("path", sorted(_SAVED_RUNS.glob("*.json")), ids=lambda p: p.name)
def test_every_kept_saved_run_reads_back_with_its_recorded_gate(path: Path) -> None:
    report = load_report(path)

    verification = load_verification(path)

    assert verification.gate is report.manifest.result_summary.gate
    assert verification.result == report.result
    assert verification.manifest == report.manifest
    assert verification.exchanges is None


def _current(document: dict[str, Any]) -> dict[str, Any]:
    return document


@pytest.mark.parametrize(
    "older",
    [
        _current,
        saved_run_at_v16,
        saved_run_at_v15,
        saved_run_at_v14,
        saved_run_at_v13,
        saved_run_at_v12,
        saved_run_at_v11,
        saved_run_at_v10,
        saved_run_at_v9,
        saved_run_at_v8,
        saved_run_at_v7,
    ],
    ids=lambda f: f.__name__,
)
def test_a_document_of_each_schema_reads_back_with_the_gate_it_recorded(
    tmp_path: Path, older: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    manifest = run_manifest()
    path = _write(tmp_path, older(run_to_dict(scan_result(), manifest)))

    verification = load_verification(path)

    assert manifest.result_summary.gate is not None
    assert verification.gate is manifest.result_summary.gate
    assert verification.result == load_report(path).result
    assert verification.stop_messages == ()
    assert verification.judge_stops == ()


def test_the_gate_is_read_as_recorded_never_re_derived(tmp_path: Path) -> None:
    manifest = run_manifest()
    summary = manifest.result_summary
    document: dict[str, Any] = json.loads(json.dumps(run_to_dict(scan_result(), manifest)))
    document["run"]["result_summary"]["gate"] = "pass"

    verification = load_verification(_write(tmp_path, document))

    assert summary.gate is not GateOutcome.PASS
    assert verification.gate is GateOutcome.PASS


_V1_RUN = {
    "schema_version": 1,
    "run": {
        "tool_version": "0.6.0",
        "target_kind": "endpoint",
        "target_ref": "http://model.invalid#m",
        "profile": "ci",
        "rules": {"guardana.demo": "abc123"},
        "rules_skipped": [],
        "started_at": "2026-07-25T09:00:00+00:00",
    },
    "findings": [],
    "unverified": [],
    "waived": [],
    "errors": [],
    "observations": [],
    "summary": {"rules_run": 1, "rules_skipped": [], "max_severity": None},
}


def test_a_schema_one_run_records_no_gate_so_it_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, _V1_RUN)
    assert load_report(path).manifest.result_summary.gate is None

    with pytest.raises(ReportLoadError) as raised:
        load_verification(path)

    assert str(raised.value) == f"{path} records no gate, so its verdict cannot be read"


def test_an_unreadable_file_is_refused_as_load_report_refuses_it(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(ReportLoadError):
        load_verification(path)
