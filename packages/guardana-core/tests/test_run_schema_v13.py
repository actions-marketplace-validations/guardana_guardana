"""Run schema 13 records which execution a run graded apart from how it graded it.

Four new facts: the exchanges a probe kept (`run.exchanges`), the recording a graded run
answered from (`run.recording`), the judge identity each evaluator stated
(`evaluators[].judge`) and why a trial went unmeasured (`assessments[].reason`), with the
`not_recorded` skip reason. A version-12 run arrives with all four null, which is unknown,
never "kept nothing" or "graded live".
"""

import copy
import json
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from _documents import counted, run_manifest, saved_run_at_v12, saved_run_at_v13, scan_result
from guardana.core.assessment import UnmeasuredReason
from guardana.core.evaluator.base import Expectation
from guardana.core.evaluator.canary import CanaryEvaluator
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    ExchangesRecord,
    RecordingOriginRecord,
    RecordingRecord,
    RunManifest,
)
from guardana.core.manifest.build import build_run_manifest
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v12
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding, ScanResult, SkippedRule, SkipReason
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.serialize import run_to_dict
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Target, TargetKind
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_DIGEST = "sha256:" + "ef" * 32


def _errors(document: dict[str, Any]) -> list[str]:
    """Validate `document` against the v13 schema, in the shape a version-13 build wrote."""
    document = saved_run_at_v13(document)
    schema = json.loads((_SCHEMAS / "run-v13.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _write(document: dict[str, Any], tmp_path: Path) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run(document: dict[str, Any]) -> dict[str, Any]:
    run: dict[str, Any] = document["run"]
    return run


# The document this build writes


def test_the_written_document_satisfies_the_v13_schema() -> None:
    assert not _errors(_document())


def test_every_new_field_is_written() -> None:
    document = _document()
    run = _run(document)

    assert run["exchanges"] == {"digest": _DIGEST, "count": 12, "altered": 2}
    assert run["recording"] == {
        "name": "support-replies",
        "version": "2026.09",
        "subject": "checkout-assistant",
        "verbatim": False,
        "origin": {
            "run_id": "5d0c8a1b-3e2f-4a6d-9b7c-1f2e3d4c5b6a",
            "target": "http://model.invalid/v1",
            "started_at": "2026-08-10T08:00:00Z",
            "stopped_by": "budget_exhausted",
            "gate": "fail",
        },
    }
    assert run["evaluators"][0]["judge"] == "model=m;endpoint=sha256:acac;samples=1"
    assert [entry["reason"] for entry in document["assessments"]] == [
        None,
        None,
        None,
        "not_recorded",
    ]


def test_every_new_field_survives_being_saved_and_read_back(tmp_path: Path) -> None:
    manifest = run_manifest()

    report = load_report(_write(run_to_dict(scan_result(), manifest), tmp_path))

    assert report.manifest.exchanges == manifest.exchanges
    assert report.manifest.recording == manifest.recording
    assert report.manifest.evaluators[0].judge == manifest.evaluators[0].judge
    assert [a.reason for a in report.result.assessments] == [
        None,
        None,
        None,
        UnmeasuredReason.NOT_RECORDED,
    ]


@pytest.mark.parametrize(
    ("exchanges", "recording"),
    [
        (None, None),
        (ExchangesRecord(digest=_DIGEST, count=0, altered=0), None),
        (
            None,
            RecordingRecord(
                name="hand-written", version="1", subject=None, verbatim=True, origin=None
            ),
        ),
        (
            None,
            RecordingRecord(
                name="kept",
                version="2026.09",
                subject=None,
                verbatim=True,
                origin=RecordingOriginRecord(
                    run_id="r", target="t", started_at=None, stopped_by=None, gate=None
                ),
            ),
        ),
    ],
    ids=["live run", "kept nothing", "hand-written recording", "origin states only its run"],
)
def test_the_execution_identity_survives_being_saved_and_read_back(
    exchanges: ExchangesRecord | None, recording: RecordingRecord | None
) -> None:
    manifest = replace(run_manifest(), exchanges=exchanges, recording=recording)

    assert not _errors(run_to_dict(scan_result(), manifest))
    assert manifest_from_dict(manifest_to_dict(manifest)) == manifest


_V13_REASONS = (
    UnmeasuredReason.NOT_RECORDED,
    UnmeasuredReason.REPLY_ALTERED,
    UnmeasuredReason.DECLINED,
)


@pytest.mark.parametrize("reason", _V13_REASONS)
def test_every_v13_unmeasured_reason_survives_being_saved_and_read_back(
    reason: UnmeasuredReason, tmp_path: Path
) -> None:
    result = scan_result()
    changed = replace(result.assessments[-1], reason=reason)
    written = replace(result, assessments=(changed,))
    saved = run_to_dict(written, counted(run_manifest(), written))

    assert not _errors(saved)
    assert load_report(_write(saved, tmp_path)).result.assessments == (changed,)


def test_a_rule_skipped_as_not_recorded_survives_being_saved_and_read_back(
    tmp_path: Path,
) -> None:
    skip = SkippedRule(
        rule_id="guardana.prompt.jailbreak",
        reason=SkipReason.NOT_RECORDED,
        missing=(),
        detail="the recording answers none of this rule's questions",
    )
    manifest = run_manifest()
    manifest = replace(
        manifest, result_summary=replace(manifest.result_summary, rules_skipped=(skip,))
    )
    saved = run_to_dict(replace(scan_result(), rules_skipped=(skip,)), manifest)

    assert not _errors(saved)
    report = load_report(_write(saved, tmp_path))
    assert report.result.rules_skipped == (skip,)
    assert report.manifest.result_summary.rules_skipped == (skip,)


# The records refuse what no run produces


@pytest.mark.parametrize(
    ("digest", "count", "altered"),
    [
        ("sha256:" + "ef" * 31, 1, 0),
        ("sha256:" + "EF" * 32, 1, 0),
        ("ef" * 32, 1, 0),
        (_DIGEST, -1, 0),
        (_DIGEST, 1, -1),
        (_DIGEST, 1, 2),
        (_DIGEST, True, 0),
    ],
    ids=[
        "short",
        "upper case",
        "no algorithm",
        "negative count",
        "negative altered",
        "altered over count",
        "bool count",
    ],
)
def test_an_exchanges_record_refuses_what_no_probe_kept(
    digest: str, count: int, altered: int
) -> None:
    with pytest.raises((ValueError, TypeError)):
        ExchangesRecord(digest=digest, count=count, altered=altered)


_RUN_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "exchanges missing": lambda run: run.pop("exchanges"),
    "exchanges not an object": lambda run: run.update(exchanges=[1]),
    "exchanges unknown key": lambda run: run["exchanges"].update(lines=3),
    "exchanges digest bare hex": lambda run: run["exchanges"].update(digest="ef" * 32),
    "exchanges count negative": lambda run: run["exchanges"].update(count=-1),
    "exchanges count missing": lambda run: run["exchanges"].pop("count"),
    "exchanges altered a string": lambda run: run["exchanges"].update(altered="2"),
    "recording missing": lambda run: run.pop("recording"),
    "recording unknown key": lambda run: run["recording"].update(digest=_DIGEST),
    "recording name missing": lambda run: run["recording"].pop("name"),
    "recording subject missing": lambda run: run["recording"].pop("subject"),
    "recording verbatim not a flag": lambda run: run["recording"].update(verbatim="yes"),
    "recording version not a string": lambda run: run["recording"].update(version=1),
    "origin not an object": lambda run: run["recording"].update(origin="probe"),
    "origin unknown key": lambda run: run["recording"]["origin"].update(trials=3),
    "origin gate missing": lambda run: run["recording"]["origin"].pop("gate"),
    "origin run id null": lambda run: run["recording"]["origin"].update(run_id=None),
    "judge missing": lambda run: run["evaluators"][0].pop("judge"),
    "judge not a string": lambda run: run["evaluators"][0].update(judge=3),
}


@pytest.mark.parametrize("breakage", _RUN_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_run_block(breakage: str) -> None:
    document = _document()
    _RUN_BREAKAGES[breakage](_run(document))

    with pytest.raises(ManifestLoadError):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v13 schema accepts {breakage}, which the loader refuses"


def test_the_loader_refuses_more_altered_exchanges_than_were_kept() -> None:
    document = _document()
    _run(document)["exchanges"].update(count=1, altered=2)

    with pytest.raises(ManifestLoadError, match="exchanges"):
        manifest_from_dict(document["run"])


_ASSESSMENT_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "reason missing": lambda doc: doc["assessments"][3].pop("reason"),
    "reason unknown": lambda doc: doc["assessments"][3].update(reason="timed_out"),
    "reason not a string": lambda doc: doc["assessments"][3].update(reason=1),
    "reason on a measured trial": lambda doc: doc["assessments"][0].update(reason="declined"),
    "skip reason unknown": lambda doc: doc["run"]["result_summary"]["rules_skipped"][0].update(
        reason="not_replayed"
    ),
}


@pytest.mark.parametrize("breakage", _ASSESSMENT_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_measurement(
    breakage: str, tmp_path: Path
) -> None:
    document = _document()
    _ASSESSMENT_BREAKAGES[breakage](document)

    with pytest.raises(ReportLoadError):
        load_report(_write(document, tmp_path))
    assert _errors(document), f"the v13 schema accepts {breakage}, which the loader refuses"


# Version 12 forward


def test_a_v12_run_migrates_to_13_with_every_new_field_unknown() -> None:
    v12 = saved_run_at_v12(_document())

    migrated = migrate_v12(v12)

    assert migrated["schema_version"] == 13
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v13.schema.json"
    assert not _errors(migrated)
    run = _run(migrated)
    assert run["exchanges"] is None
    assert run["recording"] is None
    assert [entry["judge"] for entry in run["evaluators"]] == [None]
    assert [entry["reason"] for entry in migrated["assessments"]] == [None] * 4


def test_the_migration_overwrites_what_a_v12_run_should_not_hold() -> None:
    v12 = saved_run_at_v12(_document())
    written = _run(_document())
    _run(v12).update(exchanges=written["exchanges"], recording=written["recording"])
    _run(v12)["evaluators"][0]["judge"] = "model=m"
    v12["assessments"][3]["reason"] = "not_recorded"

    migrated = migrate_v12(v12)

    assert _run(migrated)["exchanges"] is None
    assert _run(migrated)["recording"] is None
    assert _run(migrated)["evaluators"][0]["judge"] is None
    assert migrated["assessments"][3]["reason"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v12 = saved_run_at_v12(_document())
    before = copy.deepcopy(v12)

    migrated = migrate_v12(v12)

    assert v12 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v12(migrated) == v12


def test_a_loaded_v12_run_says_it_was_migrated_and_records_no_identity(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v12(_document()), tmp_path))

    assert report.manifest.migrated_from == 12
    assert report.manifest.exchanges is None
    assert report.manifest.recording is None
    assert all(record.judge is None for record in report.manifest.evaluators)
    assert all(a.reason is None for a in report.result.assessments)


# What a run built by the engine records


class _Graded(Rule):
    """Declares one judge and one deterministic evaluator, and finds nothing."""

    meta = RuleMeta("guardana.test.graded", "graded", Severity.HIGH, TargetKind.ENDPOINT)

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        return (("guard", Expectation()), ("canary", Expectation(canary="c")))

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def _built(
    *,
    exchanges: ExchangesRecord | None = None,
    recording: RecordingRecord | None = None,
) -> RunManifest:
    registry = Registry()
    registry.register_rule(_Graded())
    registry.register_evaluator(
        GuardEvaluator(lambda _text: "safe", judge_identity="model=guard-3;endpoint=sha256:aa")
    )
    registry.register_evaluator(CanaryEvaluator())
    return build_run_manifest(
        registry,
        Profile(name="p", policy=Policy()),
        ScanResult(findings=(), rules_run=("guardana.test.graded",), rules_skipped=()),
        target_kind=TargetKind.ENDPOINT,
        target_ref="http://model.invalid/v1",
        gate=GateOutcome.PASS,
        started_at=datetime(2026, 8, 11, 9, 15, tzinfo=UTC),
        calibrations={},
        exchanges=exchanges,
        recording=recording,
    )


def test_an_evaluator_record_carries_the_judge_identity_its_evaluator_states() -> None:
    judges = {record.id: record.judge for record in _built().evaluators}

    assert judges == {"canary": None, "guard": "model=guard-3;endpoint=sha256:aa"}


def test_a_built_run_records_the_exchanges_and_the_recording_it_was_handed() -> None:
    exchanges = ExchangesRecord(digest=_DIGEST, count=3, altered=1)
    recording = RecordingRecord(
        name="kept", version="2026.09", subject="checkout", verbatim=True, origin=None
    )

    manifest = _built(exchanges=exchanges, recording=recording)

    assert manifest.exchanges == exchanges
    assert manifest.recording == recording
    assert _built().exchanges is None
    assert _built().recording is None
