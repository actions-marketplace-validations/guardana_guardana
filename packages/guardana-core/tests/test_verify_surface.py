"""The supported Python surface is `guardana.core.verify.__all__`, and its signatures are pinned.

A change here is a change to a supported API: it is announced under "Changed — breaking"
with what to write instead, never made in passing.
"""

import inspect
from dataclasses import fields

from guardana.core import verify

_SURFACE = {
    "CalibrationError",
    "EndpointBuilder",
    "JudgeUnreachableError",
    "RecordingRefusedError",
    "TargetReusedError",
    "TargetUnavailableError",
    "UnenforceableBudgetError",
    "UnsupportedTargetError",
    "Verification",
    "VerificationError",
    "Verifier",
    "exchanges_path",
    "load_verification",
}


def test_the_supported_names_are_exactly_the_documented_ones() -> None:
    assert set(verify.__all__) == _SURFACE


def test_every_error_derives_from_one_base() -> None:
    errors = [getattr(verify, name) for name in _SURFACE if name.endswith("Error")]
    assert errors

    assert all(issubclass(error, verify.VerificationError) for error in errors)


def test_the_verifier_takes_the_documented_arguments_and_trust_is_required() -> None:
    parameters = inspect.signature(verify.Verifier).parameters

    assert list(parameters) == [
        "trust",
        "profile",
        "rule_paths",
        "rules",
        "evaluators",
        "calibrations",
        "concurrency",
        "registry",
        "judge_endpoint",
        "demanded_rules",
        "subject_kind",
        "fixtures",
        "secrets",
        "remedies",
    ]
    assert parameters["trust"].default is inspect.Parameter.empty


def test_scan_run_and_grade_take_the_documented_keywords() -> None:
    scan = inspect.signature(verify.Verifier.scan).parameters
    run = inspect.signature(verify.Verifier.run).parameters
    grade = inspect.signature(verify.Verifier.grade).parameters

    assert list(scan) == ["self", "path", "relative_to", "baseline", "source", "deployment"]
    assert list(run) == ["self", "target", "relative_to", "baseline", "source", "deployment"]
    assert list(grade) == ["self", "path", "source", "deployment"]


def test_a_verification_holds_the_documented_fields() -> None:
    assert [f.name for f in fields(verify.Verification)] == [
        "result",
        "manifest",
        "gate",
        "judge_usage",
        "judge_stops",
        "exchanges",
        "stop_messages",
    ]
    for member in ("exit_code", "passed", "open_questions", "document", "save"):
        assert hasattr(verify.Verification, member), member


def test_a_saved_run_is_loaded_from_its_path_alone() -> None:
    assert list(inspect.signature(verify.load_verification).parameters) == ["path"]
