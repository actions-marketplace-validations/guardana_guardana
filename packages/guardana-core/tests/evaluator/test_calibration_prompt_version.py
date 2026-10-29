"""A calibration measured under another prompt version of the judge in force is named.

The prompt version is part of the judge's id, and a calibration applies only to the id
its verdicts carried; a profile whose calibration stopped applying when the default
version moved is told so, with the pin that keeps it.
"""

from collections.abc import Mapping
from datetime import UTC, datetime

from guardana.core.calibration.store import RecordedCalibration
from guardana.core.evaluator.config import (
    calibrations_for_another_prompt_version,
    wire_config_evaluators,
)
from guardana.core.profile import Profile
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry

_JUDGE = {"endpoint": "https://judge.example/v1", "model": "j"}


def _profile(**judge: object) -> Profile:
    return Profile(name="t", policy=Policy(), evaluator_config={"llm_judge": {**_JUDGE, **judge}})


def _inline(evaluator_id: str) -> Mapping[str, object]:
    return {"evaluator_id": evaluator_id, "accuracy": 0.9, "samples": 40}


def _recorded(evaluator: str, assessor: str | None) -> dict[str, RecordedCalibration]:
    return {
        evaluator: RecordedCalibration(
            evaluator=evaluator,
            dataset_digest="sha256:" + "ab" * 32,
            measured_at=datetime(2026, 1, 1, tzinfo=UTC),
            brier=0.1,
            ece=0.05,
            samples=60,
            assessor=assessor,
        )
    }


def test_a_profile_that_names_no_prompt_version_grades_with_the_fenced_one() -> None:
    registry = Registry()
    wire_config_evaluators(registry, _profile(), sending=False)

    assert registry.evaluators()["llm_judge"].assessor_id == "llm_judge@2026.1"


def test_an_inline_calibration_for_the_previous_default_is_named_with_its_pin() -> None:
    said = calibrations_for_another_prompt_version(
        _profile(calibration=_inline("llm_judge@2025.1")), {}
    )

    assert len(said) == 1
    assert "evaluators.llm_judge.calibration" in said[0]
    assert "llm_judge@2025.1" in said[0]
    assert "llm_judge@2026.1" in said[0]
    assert 'prompt_version: "2025.1"' in said[0]


def test_a_recorded_calibration_for_the_previous_default_is_named_with_its_pin() -> None:
    said = calibrations_for_another_prompt_version(
        _profile(), _recorded("llm_judge", "llm_judge@2025.1")
    )

    assert len(said) == 1
    assert "llm_judge@2025.1" in said[0]
    assert 'prompt_version: "2025.1"' in said[0]


def test_a_calibration_for_the_version_in_force_is_not_named() -> None:
    pinned = _profile(prompt_version="2025.1", calibration=_inline("llm_judge@2025.1"))
    current = _profile(calibration=_inline("llm_judge@2026.1"))

    assert (
        calibrations_for_another_prompt_version(pinned, _recorded("llm_judge", "llm_judge@2025.1"))
        == ()
    )
    assert (
        calibrations_for_another_prompt_version(current, _recorded("llm_judge", "llm_judge@2026.1"))
        == ()
    )


def test_a_calibration_of_another_evaluator_or_without_an_assessor_is_not_named() -> None:
    assert (
        calibrations_for_another_prompt_version(
            _profile(), _recorded("reference_judge", "reference_judge@2025.1")
        )
        == ()
    )
    assert calibrations_for_another_prompt_version(_profile(), _recorded("llm_judge", None)) == ()


def test_a_profile_without_a_judge_names_nothing() -> None:
    profile = Profile(name="t", policy=Policy())

    assert (
        calibrations_for_another_prompt_version(profile, _recorded("llm_judge", "llm_judge@2025.1"))
        == ()
    )
