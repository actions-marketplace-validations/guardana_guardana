"""The `release` preset: a gate that vouches for every check it selected."""

from guardana.core.profile import PRESET_NAMES, preset
from guardana.core.redaction import EvidenceMode
from guardana.core.severity import Severity


def test_release_fails_on_high_and_on_every_check_that_did_not_decide() -> None:
    fail_on = preset("release").policy.fail_on

    assert fail_on.severity is Severity.HIGH
    assert fail_on.fail_on_skipped is True
    assert fail_on.fail_on_inconclusive is True
    assert fail_on.fail_on_error is True


def test_release_redacts_evidence_and_samples_like_the_other_presets() -> None:
    release = preset("release")

    assert release.privacy.mode is EvidenceMode.REDACTED
    assert {preset(name).trials for name in PRESET_NAMES} == {release.trials}


def test_release_is_a_listed_preset() -> None:
    assert "release" in PRESET_NAMES
