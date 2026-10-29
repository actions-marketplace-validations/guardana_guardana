"""`privacy.keep_exchanges`: strict, refused beside `metadata_only`, digested only when set."""

from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.profile import ProfileError, load_profile
from guardana.core.profile.digest import profile_digest
from guardana.core.profile.presets import preset
from guardana.core.redaction import EvidenceMode, RedactionPolicy

_CI_PROFILE_DIGEST = "sha256:2219ab15facdd105c1e8fd70d1b970feca4e474d4f9973ef377aae8e2aba3e0c"
_REDACTED_POLICY_DIGEST = "sha256:abbe3d5542a6556472c6a72d16d05bfd8f64831d829070925cd2ef55e3fd89c8"
"""What saved runs recorded for these before the switch existed; they must not move."""


def _load(tmp_path: Path, privacy: str) -> RedactionPolicy:
    path = tmp_path / "guardana.yaml"
    path.write_text(f"privacy:\n{privacy}", encoding="utf-8")
    return load_profile(path).privacy


def test_keep_exchanges_is_read_from_the_privacy_block(tmp_path: Path) -> None:
    assert _load(tmp_path, "  keep_exchanges: true\n").keep_exchanges is True
    assert _load(tmp_path, "  keep_exchanges: false\n").keep_exchanges is False
    assert _load(tmp_path, "  evidence_mode: redacted\n").keep_exchanges is False


@pytest.mark.parametrize("value", ["'yes'", "1", "null", "[true]"])
def test_a_non_boolean_keep_exchanges_is_refused(tmp_path: Path, value: str) -> None:
    with pytest.raises(ProfileError, match=r"privacy\.keep_exchanges must be true or false"):
        _load(tmp_path, f"  keep_exchanges: {value}\n")


def test_keeping_exchanges_under_metadata_only_is_refused_naming_both_keys(
    tmp_path: Path,
) -> None:
    with pytest.raises(ProfileError) as raised:
        _load(tmp_path, "  evidence_mode: metadata_only\n  keep_exchanges: true\n")

    assert "privacy.keep_exchanges" in str(raised.value)
    assert "privacy.evidence_mode" in str(raised.value)


@pytest.mark.parametrize("mode", ["redacted", "full"])
def test_keeping_exchanges_loads_beside_a_mode_that_keeps_text(tmp_path: Path, mode: str) -> None:
    policy = _load(tmp_path, f"  evidence_mode: {mode}\n  keep_exchanges: true\n")

    assert policy.keep_exchanges is True
    assert policy.mode is EvidenceMode(mode)


def test_metadata_only_without_keeping_still_loads(tmp_path: Path) -> None:
    policy = _load(tmp_path, "  evidence_mode: metadata_only\n  keep_exchanges: false\n")

    assert policy.mode is EvidenceMode.METADATA_ONLY


def test_digests_are_unchanged_while_exchanges_are_not_kept() -> None:
    ci = preset("ci")

    assert profile_digest(ci) == _CI_PROFILE_DIGEST
    assert ci.privacy.digest == _REDACTED_POLICY_DIGEST
    assert RedactionPolicy(mode=EvidenceMode.REDACTED).digest == _REDACTED_POLICY_DIGEST


def test_keeping_exchanges_changes_both_digests() -> None:
    ci = preset("ci")
    keeping = replace(ci, privacy=replace(ci.privacy, keep_exchanges=True))

    assert keeping.privacy.digest != _REDACTED_POLICY_DIGEST
    assert profile_digest(keeping) != _CI_PROFILE_DIGEST
