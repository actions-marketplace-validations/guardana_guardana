"""`budgets.max_requests_per_minute`: a positive whole number, a bound, digested only when set."""

from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.budget import Budgets
from guardana.core.profile import ProfileError, load_profile
from guardana.core.profile.digest import profile_digest
from guardana.core.profile.presets import preset

_CI_PROFILE_DIGEST = "sha256:2219ab15facdd105c1e8fd70d1b970feca4e474d4f9973ef377aae8e2aba3e0c"
"""What saved runs and recipe locks recorded for the `ci` preset before the rate existed."""


def _budgets(tmp_path: Path, block: str) -> Budgets:
    path = tmp_path / "guardana.yaml"
    path.write_text(f"name: ci\nbudgets:\n{block}", encoding="utf-8")
    return load_profile(path).budgets


def test_the_rate_is_read_from_the_budgets_block(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, "  max_requests_per_minute: 30\n")

    assert budgets.max_requests_per_minute == 30
    assert not budgets.is_unbounded


def test_a_profile_without_a_rate_sets_none(tmp_path: Path) -> None:
    budgets = _budgets(tmp_path, "  max_requests: 5\n")

    assert budgets.max_requests_per_minute is None


@pytest.mark.parametrize("value", ["0", "-3", "1.5", "'30'", "true"])
def test_a_rate_that_is_not_a_positive_whole_number_is_refused(tmp_path: Path, value: str) -> None:
    with pytest.raises(ProfileError, match=r"budgets\.max_requests_per_minute"):
        _budgets(tmp_path, f"  max_requests_per_minute: {value}\n")


def test_a_rate_alone_is_a_bound() -> None:
    assert Budgets().is_unbounded
    assert not Budgets(max_requests_per_minute=60).is_unbounded


def test_the_digest_is_unchanged_while_no_rate_is_set() -> None:
    assert profile_digest(preset("ci")) == _CI_PROFILE_DIGEST


def test_setting_a_rate_changes_the_digest() -> None:
    ci = preset("ci")
    paced = replace(ci, budgets=replace(ci.budgets, max_requests_per_minute=60))

    assert profile_digest(paced) != _CI_PROFILE_DIGEST
