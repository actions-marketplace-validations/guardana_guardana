"""A profile can require that every delivery is acknowledged, and a typo there fails loudly.

The setting decides the exit after the verdict, so it never moves the profile digest a
run, a recipe lock or a manifest records.
"""

from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.profile import PRESET_NAMES, ProfileError, default_profile, load_profile, preset
from guardana.core.profile.digest import profile_digest


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_profile_can_require_delivery(tmp_path: Path) -> None:
    assert load_profile(_write(tmp_path, "delivery:\n  required: true\n")).delivery_required


@pytest.mark.parametrize(
    "body", ["name: t\n", "delivery:\n  required: false\n", "delivery:\n", "delivery: {}\n"]
)
def test_delivery_is_not_required_unless_the_profile_says_so(tmp_path: Path, body: str) -> None:
    assert not load_profile(_write(tmp_path, body)).delivery_required


def test_presets_and_the_default_profile_require_no_delivery() -> None:
    assert not default_profile().delivery_required
    assert not any(preset(name).delivery_required for name in PRESET_NAMES)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("delivery:\n  required: yes please\n", "delivery.required must be true or false"),
        ("delivery:\n  required: 1\n", "delivery.required must be true or false"),
        ("delivery:\n  required: true\n  retries: 3\n", "unknown delivery key(s): retries"),
        ("delivery: true\n", "'delivery' must be a mapping"),
    ],
)
def test_a_delivery_block_the_loader_cannot_honour_is_refused(
    tmp_path: Path, body: str, message: str
) -> None:
    path = _write(tmp_path, body)

    with pytest.raises(ProfileError) as refused:
        load_profile(path)

    assert str(refused.value) == f"invalid profile {path}: {message}"


def test_requiring_delivery_leaves_the_profile_digest_unchanged(tmp_path: Path) -> None:
    plain = load_profile(_write(tmp_path, "fail_on:\n  severity: medium\n"))
    required = load_profile(
        _write(tmp_path, "fail_on:\n  severity: medium\ndelivery:\n  required: true\n")
    )

    assert required.delivery_required
    assert profile_digest(required) == profile_digest(plain)
    assert profile_digest(replace(plain, delivery_required=True)) == profile_digest(plain)
