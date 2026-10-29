"""A profile digest names what a profile asks of a run, the same wherever the file is read from."""

from collections.abc import Mapping
from dataclasses import fields, replace
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any

import pytest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import load_profile
from guardana.core.profile.digest import profile_digest
from guardana.core.profile.model import FailOn, Policy, Profile
from guardana.core.profile.presets import preset
from guardana.core.severity import Severity

_PROFILE = """\
name: team
rules:
  paths: [checks]
  paths_exclude: ["vendor/*"]
fail_on:
  severity: medium
rule_config:
  guardana.supply_chain.hardcoded_secret:
    since: 2026-09-01
"""


def _write(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "guardana.yaml"
    path.write_text(_PROFILE, encoding="utf-8")
    return path


def test_the_same_file_read_through_two_paths_has_one_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "ci")
    monkeypatch.chdir(tmp_path)
    from_root = profile_digest(load_profile(Path("ci/guardana.yaml")))
    monkeypatch.chdir(tmp_path / "ci")
    from_inside = profile_digest(load_profile(Path("guardana.yaml")))

    assert from_root == from_inside == profile_digest(load_profile(path.resolve()))


def test_a_narrowed_profile_named_like_a_preset_has_another_digest() -> None:
    ci = preset("ci")
    narrowed = replace(ci, policy=replace(ci.policy, exclude=("guardana.prompt.*",)))

    assert profile_digest(narrowed) != profile_digest(ci)
    assert profile_digest(replace(ci, name="renamed")) == profile_digest(ci)


def test_a_changed_failure_bar_changes_the_digest() -> None:
    lenient = Profile(name="p", policy=Policy(fail_on=FailOn(severity=Severity.CRITICAL)))
    strict = Profile(name="p", policy=Policy(fail_on=FailOn(severity=Severity.LOW)))

    assert profile_digest(lenient) != profile_digest(strict)


def test_the_trust_a_flag_can_replace_is_left_out() -> None:
    plain = Profile(name="p", policy=Policy())
    trusting = replace(plain, plugins=PluginTrust(mode=PluginMode.ALL))

    assert profile_digest(trusting) == profile_digest(plain)


def test_a_yaml_date_in_rule_config_is_digested(tmp_path: Path) -> None:
    profile = load_profile(_write(tmp_path))

    assert profile.rule_config["guardana.supply_chain.hardcoded_secret"]["since"] == date(
        2026, 9, 1
    )
    assert profile_digest(profile).startswith("sha256:")


def test_a_value_with_no_encoding_is_refused_rather_than_skipped() -> None:
    profile = Profile(name="p", policy=Policy(), rule_config={"r": {"x": object()}})

    with pytest.raises(TypeError, match="object"):
        profile_digest(profile)


_EXEMPT = {
    "name": "a label",
    "source": "where the file was read from",
    "plugins": "a flag can replace it whole, and the manifest records the trust in force",
    "policy": "covered field by field by the tests above",
    "delivery_required": "not part of the verdict",
}
"""Profile fields this test does not vary, and why."""


def test_every_profile_field_is_covered_or_left_out_on_purpose() -> None:
    """A field added to `Profile` changes the digest of a profile that sets it."""
    base = Profile(name="p", policy=Policy())
    changed = {
        member.name
        for member in fields(Profile)
        if member.name not in _EXEMPT
        and profile_digest(_with_a_different(base, member.name)) == profile_digest(base)
    }

    assert changed == set()


def test_requiring_delivery_is_left_out_of_the_digest() -> None:
    base = Profile(name="p", policy=Policy())

    assert profile_digest(replace(base, delivery_required=True)) == profile_digest(base)


def _with_a_different(profile: Profile, name: str) -> Profile:
    return replace(profile, **{name: _different(name, getattr(profile, name))})


def _different(name: str, value: Any) -> Any:  # noqa: ANN401 — any field type
    if isinstance(value, bool):
        return not value
    if isinstance(value, Enum):
        return next(member for member in type(value) if member != value)
    if isinstance(value, int):
        return value + 1
    if isinstance(value, tuple):
        return _a_dimension() if name == "required_dimensions" else (*value, "x")
    if isinstance(value, Mapping):
        return {"r": {"k": 1}}
    member = fields(value)[0]
    inner = getattr(value, member.name)
    if isinstance(inner, bool | Enum):
        new = _different(member.name, inner)
    else:
        new = 7 if inner != 7 else 8
    return replace(value, **{member.name: new})


def _a_dimension() -> tuple[object, ...]:
    from guardana.core.trace import Dimension  # noqa: PLC0415

    return (next(iter(Dimension)),)
