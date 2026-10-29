"""`rules.paths` names rule files beside the profile, wherever the command was started.

`contracts:` and `calibrations:` already read that way; a rule directory read against
the working directory made one committed profile load its rules from a repository root
and load nothing from a hook or a CI step running elsewhere.
"""

from pathlib import Path

import pytest
from guardana.core.profile import load_profile


def _profile(directory: Path, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_relative_rule_path_is_read_beside_the_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    profile = _profile(config, "name: t\nrules:\n  paths: ['my-rules']\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    prof = load_profile(profile)

    assert prof.rule_paths == (str(config / "my-rules"),)


def test_an_absolute_rule_path_is_left_alone(tmp_path: Path) -> None:
    rules = tmp_path / "shared" / "rules"
    profile = _profile(tmp_path / "config", f"name: t\nrules:\n  paths: ['{rules}']\n")

    assert load_profile(profile).rule_paths == (str(rules),)


def test_paths_exclude_still_names_scanned_files_not_files_beside_the_profile(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path / "config", "name: t\nrules:\n  paths_exclude: ['vendor/*']\n")

    assert load_profile(profile).path_excludes == ("vendor/*",)


def test_a_loaded_profile_remembers_the_file_it_came_from(tmp_path: Path) -> None:
    profile = _profile(tmp_path / "config", "name: t\n")

    assert load_profile(profile).source == profile
