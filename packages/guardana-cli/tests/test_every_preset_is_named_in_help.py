"""Every command that takes `--preset` names every preset that exists in its help."""

import re

import pytest
import typer
from guardana.cli._profile import PRESET_HELP
from guardana.cli.main import app
from guardana.core.profile import PRESET_NAMES
from typer.testing import CliRunner

runner = CliRunner()


def _commands_with_a_preset(
    command: object, path: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], object]]:
    """Walk the command tree, so a command added later is covered without being listed.

    Duck-typed: Typer builds its commands on its own copy of click's classes.
    """
    params = getattr(command, "params", ())
    found = [(path, p) for p in params if getattr(p, "name", None) == "preset"]
    for name, sub in sorted(getattr(command, "commands", {}).items()):
        found += _commands_with_a_preset(sub, (*path, name))
    return found


_FOUND = _commands_with_a_preset(typer.main.get_command(app))


def _unwrapped(text: str) -> str:
    """Help text with colour, box borders and every line break the renderer chose removed."""
    return re.sub(r"[\s│]", "", re.sub(r"\x1b\[[0-9;]*m", "", text))


def test_the_walk_finds_the_commands_that_take_a_preset() -> None:
    commands = {path for path, _ in _FOUND}

    assert {("scan",), ("probe",), ("plan", "probe"), ("doctor",)} <= commands


@pytest.mark.parametrize(("path", "param"), _FOUND, ids=[" ".join(p) for p, _ in _FOUND])
def test_every_preset_option_uses_the_help_built_from_the_presets(
    path: tuple[str, ...], param: object
) -> None:
    assert getattr(param, "help", None) == PRESET_HELP


@pytest.mark.parametrize("path", [p for p, _ in _FOUND], ids=[" ".join(p) for p, _ in _FOUND])
def test_the_preset_help_names_every_preset(path: tuple[str, ...]) -> None:
    # Wide enough that the renderer wraps the help rather than cutting it short.
    result = runner.invoke(app, [*path, "--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0, result.output
    assert _unwrapped("Named policy preset: " + "|".join(PRESET_NAMES)) in _unwrapped(result.output)
