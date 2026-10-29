"""The clean-install gate's children run the way a user's interpreter does.

Its verdicts are scripts run by the installed interpreter. An interpreter flag
inherited from the maintainer's shell can change what those scripts check:
`PYTHONOPTIMIZE` strips every `assert`, and the success marker prints anyway.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import clean_install_check


def test_interpreter_flags_from_the_calling_shell_do_not_reach_the_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in ("PYTHONOPTIMIZE", "PYTHONINSPECT", "PYTHONSTARTUP", "PYTHONHOME"):
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("HOME", str(tmp_path))

    environment = clean_install_check._clean_environment(tmp_path / ".venv")

    assert not [name for name in environment if name.startswith("PYTHON")]
    assert environment["HOME"] == str(tmp_path)


def test_a_check_script_fails_under_an_optimising_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The seam: a child built from that environment still refuses a false verdict."""
    monkeypatch.setenv("PYTHONOPTIMIZE", "2")
    environment = clean_install_check._clean_environment(tmp_path / ".venv")

    done = subprocess.run(
        [sys.executable, "-c", "assert False, 'refused'\nprint('writer ready')"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode != 0
    assert "writer ready" not in done.stdout


def _scripts(tmp_path: Path) -> list[tuple[str, str]]:
    venv, clean, pack, marker = (tmp_path / n for n in ("venv", "clean", "pack", "marker"))
    checks = [
        *clean_install_check._checks(venv, clean, tmp_path / "trace.jsonl"),
        *clean_install_check._starter_checks(venv, tmp_path / "starter"),
        *clean_install_check._trust_checks(venv, clean, pack, marker),
    ]
    return [
        (check.name, check.argv[check.argv.index("-c") + 1])
        for check in checks
        if "-c" in check.argv
    ]


def test_every_check_script_states_its_verdicts_without_assert(tmp_path: Path) -> None:
    """An `assert` vanishes under `-O`; an explicit check raises in every interpreter."""
    scripts = _scripts(tmp_path)
    asserting = [
        name
        for name, source in scripts
        if any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))
    ]

    assert len(scripts) >= 8
    assert not asserting, f"checks whose verdict is an assert: {asserting}"
