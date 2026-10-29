"""`guardana init --starter` writes a project whose README is true, command by command.

The end-to-end test runs every command the generated README shows, as written, in a
shell, and holds each to the exit code and the output lines the README states. The
edit step is applied from the README's own YAML blocks, so a README that drifts from
the files beside it fails here before a new user finds out.
"""

import json
import os
import pickletools
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_FENCE = re.compile(r"^```(\w*)\n(.*?)^```$", re.MULTILINE | re.DOTALL)
_STATED_EXIT = re.compile(r"#\s*exit\s+(\d+)\s*$")
_PROMPT = "$ "


def normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def _tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def _write_starter(directory: Path) -> dict[str, bytes]:
    result = runner.invoke(app, ["init", "--starter", str(directory)])
    assert result.exit_code == ExitCode.OK, result.output
    return _tree(directory)


def _commands(block: str) -> list[tuple[str, list[str]]]:
    """Split a console block into each command and the output lines shown under it."""
    commands: list[tuple[str, list[str]]] = []
    for line in block.splitlines():
        if line.startswith(_PROMPT):
            commands.append((line.removeprefix(_PROMPT), []))
        elif line.strip():
            assert commands, f"output shown before any command: {line!r}"
            commands[-1][1].append(line)
    return commands


def _shell_env() -> dict[str, str]:
    entry_point = Path(sys.executable).parent / "guardana"
    assert entry_point.is_file(), entry_point
    return {**os.environ, "PATH": f"{entry_point.parent}{os.pathsep}{os.environ['PATH']}"}


def _run(command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — a README line this test generated, in a temporary directory
        ["/bin/sh", "-c", command],
        cwd=cwd,
        env=_shell_env(),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _apply_edit(check: Path, section: str, appended: str) -> None:
    """Make the `expect:` section read as the README says, then append the new sample."""
    text = check.read_text(encoding="utf-8")
    start, end = text.index("expect:\n"), text.index("fixtures:\n")
    check.write_text(text[:start] + section + text[end:] + appended, encoding="utf-8")


def _load(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_every_readme_command_runs_as_written_with_the_exit_code_and_output_it_states(
    tmp_path: Path,
) -> None:
    starter = tmp_path / "starter"
    written = _write_starter(starter)
    blocks = _FENCE.findall(written["README.md"].decode("utf-8"))
    edits = [body for lang, body in blocks if lang == "yaml"]
    assert len(edits) == 2, blocks

    rule_test_outputs: list[str] = []
    tree_before_edit: dict[str, bytes] | None = None
    for lang, body in blocks:
        if lang == "yaml":
            if tree_before_edit is None:
                tree_before_edit = _tree(starter)
                _apply_edit(starter / "checks" / "codename.yaml", *edits)
            continue
        assert lang == "console", f"a README block the test does not know how to run: {lang!r}"
        for command, shown in _commands(body):
            stated = _STATED_EXIT.search(command)
            assert stated or not command.startswith("guardana "), (
                f"the README states no exit code for {command!r}"
            )
            expected = int(stated.group(1)) if stated else 0
            run = _run(command, starter)
            output = normalised(run.stdout + run.stderr)
            assert run.returncode == expected, (command, run.stdout, run.stderr)
            for line in shown:
                assert normalised(line) in output, (command, line, output)
            if command.startswith("guardana rule test"):
                rule_test_outputs.append(output)

    assert tree_before_edit is not None
    assert len(rule_test_outputs) == 2, rule_test_outputs
    assert "3 fixture(s) passed" in rule_test_outputs[0]
    assert "4 fixture(s) passed" in rule_test_outputs[1]

    after = _load(starter / "after.json")
    summary = after["run"]["result_summary"]
    assert {"ref": "model/weights.safetensors", "format": "safetensors"} in [
        {"ref": o["ref"], "format": o["attributes"].get("format")} for o in after["observations"]
    ]
    # A pickle moved where the scan does not look, or renamed to a suffix it does not
    # read, also scans clean; only a model directory observed file by file proves the fix.
    shipped = {
        path.relative_to(starter).as_posix()
        for path in (starter / "model").rglob("*")
        if path.is_file()
    }
    assert "model/weights.safetensors" in shipped
    assert shipped - {o["ref"] for o in after["observations"]} == set()
    assert summary["rules_skipped"] == []
    assert after["waived"] == []
    assert summary["waived"] == 0
    assert after["errors"] == []
    assert after["findings"] == []

    before = _load(starter / "before.json")
    assert [(f["rule_id"], f["severity"], f["target_ref"]) for f in before["findings"]] == [
        ("guardana.supply_chain.pickle_opcode", "CRITICAL", "model/weights.pkl")
    ]

    assert not (starter / "model" / "weights.pkl").exists()
    assert tree_before_edit["model/weights.safetensors"] == written["safe/weights.safetensors"]
    untouched = {rel: data for rel, data in written.items() if not rel.startswith("model/")}
    assert {rel: tree_before_edit[rel] for rel in untouched} == untouched


def test_the_planted_pickle_calls_print_and_nothing_else(tmp_path: Path) -> None:
    written = _write_starter(tmp_path / "starter")

    opcodes = [(op.name, arg) for op, arg, _ in pickletools.genops(written["model/weights.pkl"])]

    assert opcodes == [
        ("PROTO", 2),
        ("GLOBAL", "builtins print"),
        ("BINUNICODE", "Guardana starter: loading this file would have run code."),
        ("TUPLE1", None),
        ("REDUCE", None),
        ("STOP", None),
    ]


def test_the_starter_writes_its_four_files_and_never_a_policy_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    written = _write_starter(Path("a") / "b")

    assert set(written) == {
        "README.md",
        "checks/codename.yaml",
        "model/weights.pkl",
        "safe/weights.safetensors",
    }
    assert not (tmp_path / "guardana.yaml").exists()


def test_the_starter_fills_an_existing_empty_directory(tmp_path: Path) -> None:
    assert "README.md" in _write_starter(tmp_path)


def test_a_path_and_the_starter_together_are_refused_and_write_nothing(tmp_path: Path) -> None:
    policy, starter = tmp_path / "guardana.yaml", tmp_path / "starter"

    result = runner.invoke(app, ["init", str(policy), "--starter", str(starter)])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "not both" in normalised(result.output)
    assert not policy.exists()
    assert not starter.exists()


def test_the_starter_refuses_a_directory_that_is_not_empty(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("mine\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--starter", str(tmp_path)])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "is not empty" in normalised(result.output)
    assert _tree(tmp_path) == {"notes.txt": b"mine\n"}


def test_the_starter_refuses_a_path_that_is_a_file(tmp_path: Path) -> None:
    occupied = tmp_path / "starter"
    occupied.write_text("mine\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--starter", str(occupied)])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert occupied.read_text(encoding="utf-8") == "mine\n"


def test_plain_init_still_writes_guardana_yaml_in_the_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init"])

    assert result.exit_code == ExitCode.OK, result.output
    assert (tmp_path / "guardana.yaml").read_text(encoding="utf-8").startswith("name: default\n")
