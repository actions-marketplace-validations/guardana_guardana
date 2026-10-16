"""A new static finding is a regression whether or not its file already held one."""

from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_SHELL = "import os\n\nos.system(cmd)\n"
_EVAL = "\n\ndef run(untrusted_model_output):\n    return eval(untrusted_model_output)\n"


def _saved(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    tree = tmp_path / name
    tree.mkdir()
    for relative, text in files.items():
        (tree / relative).write_text(text, encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        "rules:\n  include: ['guardana.supply_chain.code_execution']\n", encoding="utf-8"
    )
    saved = tmp_path / f"{name}.json"
    result = runner.invoke(
        app,
        [
            *("scan", str(tree), "--profile", str(profile)),
            *("--format", "json", "--output", str(saved)),
        ],
    )
    if result.exit_code != ExitCode.POLICY_FAILED:
        raise RuntimeError(f"precondition: the scan should report the sink: {result.output}")
    return saved


def _diff(first: Path, second: Path) -> int:
    return runner.invoke(app, ["diff", str(first), str(second)]).exit_code


def test_control_a_new_sink_in_a_new_file_is_a_regression(tmp_path: Path) -> None:
    before = _saved(tmp_path, "before", {"run.py": _SHELL})
    after = _saved(tmp_path, "after", {"run.py": _SHELL, "other.py": _EVAL})

    assert _diff(before, after) == ExitCode.POLICY_FAILED


def test_a_new_sink_in_an_already_flagged_file_is_a_regression(tmp_path: Path) -> None:
    before = _saved(tmp_path, "before", {"run.py": _SHELL})
    after = _saved(tmp_path, "after", {"run.py": _SHELL + _EVAL})

    assert _diff(before, after) == ExitCode.POLICY_FAILED
