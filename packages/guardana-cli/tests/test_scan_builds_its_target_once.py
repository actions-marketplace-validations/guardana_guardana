"""`guardana scan PATH` builds its file target once, so the ignore file is read once."""

from pathlib import Path

import guardana.core.target.artifact as artifact_module
import pytest
from guardana.cli.main import app
from typer.testing import CliRunner


def test_a_path_scan_reads_its_ignore_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / ".guardanaignore").write_text("build\n", encoding="utf-8")
    reads: list[Path] = []
    read = artifact_module._read_ignore_file

    def counted(root: Path) -> tuple[str, ...]:
        reads.append(root)
        return read(root)

    monkeypatch.setattr(artifact_module, "_read_ignore_file", counted)

    result = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert len(reads) == 1
