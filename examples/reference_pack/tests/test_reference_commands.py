"""`pack validate`, `pack lock --check` and a `scan` through the pack's target and outputs.

Run where the pack is really installed, so its entry points, its manifest and its YAML
rule are read from the wheel, as a team's build would read them.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

PACK = Path(__file__).resolve().parents[1]
LOCK = PACK / "guardana-lock.yaml"
NAME = "guardana-reference-pack"
ADMIT = ("--plugins", "allowlist", "--allow-plugin", NAME)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def guardana(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the `guardana` installed beside this interpreter, with no `GUARDANA_*` variable."""
    executable = shutil.which("guardana", path=str(Path(sys.executable).parent))
    if executable is None:
        pytest.fail("no guardana command is installed beside this interpreter")
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GUARDANA_")}
    environment["NO_COLOR"] = "1"
    return subprocess.run(  # noqa: S603 — a fixed command with literal arguments
        [executable, *args], capture_output=True, text=True, check=False, env=environment
    )


def _said(result: subprocess.CompletedProcess[str]) -> str:
    return " ".join(_ANSI.sub("", result.stdout + result.stderr).split())


def _load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return document


def _own(lock: dict[str, Any]) -> dict[str, Any]:
    (pack,) = [p for p in lock["packs"] if p["name"] == NAME]
    entry: dict[str, Any] = pack
    return entry


@pytest.fixture
def installed(tmp_path: Path) -> dict[str, Any]:
    """The lock `pack lock` writes for this build."""
    path = tmp_path / "installed-lock.yaml"
    result = guardana("pack", "lock", str(path), *ADMIT)
    assert result.returncode == 0, _said(result)
    return _load(path)


def _merged(committed: dict[str, Any], installed: dict[str, Any]) -> dict[str, Any]:
    """The committed lock's own entry beside every other pack as this build installs it."""
    others = [p for p in installed["packs"] if p["name"] != NAME]
    return {**installed, "packs": [*others, _own(committed)]}


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_pack_validate_accepts_the_pack() -> None:
    result = guardana("pack", "validate", *ADMIT)

    assert result.returncode == 0, _said(result)
    assert NAME in _said(result)


def test_the_committed_lock_pins_what_the_pack_registers(installed: dict[str, Any]) -> None:
    committed = _load(LOCK)

    assert committed["schema_version"] == 3
    assert committed["extension_api"] == installed["extension_api"]
    assert [p["name"] for p in committed["packs"]] == [NAME]
    assert _own(committed) == _own(installed)


def test_pack_lock_check_accepts_the_committed_entry(
    installed: dict[str, Any], tmp_path: Path
) -> None:
    lock = _write(tmp_path / "guardana-lock.yaml", _merged(_load(LOCK), installed))

    result = guardana("pack", "lock", str(lock), "--check", *ADMIT)

    assert result.returncode == 0, _said(result)


def test_pack_lock_check_refuses_a_changed_rule_digest(
    installed: dict[str, Any], tmp_path: Path
) -> None:
    tampered = _merged(_load(LOCK), installed)
    rules = _own(tampered)["rules"]
    rules["reference.supply_chain.unpinned_requirement"] = {"digest": "0000000000000000"}
    lock = _write(tmp_path / "guardana-lock.yaml", tampered)

    result = guardana("pack", "lock", str(lock), "--check", *ADMIT)

    assert result.returncode == 1, _said(result)
    assert "reference.supply_chain.unpinned_requirement" in _said(result)


def test_a_scan_writes_the_summary_and_delivers_it(tmp_path: Path) -> None:
    source = tmp_path / "service"
    source.mkdir()
    (source / "requirements.txt").write_text("requests>=2.31\nidna==3.7\n", encoding="utf-8")
    summaries = tmp_path / "summaries"
    summaries.mkdir()

    result = guardana(
        "scan",
        "--target",
        f"reference-requirements://{source}",
        *ADMIT,
        "--format",
        "reference-summary",
        "--reporter",
        f"reference-file://{summaries}",
    )

    assert result.returncode == 0, _said(result)
    heading = re.match(r"# Guardana run (\S+)\n", result.stdout)
    assert heading is not None, result.stdout
    run_id = heading.group(1).replace("\\", "")
    assert "| Gate | **pass** |" in result.stdout
    assert "reference.supply\\_chain.unpinned\\_requirement" in result.stdout
    assert f"delivery: delivered — reference-file to {summaries}" in _said(result)
    written = (summaries / f"guardana-{run_id}.md").read_text(encoding="utf-8")
    assert written.startswith(heading.group(0))
    assert "'requests\\>=2.31' is not pinned" in written
