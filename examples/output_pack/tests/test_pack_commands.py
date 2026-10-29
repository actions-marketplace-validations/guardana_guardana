"""This package's manifest declares both outputs, and `pack validate` and `pack lock` see them.

Run where the package is really installed, so its entry points and its manifest are
read from the wheel, as a team's build would read them.
"""

import re
from importlib import resources
from pathlib import Path

import acme_outputs
import yaml
from acme_doubles import ADMIT
from guardana.cli.main import app
from guardana.core.output import RendererSpec, ReporterSpec
from guardana.core.pack import load_manifest
from typer.testing import CliRunner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

runner = CliRunner()


def test_the_manifest_ships_inside_the_wheel_and_declares_both_outputs() -> None:
    manifest_file = resources.files("acme_outputs").joinpath("guardana-pack.yaml")
    with resources.as_file(manifest_file) as path:
        manifest = load_manifest(path)

    assert manifest.schema_version == 3
    assert manifest.name == "acme-guardana-outputs"
    assert set(manifest.provides) >= {"renderer:acme-table", "reporter:acme-webhook"}


def test_each_provider_returns_the_spec_its_entry_point_names() -> None:
    table = acme_outputs.provide_table()
    hook = acme_outputs.provide_webhook()

    assert isinstance(table, RendererSpec)
    assert table.name == "acme-table"
    assert isinstance(hook, ReporterSpec)
    assert hook.name == "acme-webhook"


def test_pack_validate_accepts_both_outputs() -> None:
    result = runner.invoke(app, ["pack", "validate", *ADMIT])

    assert result.exit_code == 0, result.output
    text = " ".join(_ANSI.sub("", result.stdout).split())
    assert "acme-guardana-outputs" in text


def test_pack_lock_pins_both_outputs_in_lock_schema_3(tmp_path: Path) -> None:
    lock = tmp_path / "guardana-lock.yaml"

    written = runner.invoke(app, ["pack", "lock", str(lock), *ADMIT])
    checked = runner.invoke(app, ["pack", "lock", str(lock), "--check", *ADMIT])

    assert written.exit_code == 0, written.output
    assert checked.exit_code == 0, checked.output
    document = yaml.safe_load(lock.read_text(encoding="utf-8"))
    assert document["schema_version"] == 3
    (pack,) = [p for p in document["packs"] if p["name"] == "acme-guardana-outputs"]
    assert pack["renderers"] == ["acme-table"]
    assert pack["reporters"] == ["acme-webhook"]
