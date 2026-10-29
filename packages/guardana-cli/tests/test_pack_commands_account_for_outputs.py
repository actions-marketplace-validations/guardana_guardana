"""`pack validate` and `pack lock` account for every installed output before reading a manifest.

An output trust refused, one whose provider failed, and a name several distributions
install all leave "what this build provides" unproven, so both commands exit `2` before
`discover_packs` imports any module to read its manifest. An admitted output a pack
declares is validated and pinned like an evaluator, by name.
"""

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from _fake_distribution import MARKING_MODULE, FakeModule, FakeSite
from _output_modules import RAISING_PROVIDER, RECORDING_RENDERER, RECORDING_REPORTER, body
from guardana.cli import pack
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import RENDERER_GROUP, REPORTER_GROUP, RULE_GROUP
from guardana.core.pack import MANIFEST_NAME, PackDiscovery
from guardana.core.plugins import PluginTrust
from typer.testing import CliRunner

runner = CliRunner()

_DIST = "acme-guardana-outputs"
_ADMIT = ["--plugins", "allowlist", "--allow-plugin", _DIST]
_MANIFEST = """\
schema_version: 3
name: acme-outputs
extension_api: ">=2,<3"
output_api: ">=1,<2"
provides:
  renderers: [acme-table]
"""


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


@pytest.fixture
def no_manifest_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if a pack command reaches the step that imports modules for manifests."""

    def refused(trust: PluginTrust) -> PackDiscovery:
        raise AssertionError(f"discover_packs ran under {trust.describe()}")

    monkeypatch.setattr(pack, "discover_packs", refused)


def _commands(tmp_path: Path) -> list[list[str]]:
    return [["pack", "validate"], ["pack", "lock", str(tmp_path / "guardana-lock.yaml")]]


def _install(
    site: FakeSite, template: str, *, distribution: str = _DIST, group: str = RENDERER_GROUP
) -> FakeModule:
    name = "acme-table" if group == RENDERER_GROUP else "acme-webhook"
    module = site.module(body(template, name))
    site.distribution(distribution, (group, name, module.name))
    return module


@pytest.mark.parametrize("command", [0, 1], ids=["validate", "lock"])
def test_an_output_trust_refuses_stops_both_commands_before_any_manifest_is_read(
    site: FakeSite, tmp_path: Path, no_manifest_read: None, command: int
) -> None:
    module = _install(site, RECORDING_RENDERER)

    result = runner.invoke(app, _commands(tmp_path)[command])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert (
        f"the format acme-table comes from {_DIST} 1.0, which plugin trust builtins does not admit"
    ) in result.stderr
    assert f"--allow-plugin {_DIST}" in result.stderr
    assert "1 extension(s) were refused by plugin trust" in result.stderr
    assert not module.marker.exists(), "a refused output was imported"
    assert not (tmp_path / "guardana-lock.yaml").exists()


@pytest.mark.parametrize("command", [0, 1], ids=["validate", "lock"])
def test_an_output_whose_provider_fails_stops_both_commands(
    site: FakeSite, tmp_path: Path, no_manifest_read: None, command: int
) -> None:
    _install(site, RAISING_PROVIDER, group=REPORTER_GROUP)

    result = runner.invoke(app, [*_commands(tmp_path)[command], *_ADMIT])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert f"the reporter acme-webhook from {_DIST} 1.0 could not be loaded" in result.stderr
    assert "the provider is broken" in result.stderr
    assert not (tmp_path / "guardana-lock.yaml").exists()


@pytest.mark.parametrize("command", [0, 1], ids=["validate", "lock"])
def test_an_output_name_two_distributions_install_stops_both_commands(
    site: FakeSite, tmp_path: Path, no_manifest_read: None, command: int
) -> None:
    first = _install(site, RECORDING_RENDERER, distribution="acme-a")
    second = _install(site, RECORDING_RENDERER, distribution="acme-b")

    result = runner.invoke(app, [*_commands(tmp_path)[command], "--plugins", "all"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert (
        "the format acme-table is installed by 2 distributions (acme-a 1.0, acme-b 1.0); "
        "selecting it is refused"
    ) in result.stderr
    assert not first.marker.exists()
    assert not second.marker.exists()
    assert not (tmp_path / "guardana-lock.yaml").exists()


def _output_pack(site: FakeSite, manifest: str = _MANIFEST) -> FakeModule:
    """Install a package whose own module provides `acme-table` and ships `manifest`."""
    module = site.module(body(RECORDING_RENDERER, "acme-table"), package=True)
    (module.directory / MANIFEST_NAME).write_text(manifest, encoding="utf-8")
    site.distribution(_DIST, (RENDERER_GROUP, "acme-table", module.name))
    return module


def test_a_pack_declaring_the_output_it_installs_validates(site: FakeSite) -> None:
    _output_pack(site)

    result = runner.invoke(app, ["pack", "validate", *_ADMIT])

    assert result.exit_code == ExitCode.OK, result.output
    assert "✓ acme-outputs (extension_api >=2,<3, output_api >=1,<2) — 1 declared" in (
        result.stdout
    )


def test_a_pack_declaring_an_output_it_does_not_install_is_reported(site: FakeSite) -> None:
    _output_pack(site, _MANIFEST + "  reporters: [acme-webhook]\n")

    result = runner.invoke(app, ["pack", "validate", *_ADMIT])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert "declares reporter acme-webhook and does not register it" in result.stdout


def test_a_lock_pins_the_output_by_name_as_schema_3_and_then_matches(
    site: FakeSite, tmp_path: Path
) -> None:
    _output_pack(site)
    path = tmp_path / "guardana-lock.yaml"

    written = runner.invoke(app, ["pack", "lock", str(path), *_ADMIT])
    checked = runner.invoke(app, ["pack", "lock", str(path), "--check", *_ADMIT])

    assert written.exit_code == ExitCode.OK, written.output
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 3
    (entry,) = [p for p in document["packs"] if p["name"] == "acme-outputs"]
    assert entry["renderers"] == ["acme-table"]
    assert entry["reporters"] == []
    assert checked.exit_code == ExitCode.OK, checked.output


_IMPOSTER = "acme-imposter"


def _pack_with_a_separate_renderer(site: FakeSite, renderer_from: str) -> None:
    """Install the pack's manifest under `_DIST` and `acme-table` from `renderer_from`."""
    package = site.module(MARKING_MODULE, package=True)
    (package.directory / MANIFEST_NAME).write_text(_MANIFEST, encoding="utf-8")
    renderer = site.module(body(RECORDING_RENDERER, "acme-table"))
    if renderer_from == _DIST:
        site.distribution(
            _DIST,
            (RULE_GROUP, "acme-outputs", package.name),
            (RENDERER_GROUP, "acme-table", renderer.name),
        )
    else:
        site.distribution(_DIST, (RULE_GROUP, "acme-outputs", package.name))
        site.distribution(renderer_from, (RENDERER_GROUP, "acme-table", renderer.name))


def test_a_pinned_output_another_distribution_now_registers_is_drift(
    site: FakeSite, tmp_path: Path
) -> None:
    path = tmp_path / "guardana-lock.yaml"
    admit = [*_ADMIT, "--allow-plugin", _IMPOSTER]
    _pack_with_a_separate_renderer(site, _DIST)
    written = runner.invoke(app, ["pack", "lock", str(path), *admit])
    assert written.exit_code == ExitCode.OK, written.output
    (entry,) = [
        p
        for p in yaml.safe_load(path.read_text(encoding="utf-8"))["packs"]
        if p["name"] == "acme-outputs"
    ]
    assert entry["renderers"] == ["acme-table"]
    for info in site.root.glob("*.dist-info"):
        shutil.rmtree(info)
    _pack_with_a_separate_renderer(site, _IMPOSTER)

    checked = runner.invoke(app, ["pack", "lock", str(path), "--check", *admit])
    rewritten = runner.invoke(app, ["pack", "lock", str(tmp_path / "again.yaml"), *admit])

    assert checked.exit_code == ExitCode.POLICY_FAILED, checked.output
    assert "removed: acme-table — renderer was locked and is gone" in checked.stdout
    assert rewritten.exit_code == ExitCode.INDETERMINATE, rewritten.output
    assert f"renderer acme-table, which {_IMPOSTER} registers" in rewritten.stderr
    assert not (tmp_path / "again.yaml").exists()


def test_a_schema_2_lock_checked_with_an_output_installed_says_to_rewrite_it(
    site: FakeSite, tmp_path: Path
) -> None:
    path = tmp_path / "guardana-lock.yaml"
    written = runner.invoke(app, ["pack", "lock", str(path)])
    assert written.exit_code == ExitCode.OK, written.output
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["schema_version"] == 2
    _output_pack(site)

    result = runner.invoke(app, ["pack", "lock", str(path), "--check", *_ADMIT])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    assert "pack_unlocked: acme-outputs" in result.stdout
    assert "lock schema 2, which pins no outputs" in result.stderr
    assert "secret scanners" not in result.stderr


def test_an_output_without_a_manifest_is_named_by_validate(site: FakeSite) -> None:
    module = _install(site, RECORDING_REPORTER, group=REPORTER_GROUP)

    result = runner.invoke(app, ["pack", "validate", *_ADMIT])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert module.name in result.stderr
    assert "renderers or reporters) and declare no manifest" in result.stderr
