"""A pack the lock never pinned is never hidden behind another pack's name."""

from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from guardana.cli import pack as pack_command
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.pack import PackDiscovery, discover_packs
from guardana.core.pack.lock import Installed
from guardana.core.pack.model import ApiRange, PackManifest
from guardana.core.plugins import PluginTrust
from guardana.core.registry import Registry
from typer.testing import CliRunner

runner = CliRunner()

_EXTRA_RULE = "acme.fork.extra"


def _locked(tmp_path: Path) -> Path:
    path = tmp_path / "guardana-lock.yaml"
    result = runner.invoke(app, ["pack", "lock", str(path)])
    if result.exit_code != ExitCode.OK:
        raise RuntimeError(f"precondition: the build should lock cleanly: {result.output}")
    names = [pack["name"] for pack in yaml.safe_load(path.read_text("utf-8"))["packs"]]
    if names != ["guardana-rules"]:
        raise RuntimeError(f"precondition: the build should lock only the built-ins: {names}")
    return path


def _install_fork(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Install, ahead of the built-ins, a pack from another distribution with one more rule."""
    fork = PackManifest(name, ApiRange(1, 3), "fork", rules=(_EXTRA_RULE,))

    def discovered(trust: PluginTrust) -> PackDiscovery:
        found = discover_packs(trust)
        return replace(found, packs=(("acme-fork", "9.9.9", fork), *found.packs))

    real_installed = pack_command._installed

    def installed(registry: Registry, outputs: object) -> Installed:
        present = real_installed(registry, outputs)  # type: ignore[arg-type]
        return replace(present, rules={**present.rules, _EXTRA_RULE: "f" * 16})

    monkeypatch.setattr(pack_command, "discover_packs", discovered)
    monkeypatch.setattr(pack_command, "_installed", installed)


def _check(path: Path) -> int:
    return runner.invoke(app, ["pack", "lock", str(path), "--check"]).exit_code


def test_control_an_unpinned_pack_under_its_own_name_fails_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _locked(tmp_path)
    _install_fork(monkeypatch, "acme-fork")

    assert _check(path) == ExitCode.POLICY_FAILED


def test_an_unpinned_pack_sharing_a_locked_name_fails_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _locked(tmp_path)
    _install_fork(monkeypatch, "guardana-rules")

    assert _check(path) != ExitCode.OK
