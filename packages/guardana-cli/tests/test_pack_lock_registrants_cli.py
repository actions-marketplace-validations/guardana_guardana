"""`pack lock` pins a pack's evaluators and targets only when its own distribution registers them.

A manifest names an evaluator by id and a target by class name; another distribution
registering that id ships other code under it. Written, the lock is refused; checked,
the id reads `removed`, because the code the lock pinned is no longer what runs.
"""

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from _fake_distribution import MARKING_MODULE, FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import EVALUATOR_GROUP, RULE_GROUP, TARGET_GROUP
from guardana.core.pack import MANIFEST_NAME
from typer.testing import CliRunner

runner = CliRunner()

_DIST = "acme-guardana-judges"
_IMPOSTER = "acme-imposter"
_ADMIT = ["--plugins", "allowlist", "--allow-plugin", _DIST, "--allow-plugin", _IMPOSTER]

_EVALUATOR_MODULE = """\
from guardana.core.evaluator import Evaluator, Verdict


class _Judge(Evaluator):
    id = "acme.judge"

    def evaluate(self, exchange, expectation):
        return Verdict("inconclusive", 0.0, "a fixture grades nothing", self.id)


def provide():
    return [_Judge()]
"""

_TARGET_MODULE = """\
from guardana.core.target import Capability, Target, TargetKind


class AcmeTarget(Target):
    kind = TargetKind.ENDPOINT

    def capabilities(self):
        return {Capability.CHAT}

    @property
    def ref(self):
        return "acme"


def provide():
    return [AcmeTarget]
"""

_KINDS = {
    "evaluator": (EVALUATOR_GROUP, _EVALUATOR_MODULE, "acme.judge", "evaluators"),
    "target": (TARGET_GROUP, _TARGET_MODULE, "AcmeTarget", "targets"),
}


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _install(site: FakeSite, kind: str, registered_by: str) -> None:
    """Install a pack declaring one `kind` under `_DIST`, registered by `registered_by`."""
    group, body, name, key = _KINDS[kind]
    package = site.module(MARKING_MODULE, package=True)
    (package.directory / MANIFEST_NAME).write_text(
        f'schema_version: 2\nname: acme-judges\nextension_api: ">=2,<3"\n'
        f"provides:\n  {key}: [{name}]\n",
        encoding="utf-8",
    )
    module = site.module(body)
    if registered_by == _DIST:
        site.distribution(
            _DIST, (RULE_GROUP, "acme-judges", package.name), (group, kind, module.name)
        )
    else:
        site.distribution(_DIST, (RULE_GROUP, "acme-judges", package.name))
        site.distribution(registered_by, (group, kind, module.name))


def _reinstall(site: FakeSite, kind: str, registered_by: str) -> None:
    for info in site.root.glob("*.dist-info"):
        shutil.rmtree(info)
    _install(site, kind, registered_by)


def _pack_entry(path: Path) -> dict[str, object]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    (entry,) = [p for p in document["packs"] if p["name"] == "acme-judges"]
    return dict(entry)


@pytest.mark.parametrize("kind", sorted(_KINDS))
def test_a_packs_own_evaluator_or_target_is_pinned_and_then_matches(
    site: FakeSite, tmp_path: Path, kind: str
) -> None:
    _install(site, kind, _DIST)
    path = tmp_path / "guardana-lock.yaml"

    written = runner.invoke(app, ["pack", "lock", str(path), *_ADMIT])
    checked = runner.invoke(app, ["pack", "lock", str(path), "--check", *_ADMIT])

    assert written.exit_code == ExitCode.OK, written.output
    _group, _body, name, key = _KINDS[kind]
    assert _pack_entry(path)[key] == [name]
    assert checked.exit_code == ExitCode.OK, checked.output


@pytest.mark.parametrize("kind", sorted(_KINDS))
def test_a_lock_is_not_written_over_an_evaluator_or_target_another_distribution_registers(
    site: FakeSite, tmp_path: Path, kind: str
) -> None:
    _install(site, kind, _IMPOSTER)
    path = tmp_path / "guardana-lock.yaml"

    result = runner.invoke(app, ["pack", "lock", str(path), *_ADMIT])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    _group, _body, name, _key = _KINDS[kind]
    assert "a pack declares an extension another distribution registers" in result.stderr
    assert f"acme-judges declares {kind} {name}, which {_IMPOSTER} registers" in result.stderr
    assert not path.exists()


@pytest.mark.parametrize("kind", sorted(_KINDS))
def test_a_pinned_evaluator_or_target_another_distribution_now_registers_is_removed(
    site: FakeSite, tmp_path: Path, kind: str
) -> None:
    _install(site, kind, _DIST)
    path = tmp_path / "guardana-lock.yaml"
    written = runner.invoke(app, ["pack", "lock", str(path), *_ADMIT])
    assert written.exit_code == ExitCode.OK, written.output
    _reinstall(site, kind, _IMPOSTER)

    checked = runner.invoke(app, ["pack", "lock", str(path), "--check", *_ADMIT])

    assert checked.exit_code == ExitCode.POLICY_FAILED, checked.output
    _group, _body, name, _key = _KINDS[kind]
    assert f"removed: {name} — {kind} was locked and is gone" in checked.stdout


def test_the_built_in_pack_still_pins_the_evaluators_its_distribution_registers(
    tmp_path: Path,
) -> None:
    """`guardana-rules` declares evaluators that `guardana-rules` registers."""
    path = tmp_path / "guardana-lock.yaml"

    written = runner.invoke(app, ["pack", "lock", str(path)])

    assert written.exit_code == ExitCode.OK, written.output
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    (builtin,) = [p for p in document["packs"] if p["name"] == "guardana-rules"]
    assert "canary" in builtin["evaluators"]
