"""Reading a pack's manifest imports its module, so trust decides before the read.

`importlib.resources.files(module)` runs the module's `__init__`. A pack command that
read manifests for every advertised module would execute exactly the code plugin
trust had just refused, so the pack functions take the same trust and walk the same
enumeration as discovery, and hand back what they refused beside what they read.
"""

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import MARKING_MODULE, FakeModule, FakeSite
from guardana.core.entrypoints import RULE_GROUP
from guardana.core.pack import (
    MANIFEST_NAME,
    PackError,
    discover_packs,
    installed_manifests,
    installed_packs,
    unmanifested_packages,
)
from guardana.core.plugins import PluginMode, PluginTrust

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)
_ALL = PluginTrust(mode=PluginMode.ALL)
_MANIFEST = Path(__file__).parent / "pack_manifests" / "acme-guardana-pack-0.19.1.yaml"


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _pack(site: FakeSite, *, manifest: bool, body: str = MARKING_MODULE) -> FakeModule:
    module = site.module(body, package=True)
    if manifest:
        shutil.copyfile(_MANIFEST, site.root / module.name / MANIFEST_NAME)
    site.distribution("acme-pack", (RULE_GROUP, "acme", module.name))
    return module


def test_a_refused_pack_is_reported_and_its_module_never_imported(site: FakeSite) -> None:
    module = _pack(site, manifest=True)

    found = discover_packs(_BUILTINS)

    assert [(ep.distribution, ep.module) for ep in found.refused] == [("acme-pack", module.name)]
    assert module.name not in found.unmanifested
    assert all(manifest.name != "acme-guardana-rules" for manifest in found.manifests)
    assert not module.marker.exists()


def test_the_list_functions_under_a_trust_never_import_what_it_refuses(site: FakeSite) -> None:
    module = _pack(site, manifest=False)

    assert module.name not in unmanifested_packages(_BUILTINS)
    assert all(m.name != "acme-guardana-rules" for m in installed_manifests(_BUILTINS))
    assert all(distribution != "acme-pack" for distribution, _, _ in installed_packs(_BUILTINS))
    assert not module.marker.exists()


def test_under_all_every_pack_is_read(site: FakeSite) -> None:
    with_manifest = _pack(site, manifest=True)

    found = discover_packs(_ALL)

    assert not found.refused
    assert ("acme-pack", "1.0") in {
        (d, v) for d, v, m in found.packs if m.name == "acme-guardana-rules"
    }
    assert [m.name for m in installed_manifests(_ALL)].count("acme-guardana-rules") == 1
    assert with_manifest.marker.exists()


def test_under_all_a_pack_with_no_manifest_is_named(site: FakeSite) -> None:
    module = _pack(site, manifest=False)

    assert module.name in unmanifested_packages(_ALL)
    assert module.marker.exists()


def test_a_pack_that_fails_to_import_is_an_unreadable_manifest_not_a_missing_one(
    site: FakeSite,
) -> None:
    module = _pack(site, manifest=True, body="from guardana.core import not_a_real_name\n")

    with pytest.raises(PackError, match=module.name):
        discover_packs(_ALL)


def test_a_pack_whose_dependency_is_missing_is_an_unreadable_manifest(site: FakeSite) -> None:
    module = _pack(site, manifest=True, body="import guardana_fake_dependency_nobody_installed\n")

    with pytest.raises(PackError, match="ModuleNotFoundError") as raised:
        discover_packs(_ALL)
    assert module.name in str(raised.value)


def test_a_pack_that_fails_to_import_is_not_imported_when_refused(site: FakeSite) -> None:
    _pack(site, manifest=True, body="from guardana.core import not_a_real_name\n")

    assert discover_packs(_BUILTINS).refused


def test_an_entry_point_naming_a_module_that_is_not_there_has_no_manifest(
    site: FakeSite,
) -> None:
    site.distribution("acme-stale", (RULE_GROUP, "stale", "guardana_fake_gone_module"))

    assert "guardana_fake_gone_module" in unmanifested_packages(_ALL)
