"""The reference pack checks its imports against the same surface the snapshot records.

The pack computes its allowed imports from the installed build, so it needs no generated
file; `scripts/api_surface.py` records the surface from source. Each keeps its own list of
the modules that make up the surface, and this compares the two, so a module added to one
cannot leave the other checking a different surface.
"""

import importlib.util
from functools import cache
from pathlib import Path
from types import ModuleType

import api_surface

_PACK_SURFACE = (
    api_surface._REPO / "examples" / "reference_pack" / "tests" / "test_reference_surface.py"
)
_SECTIONS = ("facade", "extension", "outputs", "kit")
"""The sections of the snapshot that hold importable names, as opposed to constants."""


def _load(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("reference_pack_surface", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@cache
def _pack_names() -> frozenset[str]:
    surface = _load(_PACK_SURFACE).supported_surface()
    return frozenset(f"{module}.{name}" for module, names in surface.items() for name in names)


@cache
def _recorded_names() -> frozenset[str]:
    document = api_surface.build()
    return frozenset(name for section in _SECTIONS for name in document[section])


def _modules(names: frozenset[str]) -> frozenset[str]:
    return frozenset(name.rsplit(".", 1)[0] for name in names)


def test_the_pack_and_the_snapshot_name_the_same_modules() -> None:
    assert _modules(_pack_names()) == _modules(_recorded_names())


def test_the_pack_and_the_snapshot_allow_the_same_names() -> None:
    assert _pack_names() == _recorded_names()


def test_the_comparison_sees_the_surface_it_compares() -> None:
    """Two empty sets are equal too; the comparison is only worth something when both hold it."""
    modules = _modules(_pack_names())

    assert {"guardana.core", "guardana.core.testing", "guardana.core.rule.fixture"} <= modules
    assert "guardana.core.testing.files_target" in _recorded_names()
