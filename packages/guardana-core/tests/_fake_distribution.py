"""Installed distributions built in a temporary directory, read by the real `importlib.metadata`.

A fake `EntryPoint` object proves only what the fake does. A `.dist-info` directory on
`sys.path` goes through the same metadata finder a pip-installed pack does, so the
distribution name, version and module a test sees are the ones production reads.
"""

import importlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest

EXPLODING_MODULE = """\
from pathlib import Path

Path(__file__).with_name(__name__ + ".imported").write_text("imported", encoding="utf-8")
raise RuntimeError("this module was imported")
"""
"""A module that leaves a marker beside itself, then fails, the moment it is imported."""

MARKING_MODULE = """\
from pathlib import Path

Path(__file__).with_name(__name__ + ".imported").write_text("imported", encoding="utf-8")


def provide():
    return []
"""
"""A module that leaves a marker beside itself and provides nothing, successfully."""


@dataclass(frozen=True, slots=True)
class FakeModule:
    """A module a fake distribution's entry point names."""

    name: str
    directory: Path
    """Where the module's own file sits: the site root, or the package directory."""

    @property
    def marker(self) -> Path:
        """The file the module writes when, and only when, it is imported."""
        return self.directory / f"{self.name}.imported"


class FakeSite:
    """A directory on `sys.path` that fake distributions and their modules are written to."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self._modules: list[str] = []
        monkeypatch.syspath_prepend(str(root))

    def module(self, body: str, *, package: bool = False) -> FakeModule:
        """Write a uniquely named module (or package), so no test sees another's import."""
        name = f"guardana_fake_{uuid4().hex[:12]}"
        if package:
            (self.root / name).mkdir()
            (self.root / name / "__init__.py").write_text(body, encoding="utf-8")
        else:
            (self.root / f"{name}.py").write_text(body, encoding="utf-8")
        self._modules.append(name)
        importlib.invalidate_caches()
        return FakeModule(name, self.root / name if package else self.root)

    def distribution(
        self, name: str, *entry_points: tuple[str, str, str], version: str = "1.0"
    ) -> None:
        """Install `name` at `version`, advertising `(group, entry point name, module)` triples."""
        # Escaped as a wheel names it: importlib parses the name up to the first `-`.
        info = self.root / f"{re.sub(r'[-_.]+', '_', name)}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
        )
        groups: dict[str, list[str]] = {}
        for group, entry_point, module in entry_points:
            groups.setdefault(group, []).append(f"{entry_point} = {module}:provide")
        (info / "entry_points.txt").write_text(
            "".join(f"[{group}]\n" + "\n".join(lines) + "\n\n" for group, lines in groups.items()),
            encoding="utf-8",
        )
        importlib.invalidate_caches()

    def forget_imports(self) -> None:
        """Drop every module this site wrote from `sys.modules`."""
        for name in self._modules:
            sys.modules.pop(name, None)
