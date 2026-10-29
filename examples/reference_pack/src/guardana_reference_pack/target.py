"""`reference-requirements://<dir>`: the pip requirement files under a directory, as an artifact.

The target lists `requirements*.txt` and `requirements*.in` files and nothing else, so it
holds no Python: `python_source` answers None for every path and nothing is ever left
unread by it. It declares `READ_FILES` and implements `FileReader`, both halves, which
`guardana.testing.assert_target_conforms` checks.
"""

from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Self

from guardana.core import Capability, LocatorError, Target, TargetKind

from guardana_reference_pack.unpinned import is_requirements_file

SCHEME = "reference-requirements"


class ReferenceRequirementsTarget(Target):
    """The requirement files under one directory, walked in a stable order."""

    kind = TargetKind.ARTIFACT
    scheme = SCHEME

    def __init__(self, root: Path | str) -> None:
        """Point the target at a directory."""
        self._root = Path(root)

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        """Build the target selected as `reference-requirements://<dir>`."""
        if options:
            raise LocatorError(
                f"{SCHEME} accepts no target options; unknown: {', '.join(sorted(options))}"
            )
        root = Path(locator)
        if not root.is_dir():
            raise LocatorError(f"{root} is not a directory")
        return cls(root)

    def capabilities(self) -> set[Capability]:
        """Files, and only files."""
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        """How this target appears in a finding and in a run manifest."""
        return f"{SCHEME}://{self._root}"

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        """Yield each requirement file, sorted, optionally by suffix in any case."""
        if not self._root.is_dir():
            return
        wanted = None if suffixes is None else {suffix.lower() for suffix in suffixes}
        for path in sorted(p for p in self._root.rglob("*") if p.is_file()):
            if is_requirements_file(path) and (wanted is None or path.suffix.lower() in wanted):
                yield path

    def python_source(self, path: Path) -> None:
        """Return None: the target lists no Python file."""
        return

    def unread_sources(self) -> tuple[()]:
        """Return nothing: the target reads no file itself, the rules do."""
        return ()
