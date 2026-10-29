import ast
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import OWASP_LLM03_2025, OWASP_LLM04_2026
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._declared_deps import declared_import_names, normalize
from guardana.rules.supply_chain._known_packages import (
    KNOWN_DISTRIBUTIONS,
    installed_import_names,
)
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._unread_python import unread_python

_STDLIB = frozenset(sys.stdlib_module_names)
# Matched exactly, as Python's own finder does: `helperlib.PY` is not importable as
# `helperlib`. A stub names a module a build step or a native extension provides.
_MODULE_SUFFIXES = frozenset({".py", ".pyi", ".pyd", ".so"})


def _module_name(path: Path) -> str | None:
    """Return the module a file provides, or None if Python would not import it as one."""
    if path.suffix not in _MODULE_SUFFIXES:
        return None
    return path.name.split(".", 1)[0]


def _imports(source: PythonSource) -> Iterator[tuple[int, str]]:
    # Sorted by line because this reads two node types: the index orders each type
    # by position, but interleaving `import x` with `from y import z` is this
    # function's own job, and findings that jump around the file read as noise.
    found: list[tuple[int, str]] = [
        (node.lineno, alias.name.split(".")[0])
        for node in source.nodes(ast.Import)
        for alias in node.names
    ]
    found.extend(
        (node.lineno, node.module.split(".")[0])
        for node in source.nodes(ast.ImportFrom)
        if node.level == 0 and node.module
    )
    yield from sorted(found)


_INSTALLED_PACKAGES = "site-packages"


def _relative_parts(path: Path, root: Path) -> tuple[str, ...]:
    """Split a listed path below the scan root; the root's own name is never a module."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return (path.name,)
    return parts or (path.name,)


def _local_modules(files: Iterable[Path], root: Path) -> frozenset[str]:
    """Name every module the target's own listing provides.

    A module file names itself, its package and, for a namespace package, the
    directory above that; anything under a `src/` directory names its top-level
    package. Only listed files count, so a directory the scan skips or excludes
    cannot make an unknown import look local.
    """
    names: set[str] = set()
    for path in files:
        *directories, filename = _relative_parts(path, root)
        module = _module_name(Path(filename))
        if module is not None:
            names.add(module)
            names.update(directories[-2:])
        names.update(
            directories[index + 1]
            for index, directory in enumerate(directories[:-1])
            if directory == "src"
        )
    return frozenset(names)


class HallucinatedPackageRule(ArtifactRule):
    """Flags an import of a package nobody has heard of — a slopsquat lead, not a verdict."""

    meta = RuleMeta(
        id="guardana.supply_chain.hallucinated_package",
        title="Import of unknown package (possible slopsquat lead)",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample an unknown import, a declared one and a file the scan could not read."""
        return materialise(
            (
                _samples.sample(
                    "an import nobody declared or published",
                    FixtureOutcome.FINDING,
                    {"app.py": "import json\n\nimport tokenizerz_fast_utils\n"},
                ),
                _samples.sample(
                    "an import the project declares in its requirements",
                    FixtureOutcome.CLEAN,
                    {
                        "app.py": "import json\n\nimport acme_tokenizers\n",
                        "requirements.txt": "acme-tokenizers==1.0\n",
                    },
                ),
                _samples.past_the_source_limit(
                    "an unknown import padded past the read limit, so nobody read it",
                    "app.py",
                    "import tokenizerz_fast_utils\n",
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file, treating the target's own modules as known."""
        if not isinstance(target, FileReader):
            return
        root = Path(target.ref)
        # An installed package names itself and declares its own dependencies; neither
        # is this project's, so it must not make an unknown import look known.
        files = tuple(
            path
            for path in target.iter_files()
            if _INSTALLED_PACKAGES not in _relative_parts(path, root)
        )
        local = _local_modules(files, root)
        known = _STDLIB | KNOWN_DISTRIBUTIONS | installed_import_names() | local
        # The repo's own declared dependencies (requirements/pyproject), normalized —
        # so a real, in-requirements package is known even under an isolated install
        # where it isn't importable in Guardana's env.
        declared = declared_import_names(files)
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is None:
                yield from unread_python(self.meta, target, path, ctx)
            else:
                yield from self._scan(source, known, declared)

    def _scan(
        self, source: PythonSource, known: frozenset[str], declared: frozenset[str]
    ) -> Iterator[Finding]:
        path = source.path
        for lineno, name in _imports(source):
            if name not in known and normalize(name) not in declared:
                yield Finding(
                    rule_id=self.meta.id,
                    severity=self.meta.severity,
                    title=self.meta.title,
                    taxonomy=self.meta.taxonomy,
                    target_ref=f"{path}:{lineno}",
                    evidence=Evidence(
                        summary=(
                            f"import '{name}' isn't a known package or a declared dependency "
                            f"— declare it in requirements/pyproject, or verify it exists on PyPI"
                        ),
                        detail=f"{path.name}:{lineno}",
                    ),
                    verdict=lead_verdict(
                        f"import '{name}' is not in Guardana's known packages nor the repo's "
                        f"declared dependencies; an undeclared-or-slopsquat lead, not a certainty"
                    ),
                )
