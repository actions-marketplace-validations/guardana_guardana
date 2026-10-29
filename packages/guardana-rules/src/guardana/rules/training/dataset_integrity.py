import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.source import PythonSource
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    NIST_POISONING,
    OWASP_LLM04_2025,
    OWASP_LLM05_2026,
    OWASP_ML02_2023,
)
from guardana.core.testing import files_target
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._ast_names import import_aliases
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._unread_python import unread_python

# A dataset "loading script" is a Python class the datasets library imports and
# runs to produce examples — arbitrary code that executes while you are "just
# loading data", and a poisoning/RCE surface distinct from the model weights.
# These base classes are specific to Hugging Face `datasets`, so matching them by
# name is precise, not heuristic.
_BUILDER_BASES = frozenset(
    {"GeneratorBasedBuilder", "ArrowBasedBuilder", "BeamBasedBuilder", "DatasetBuilder"}
)


def _base_name(base: ast.expr) -> str:
    if isinstance(base, ast.Attribute):
        return base.attr
    if isinstance(base, ast.Name):
        return base.id
    return ""


def _loader_script_lines(source: PythonSource) -> Iterator[int]:
    for node in source.nodes(ast.ClassDef):
        if any(_base_name(base) in _BUILDER_BASES for base in node.bases):
            yield node.lineno


_HF_MODULES = frozenset({"datasets", "datasets.load"})
_HF_LOADERS = frozenset(f"{module}.load_dataset" for module in _HF_MODULES)


def _hf_loader_names(source: PythonSource) -> frozenset[str]:
    """Return the bare names a `from datasets[.load] import ...` binds to Hugging Face's loader."""
    names: set[str] = set()
    for node in source.nodes(ast.ImportFrom):
        if node.module not in _HF_MODULES or node.level != 0:
            continue
        for alias in node.names:
            if alias.name == "*":
                names.add("load_dataset")
            elif alias.name == "load_dataset":
                names.add(alias.asname or alias.name)
    return frozenset(names)


def _dotted_name(expr: ast.expr, aliases: dict[str, str]) -> str:
    """Return an expression's dotted name, its leading name resolved through `aliases`, or ""."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return ""
    parts.append(aliases.get(expr.id, expr.id))
    return ".".join(reversed(parts))


def _is_getattr_loader(expr: ast.expr, aliases: dict[str, str]) -> bool:
    """Whether `expr` is `getattr(<datasets module>, "load_dataset")`."""
    match expr:
        case ast.Call(
            func=ast.Name(id="getattr"),
            args=[receiver, ast.Constant(value="load_dataset")],
            keywords=[],
        ):
            return _dotted_name(receiver, aliases) in _HF_MODULES
    return False


def _is_loader(expr: ast.expr, aliases: dict[str, str], loader_names: set[str]) -> bool:
    """Whether `expr` evaluates to Hugging Face's `load_dataset` in this file."""
    # A bare name counts only when an import or alias bound it; a receiver counts
    # when it resolves to `datasets`, or is literally `datasets` unimported.
    if isinstance(expr, ast.Name):
        return expr.id in loader_names
    if isinstance(expr, ast.Attribute):
        return _dotted_name(expr, aliases) in _HF_LOADERS
    return _is_getattr_loader(expr, aliases)


def _loader_names(source: PythonSource, aliases: dict[str, str]) -> set[str]:
    """Return every bare name bound to the loader by an import or a plain assignment."""
    names = set(_hf_loader_names(source))
    bindings: list[tuple[ast.stmt, list[ast.expr], ast.expr]] = [
        (node, node.targets, node.value) for node in source.nodes(ast.Assign)
    ]
    bindings += [
        (node, [node.target], node.value)
        for node in source.nodes(ast.AnnAssign)
        if node.value is not None
    ]
    # Document order across both kinds, so an alias of an alias resolves.
    for _node, targets, value in sorted(bindings, key=lambda b: (b[0].lineno, b[0].col_offset)):
        if _is_loader(value, aliases, names):
            names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


_COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
_SHOWN_REVISION_CHARS = 60


def _pin_gap(call: ast.Call) -> str | None:
    """Say why a loader call's `revision=` does not pin a commit, or None when it does."""
    revision = next((kw.value for kw in call.keywords if kw.arg == "revision"), None)
    if revision is None:
        if any(kw.arg is None for kw in call.keywords):
            return "load_dataset() with **kwargs and no revision= — the pin cannot be checked"
        return "load_dataset() without revision= — training data source can be swapped"
    if isinstance(revision, ast.Constant):
        if isinstance(revision.value, str):
            if _COMMIT_SHA.fullmatch(revision.value):
                return None
            shown = revision.value[:_SHOWN_REVISION_CHARS]
            return f"load_dataset() revision={shown!r} names a branch or tag that can move"
        if revision.value is None:
            return "load_dataset() revision=None — the default branch can move"
    return "load_dataset() revision is not a literal commit SHA, so the pin cannot be checked"


def _unpinned_loads(source: PythonSource) -> Iterator[tuple[int, str]]:
    aliases = import_aliases(source)
    loader_names = _loader_names(source, aliases)
    for node in source.nodes(ast.Call):
        if not _is_loader(node.func, aliases, loader_names):
            continue
        gap = _pin_gap(node)
        if gap is not None:
            yield node.lineno, gap


class DatasetIntegrityRule(ArtifactRule):
    """Flags training-data hygiene gaps: dataset loading scripts and unpinned dataset pulls.

    Static poisoning *proof* is statistical, not a file scan — this rule instead
    surfaces the two hygiene gaps that make data poisoning possible and that are
    deterministically detectable: a dataset that runs code on load, and a dataset
    pulled from a mutable, unpinned source that can be swapped under you. Both are
    reported as leads, never as a confident poisoning verdict.
    """

    meta = RuleMeta(
        id="guardana.training.dataset_integrity",
        title="Training-data integrity gap (loader script or unpinned dataset)",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM04_2025,
            OWASP_LLM05_2026,
            OWASP_ML02_2023,
            NIST_POISONING,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample an unpinned pull, a pull pinned to a commit, and a script too large to read."""
        unpinned = "from datasets import load_dataset\n\nrows = load_dataset('imdb')\n"
        pinned = (
            "from datasets import load_dataset\n\n"
            "rows = load_dataset('imdb', revision='e6281661ce1c48d982bc483cf8a173c1bbeb5d31')\n"
        )
        return materialise(
            (
                DeclaredFixture(
                    "a training script pulling a dataset from a moving branch",
                    FixtureOutcome.FINDING,
                    lambda: files_target({"train.py": unpinned}),
                ),
                DeclaredFixture(
                    "a training script pulling a dataset pinned to a commit",
                    FixtureOutcome.CLEAN,
                    lambda: files_target({"train.py": pinned}),
                ),
                _samples.past_the_source_limit(
                    "a training script padded past the source read limit", "train.py", unpinned
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.py` file for dataset loader scripts and unpinned dataset loads."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is None:
                yield from unread_python(self.meta, target, path, ctx)
            else:
                yield from self._scan(source)

    def _scan(self, source: PythonSource) -> Iterator[Finding]:
        path = source.path
        for lineno in _loader_script_lines(source):
            yield self._lead(
                path,
                lineno,
                Severity.MEDIUM,
                "dataset loading script runs code on load (poisoning/RCE surface)",
            )
        for lineno, summary in _unpinned_loads(source):
            # LOW on purpose: an unpinned `load_dataset(...)` is in nearly every
            # tutorial and repo, so this is an honest hygiene nudge, never a gate.
            yield self._lead(path, lineno, Severity.LOW, summary)

    def _lead(self, path: Path, lineno: int, severity: Severity, summary: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=f"{path}:{lineno}",
            evidence=Evidence(summary=summary, detail=f"{path.name}:{lineno}"),
            verdict=lead_verdict(summary),
        )
