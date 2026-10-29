"""`reference.supply_chain.unpinned_requirement`: a pip requirement not pinned to one version.

A requirement that admits a range installs whatever the index serves on the day of the
build, so the artifact that ships is not the one that was reviewed. The rule reads every
`requirements*.txt` and `requirements*.in` file a target lists, and declines a file it
cannot read whole, a line it cannot parse and an include it does not follow.
"""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from guardana.core import (
    Capability,
    Evidence,
    Finding,
    Rule,
    RuleContext,
    RuleError,
    RuleMeta,
    Severity,
    Target,
    TargetKind,
    Verdict,
)
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture
from guardana.core.target.protocols import FileReader
from guardana.core.testing import files_target

from guardana_reference_pack.controls import OWASP_LLM03_2025, PINNED_DEPENDENCIES

SUFFIXES = (".txt", ".in")
STEM = "requirements"
MAX_BYTES = 1024 * 1024

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?:\[[^\]]*\])?")
_PIN = re.compile(r"(?:===|==)\s*[A-Za-z0-9][A-Za-z0-9.+!_-]*")
_INCLUDES = ("-r", "--requirement", "-c", "--constraint")
_EDITABLE = ("-e", "--editable")
_COMMENT = re.compile(r"(?:^|\s)#.*$")


@dataclass(frozen=True, slots=True)
class _Unread:
    """Why a file was not read whole."""

    reason: str


def is_requirements_file(path: Path) -> bool:
    """Whether `path` is named like a pip requirements file, in any case."""
    name = path.name.lower()
    return name.startswith(STEM) and path.suffix.lower() in SUFFIXES


class UnpinnedRequirementRule(Rule):
    """Report every requirement that admits more than one version."""

    meta = RuleMeta(
        id="reference.supply_chain.unpinned_requirement",
        title="A requirement is not pinned to one version",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM03_2025, PINNED_DEPENDENCIES),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Read each requirements file the target lists and grade it line by line."""
        if not isinstance(target, FileReader):
            raise RuleError(f"{self.meta.id} needs a file target, got {type(target).__name__}")
        for path in target.iter_files(SUFFIXES):
            if not is_requirements_file(path):
                continue
            ctx.examined(path)
            text = _read(path)
            if isinstance(text, _Unread):
                yield self._declined(path, text.reason)
                continue
            yield from self._graded(path, text)

    def _graded(self, path: Path, text: str) -> Iterator[Finding]:
        for number, line in _logical_lines(text):
            flag = _flag(line)
            if flag in _INCLUDES:
                yield self._declined(path, f"line {number} includes another file, not followed")
            elif flag in _EDITABLE:
                yield self._unpinned(path, number, line, "an editable install names no version")
            elif not flag.startswith("-"):
                yield from self._requirement(path, number, line)

    def _requirement(self, path: Path, number: int, line: str) -> Iterator[Finding]:
        spec = line.split(";", 1)[0].split(" --", 1)[0].strip()
        name = _NAME.match(spec)
        rest = "" if name is None else spec[name.end() :].strip()
        if "://" in spec or rest.startswith("@"):
            yield self._declined(path, f"line {number} is a direct reference, not graded")
        elif name is None:
            yield self._declined(path, f"line {number} is not a requirement this rule reads")
        elif _PIN.fullmatch(rest) is None:
            yield self._unpinned(path, number, spec, "it admits more than one version")

    def _unpinned(self, path: Path, number: int, spec: str, why: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"{spec!r} is not pinned: {why}",
                detail=f"file={path.name}; line={number}",
            ),
        )

    def _declined(self, path: Path, reason: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=reason, detail=f"file={path.name}"),
            verdict=Verdict("inconclusive", 0.0, reason, self.meta.id),
        )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Three samples: a range, exact pins, and a file that is not UTF-8."""
        return (
            RuleFixture(
                "a requirement that admits a range",
                files_target({"requirements.txt": "requests>=2.31\n"}),
                FixtureOutcome.FINDING,
            ),
            RuleFixture(
                "every requirement pinned, with comments, options and a marker",
                files_target(
                    {
                        "requirements.txt": (
                            "# the service\n"
                            "--index-url https://pypi.org/simple\n"
                            "requests==2.32.3  # http\n"
                            "tomli===2.0.1 ; python_version < '3.11'\n"
                        )
                    }
                ),
                FixtureOutcome.CLEAN,
            ),
            RuleFixture(
                "a requirements file that is not UTF-8",
                files_target({"requirements.txt": b"requests==2.32.3\n\xff\xfe\n"}),
                FixtureOutcome.INCONCLUSIVE,
                note="the bytes do not decode, so no line of the file is graded",
            ),
        )


def _flag(line: str) -> str:
    """Return the pip option a line starts with, `-rbase.txt` and `--requirement=x` alike."""
    head = line.split(maxsplit=1)[0].split("=", 1)[0]
    if head.startswith("-") and not head.startswith("--"):
        return head[:2]
    return head


def _read(path: Path) -> str | _Unread:
    """Read `path` as UTF-8, at most `MAX_BYTES`; say why when that is not possible."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        return _Unread(f"could not be read: {exc.strerror or type(exc).__name__}")
    if len(data) > MAX_BYTES:
        return _Unread(f"is larger than {MAX_BYTES} bytes, so it was not read whole")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _Unread(f"is not UTF-8 (byte {exc.start})")


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield each logical line with its first line number, continuations joined, comments cut."""
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not pending:
            start = number
        if raw.endswith("\\"):
            pending.append(raw[:-1])
            continue
        pending.append(raw)
        line = _COMMENT.sub("", " ".join(pending)).strip()
        pending = []
        if line:
            yield start, line
    if pending:
        line = _COMMENT.sub("", " ".join(pending)).strip()
        if line:
            yield start, line
