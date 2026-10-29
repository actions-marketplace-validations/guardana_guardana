"""A sample whose files the target could not read proves a decline, never a clean result."""

import gc
from collections.abc import Iterable
from pathlib import Path

import pytest
from guardana.core.report import Evidence, Finding
from guardana.core.rule import FixtureOutcome, Rule, RuleContext, RuleFixture, RuleMeta
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.testing import files_target


class _EvalRule(Rule):
    """Reports every Python file whose source calls `eval`."""

    meta = RuleMeta(
        "acme.eval",
        "eval",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def __init__(self, samples: list[RuleFixture]) -> None:
        self._samples = samples

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Read every `.py` file through the target, as a built-in does."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".py",)):
            source = target.python_source(path)
            if source is not None and "eval(" in source.text:
                yield Finding(
                    rule_id=self.meta.id,
                    title="eval",
                    severity=Severity.HIGH,
                    taxonomy=(),
                    target_ref=str(path),
                    evidence=Evidence(summary="calls eval"),
                )

    def fixtures(self) -> Iterable[RuleFixture]:
        """The samples the test set."""
        return self._samples


def _tree(tmp_path: Path, files: dict[str, str]) -> ArtifactTarget:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return ArtifactTarget(tmp_path, source_read_limit=16)


def test_a_file_the_target_could_not_read_classifies_as_a_decline(tmp_path: Path) -> None:
    unread = _tree(tmp_path, {"big.py": "x = 1\n" * 20})
    rule = _EvalRule([RuleFixture("too large to read", unread, FixtureOutcome.INCONCLUSIVE)])

    [result] = verify_rule(rule).results

    assert result.verdict is FixtureVerdict.PASSED
    assert result.observed is FixtureOutcome.INCONCLUSIVE


def test_a_clean_sample_over_an_unread_file_fails_and_names_it(tmp_path: Path) -> None:
    unread = _tree(tmp_path, {"big.py": "x = 1\n" * 20})
    rule = _EvalRule([RuleFixture("claims clean", unread, FixtureOutcome.CLEAN)])

    [result] = verify_rule(rule).results

    assert result.verdict is FixtureVerdict.FAILED
    assert "unread: big.py" in result.detail


def test_a_finding_beside_an_unread_file_stays_a_finding(tmp_path: Path) -> None:
    mixed = _tree(tmp_path, {"a.py": "eval(1)\n", "big.py": "x = 1\n" * 20})
    rule = _EvalRule([RuleFixture("one read, one not", mixed, FixtureOutcome.FINDING)])

    [result] = verify_rule(rule).results

    assert result.verdict is FixtureVerdict.PASSED


def test_files_target_holds_the_files_it_was_given() -> None:
    target = files_target({"pkg/a.py": "eval(1)\n", "model.bin": b"\x00\x01"})

    names = sorted(p.name for p in target.iter_files())

    assert names == ["a.py", "model.bin"]
    rule = _EvalRule([RuleFixture("eval", target, FixtureOutcome.FINDING)])
    assert verify_rule(rule).results[0].verdict is FixtureVerdict.PASSED


@pytest.mark.parametrize("name", ["/etc/passwd", "../outside.py", "a/../../b.py", ""])
def test_files_target_refuses_a_path_outside_its_tree(name: str) -> None:
    with pytest.raises(ValueError, match="relative path inside its tree"):
        files_target({name: "x"})


def test_files_target_removes_its_directory_once_the_target_is_gone() -> None:
    target = files_target({"a.py": "x = 1\n"})
    root = Path(target.ref)
    assert root.is_dir()

    del target
    gc.collect()

    assert not root.exists()


def test_files_target_reads_only_up_to_the_limit_it_was_given() -> None:
    target = files_target({"big.py": "x = 1\n" * 20, "a.py": "eval(1)\n"}, source_read_limit=16)
    rule = _EvalRule([RuleFixture("one read, one not", target, FixtureOutcome.FINDING)])

    assert verify_rule(rule).results[0].verdict is FixtureVerdict.PASSED
    assert [unread.path.name for unread in target.unread_sources()] == ["big.py"]


def test_files_target_reads_up_to_the_target_default_unless_told_otherwise() -> None:
    target = files_target({"big.py": "x = 1\n" * 20})
    rule = _EvalRule([RuleFixture("read in full", target, FixtureOutcome.CLEAN)])

    assert verify_rule(rule).results[0].verdict is FixtureVerdict.PASSED
    assert target.unread_sources() == ()
