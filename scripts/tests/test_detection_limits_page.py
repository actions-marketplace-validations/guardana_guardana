"""The detection-limits page places every built-in once and never drops an undeclared rule.

Beside the generator rather than under `packages/`, for the reason the site generator's
tests are: importing a script from a test the dogfood scan reads would make Guardana
flag Guardana for an undeclared dependency.
"""

import re
from collections.abc import Iterable
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import FixtureOutcome, Rule, RuleContext, RuleFixture, RuleMeta
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Target, TargetKind
from guardana.core.taxonomy import resolve
from guardana.rules import provide_evaluators, provide_rules

import generate_docs

_PAGE = Path(__file__).resolve().parents[2] / "docs" / "generated" / "detection-limits.md"
_SAMPLED_CANARY_RULE = "guardana.prompt.system_prompt_leak.canary"
_ENTRY = re.compile(r"^- `([^`]+)`: ", re.MULTILINE)


class _FakeRule(Rule):
    def __init__(self, rule_id: str, detection: Detection) -> None:
        taxonomy = resolve("LLM01:2025")
        self.meta = RuleMeta(
            rule_id,
            f"title of {rule_id}",
            Severity.LOW,
            TargetKind.ARTIFACT,
            taxonomy=(taxonomy,) if taxonomy is not None else (),
            detection=detection,
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing; this rule exists to be placed on the page."""
        return ()


class _FiringRule(_FakeRule):
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report one finding on any target."""
        yield Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref="sample",
            evidence=Evidence(summary="the fact the sample plants"),
        )


class _SampledRule(_FakeRule):
    """Ships a finding and a clean sample it classifies correctly, and optionally a wrong one."""

    def __init__(self, *, with_a_wrong_sample: bool) -> None:
        super().__init__("acme.demo.sampled", Detection.INVARIANT)
        self._with_a_wrong_sample = with_a_wrong_sample

    def fixtures(self) -> Iterable[RuleFixture]:
        """Fire through a firing twin, stay quiet itself, and misread the third if asked."""
        target = ArtifactTarget(Path(__file__).parent)
        yield RuleFixture(
            "fires",
            target,
            FixtureOutcome.FINDING,
            rule=_FiringRule(self.meta.id, Detection.INVARIANT),
        )
        yield RuleFixture("stays quiet", target, FixtureOutcome.CLEAN)
        if self._with_a_wrong_sample:
            yield RuleFixture("should decline", target, FixtureOutcome.INCONCLUSIVE)


def _rule_ids(page: str) -> list[str]:
    """Collect the ids listed under a detection group, leaving the mappings out."""
    listed: list[str] = []
    heading = ""
    for line in page.splitlines():
        if line.startswith("### "):
            heading = line[4:]
        elif line.startswith("## "):
            heading = ""
        elif heading in generate_docs._GROUPS:
            listed += _ENTRY.findall(line)
    return listed


def _section(page: str, family: str, group: str) -> str:
    family_part = page.split(f"## {family}\n", 1)[1].split("\n## ", 1)[0]
    return family_part.split(f"### {group}\n", 1)[1].split("\n### ", 1)[0]


def test_the_committed_page_lists_every_built_in_exactly_once() -> None:
    listed = _rule_ids(_PAGE.read_text(encoding="utf-8"))
    installed = sorted(rule.meta.id for rule in provide_rules())

    assert sorted(listed) == installed, (
        f"missing: {sorted(set(installed) - set(listed))}; "
        f"repeated: {sorted({i for i in listed if listed.count(i) > 1})}"
    )


def test_the_committed_page_is_what_the_generator_writes_today() -> None:
    wanted = generate_docs._front("detection-limits.md") + generate_docs._detection_limits(
        generate_docs._rules()
    )

    assert _PAGE.read_text(encoding="utf-8") == wanted


def test_an_undeclared_rule_is_printed_as_not_declared() -> None:
    rules: list[Rule] = [
        _FakeRule("acme.demo.fact", Detection.INVARIANT),
        _FakeRule("acme.demo.lead", Detection.HEURISTIC),
        _FakeRule("acme.demo.silent", Detection.UNDECLARED),
    ]

    page = generate_docs._detection_page(rules, lambda _rule: False)

    assert sorted(_rule_ids(page)) == ["acme.demo.fact", "acme.demo.lead", "acme.demo.silent"]
    assert "acme.demo.silent" in _section(page, "demo", "Not declared")
    assert "acme.demo.fact" in _section(page, "demo", "Invariant, not sampled")
    assert "acme.demo.lead" in _section(page, "demo", "Heuristic lead")


def test_only_a_sampled_invariant_is_called_tested() -> None:
    rules: list[Rule] = [
        _FakeRule("acme.demo.sampled", Detection.INVARIANT),
        _FakeRule("acme.demo.unsampled", Detection.INVARIANT),
        _FakeRule("acme.demo.lead", Detection.HEURISTIC),
    ]

    page = generate_docs._detection_page(rules, lambda rule: rule.meta.id != "acme.demo.unsampled")

    tested = _section(page, "demo", "Tested invariant")
    assert "acme.demo.sampled" in tested
    assert "acme.demo.unsampled" not in tested
    assert "acme.demo.lead" not in tested
    assert "acme.demo.unsampled" in _section(page, "demo", "Invariant, not sampled")


def test_an_empty_group_is_not_printed_and_the_mapping_is_not_called_coverage() -> None:
    page = generate_docs._detection_page(
        [_FakeRule("acme.demo.lead", Detection.HEURISTIC)], lambda _rule: False
    )

    assert "### Tested invariant" not in page
    assert "### Not declared" not in page
    mapping = _section(
        page, "demo", "Framework entries these rules are relevant to, not coverage of them"
    )
    assert "`LLM01:2025`: Prompt Injection" in mapping


def test_a_rule_with_no_samples_is_not_tested() -> None:
    silent = _FakeRule("acme.demo.fact", Detection.INVARIANT)

    assert generate_docs._ships_both_samples(silent, RuleContext()) is False


def test_samples_that_cannot_be_graded_do_not_make_a_rule_tested() -> None:
    """The same samples count only when they ran and classified correctly."""
    (canary,) = [r for r in provide_rules() if r.meta.id == _SAMPLED_CANARY_RULE]
    graded = RuleContext(evaluators={type(e).id: e for e in provide_evaluators()})

    assert generate_docs._ships_both_samples(canary, graded) is True
    assert generate_docs._ships_both_samples(canary, RuleContext()) is False


def test_a_rule_that_misreads_one_of_its_samples_is_not_tested() -> None:
    """Passing finding and clean samples say nothing once another sample was misread."""
    ctx = RuleContext()

    assert generate_docs._ships_both_samples(_SampledRule(with_a_wrong_sample=False), ctx) is True
    assert generate_docs._ships_both_samples(_SampledRule(with_a_wrong_sample=True), ctx) is False
