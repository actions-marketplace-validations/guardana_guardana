"""Both rules prove all three outcomes through `guardana rule test`, and the Python rule's
edges are pinned here, run the way a run calls it."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from guardana.core import Exchange, Expectation, Finding, Registry, RuleContext
from guardana.core.testing import files_target
from guardana_reference_pack import provide_evaluators
from guardana_reference_pack.controls import OWASP_LLM02_2025, OWASP_LLM03_2025
from guardana_reference_pack.unpinned import MAX_BYTES, UnpinnedRequirementRule

ADMIT = ("--plugins", "allowlist", "--allow-plugin", "guardana-reference-pack")


def guardana(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the `guardana` installed beside this interpreter, with no `GUARDANA_*` variable."""
    executable = shutil.which("guardana", path=str(Path(sys.executable).parent))
    if executable is None:
        pytest.fail("no guardana command is installed beside this interpreter")
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GUARDANA_")}
    return subprocess.run(  # noqa: S603 — a fixed command with literal arguments
        [executable, *args], capture_output=True, text=True, check=False, env=environment
    )


def _run(files: dict[str, str | bytes]) -> list[Finding]:
    return list(UnpinnedRequirementRule().run(files_target(files), RuleContext()))


def _declined(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is not None and f.verdict.outcome == "inconclusive"]


def _found(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is None]


def test_rule_test_proves_every_reference_rule() -> None:
    result = guardana("rule", "test", "reference.*", *ADMIT)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 rule(s); 6 fixture(s) passed, 0 failed, 0 could not run." in result.stdout
    assert "0 rule(s) not fully sampled" in result.stdout


def test_rule_test_refuses_the_pack_until_it_is_admitted() -> None:
    result = guardana("rule", "test", "reference.*")

    assert result.returncode != 0
    assert "guardana-reference-pack" in result.stdout + result.stderr


def test_a_range_a_wildcard_and_an_editable_install_are_each_a_finding() -> None:
    findings = _run(
        {"requirements.txt": "requests>=2.31\nurllib3==2.*\n-e ./vendored\nidna==3.7\n"}
    )

    assert len(_found(findings)) == 3
    assert _declined(findings) == []


def test_exact_pins_with_hashes_markers_and_options_are_clean() -> None:
    lines = [
        "--index-url https://pypi.org/simple",
        "requests==2.32.3 \\",
        f"    --hash=sha256:{'0' * 64}",
        "tomli===2.0.1 ; python_version < '3.11'  # backport",
    ]
    findings = _run({"requirements.in": "\n".join(lines) + "\n"})

    assert findings == []


@pytest.mark.parametrize(
    "line",
    [
        "-r base.txt",
        "--requirement=base.txt",
        "-cconstraints.txt",
        "acme @ https://example.invalid/acme-1.0.tar.gz",
        "https://example.invalid/acme-1.0.tar.gz",
        "./local/package",
    ],
)
def test_a_line_the_rule_does_not_grade_is_declined_not_passed(line: str) -> None:
    findings = _run({"requirements.txt": f"{line}\n"})

    assert len(_declined(findings)) == 1
    assert _found(findings) == []


def test_a_file_too_large_to_read_whole_is_declined() -> None:
    findings = _run({"requirements.txt": "requests==2.32.3\n" * (MAX_BYTES // 17 + 1)})

    assert len(_declined(findings)) == 1


def test_files_not_named_like_requirements_are_not_read() -> None:
    assert _run({"constraints.txt": "requests>=2\n", "notes.txt": "requests>=2\n"}) == []


def test_a_requirements_file_in_any_case_is_read() -> None:
    assert len(_found(_run({"deps/REQUIREMENTS-dev.TXT": "requests>=2\n"}))) == 1


def test_the_public_entries_equal_what_the_engine_resolves(tmp_path: Path) -> None:
    rule = tmp_path / "probe.yaml"
    rule.write_text(
        "id: local.taxonomy_probe\ntitle: resolves two public entries\nseverity: low\n"
        "target_kind: endpoint\ntaxonomy: [LLM02:2025, LLM03:2025]\nevaluator: contains\n"
        'requires: [chat]\nprompts: ["hello"]\nexpect:\n  contains_none: ["x"]\n',
        encoding="utf-8",
    )
    registry = Registry()

    loaded = registry.load_yaml_rule_dirs([rule])

    assert loaded.errors == ()
    assert registry.rules()[0].meta.taxonomy == (OWASP_LLM02_2025, OWASP_LLM03_2025)


def test_the_evaluator_declines_an_exchange_with_no_reply() -> None:
    (evaluator,) = provide_evaluators()

    verdict = evaluator.evaluate(Exchange(messages=()), Expectation(fields={"marker": "BLUEFINCH"}))

    assert verdict.outcome == "inconclusive"


def test_the_evaluator_refuses_to_grade_without_a_marker() -> None:
    (evaluator,) = provide_evaluators()

    with pytest.raises(TypeError, match=r"expect\.marker"):
        evaluator.evaluate(Exchange(messages=()), Expectation())
