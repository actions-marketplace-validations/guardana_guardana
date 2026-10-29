"""A rule directory somebody configured that loads nothing says so.

`rules.paths` and `--rules` name directories of YAML rules. One that holds no rule file at
the top level — empty, or with its rules in a subdirectory — used to load nothing and
record nothing, so a run without the team's own checks read as complete.
"""

from pathlib import Path

from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.registry import Registry

_RULE = (
    "id: acme.prompt.demo\n"
    "title: demo\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: keyword\n"
    "requires: [chat]\n"
    "prompts: ['hello']\n"
    "expect: {goal: 'complied'}\n"
)


def _load(path: Path) -> tuple[tuple[str, ...], list[str]]:
    registry = Registry()
    registry.register_evaluator(KeywordEvaluator())
    outcome = registry.load_yaml_rule_dirs([path])
    return outcome.loaded, [f"{e.source}: {e.reason}" for e in registry.load_errors]


def test_an_empty_rule_directory_is_a_load_error(tmp_path: Path) -> None:
    loaded, errors = _load(tmp_path)

    assert loaded == ()
    assert len(errors) == 1
    assert "holds no .yaml or .yml rule file" in errors[0]


def test_rules_only_in_a_subdirectory_are_named_as_not_read(tmp_path: Path) -> None:
    (tmp_path / "prompt").mkdir()
    (tmp_path / "prompt" / "demo.yaml").write_text(_RULE, encoding="utf-8")

    loaded, errors = _load(tmp_path)

    assert loaded == ()
    assert "subdirectories are not read" in errors[0]


def test_an_upper_case_extension_is_a_rule_file(tmp_path: Path) -> None:
    (tmp_path / "demo.YAML").write_text(_RULE, encoding="utf-8")

    loaded, errors = _load(tmp_path)

    assert loaded == ("acme.prompt.demo",)
    assert errors == []


def test_a_directory_with_a_rule_file_records_no_error(tmp_path: Path) -> None:
    (tmp_path / "demo.yaml").write_text(_RULE, encoding="utf-8")

    loaded, errors = _load(tmp_path)

    assert loaded == ("acme.prompt.demo",)
    assert errors == []
