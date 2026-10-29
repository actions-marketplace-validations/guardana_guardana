"""The rule `docs/model-formats.md` shows is the example pack's rule, character for character.

The page calls it runnable, so a copy that drifts from the tested code teaches a shape
nothing runs.
"""

import re
from pathlib import Path

_EXAMPLE = "examples/custom_rule/src/acme_rules/approved_model.py"
_PAGE = "docs/model-formats.md"


def _repo() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "README.md").is_file() and (parent / "packages").is_dir():
            return parent
    raise AssertionError("could not locate the repository root")


def test_the_page_shows_the_example_rule_verbatim() -> None:
    page = (_repo() / _PAGE).read_text(encoding="utf-8")
    source = (_repo() / _EXAMPLE).read_text(encoding="utf-8")
    [snippet] = [
        block
        for block in re.findall(r"```python\n(.*?)```", page, re.DOTALL)
        if "def _unscanned" in block
    ]

    assert "ctx.examined(path)" in snippet
    assert "ShortfallKind.UNEXAMINED_COMPONENT" in snippet
    assert snippet in source
