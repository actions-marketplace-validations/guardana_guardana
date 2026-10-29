"""The README's diagram is the docs' diagram, so the two cannot tell different stories."""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_MERMAID = re.compile(r"```mermaid\n.*?\n```", re.DOTALL)


def test_the_readme_draws_the_how_it_works_diagram_unchanged() -> None:
    source = _MERMAID.findall((_ROOT / "docs" / "how-it-works.md").read_text(encoding="utf-8"))
    readme = _MERMAID.findall((_ROOT / "README.md").read_text(encoding="utf-8"))

    assert source
    assert readme == source[:1]
