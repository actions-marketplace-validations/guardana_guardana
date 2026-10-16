"""`docs/writing-rules.md` marks the loaders it recommends from outside the supported surface."""

from pathlib import Path

_PAGE = Path(__file__).resolve().parents[3] / "docs" / "writing-rules.md"
_WARNING = "compatibility.md#the-supported-surface"


def _paragraphs_naming(name: str) -> list[str]:
    paragraphs = _PAGE.read_text(encoding="utf-8").split("\n\n")
    return [paragraph for paragraph in paragraphs if name in paragraph]


def _warned(name: str) -> bool:
    """Tell whether the page marks `name` as outside the surface where it recommends it."""
    page = _PAGE.read_text(encoding="utf-8")
    return any(
        name in paragraph and _WARNING in paragraph
        for paragraph in page.split("\n\n")
        if "outside" in paragraph
    )


def test_control_the_page_warns_where_it_shows_case_id_for() -> None:
    assert _paragraphs_naming("case_id_for")
    assert _warned("case_id_for")


def test_the_page_warns_where_it_recommends_load_yaml_rules() -> None:
    assert _paragraphs_naming("load_yaml_rules")
    assert _warned("load_yaml_rules")
