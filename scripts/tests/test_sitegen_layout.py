"""Every generated docs page opens with a skip link targeting the main content."""

from __future__ import annotations

import re

from sitegen import layout, theme

_FOCUSABLE = re.compile(
    r"<(?:a\s[^>]*href=|button|input|select|textarea|summary)[^>]*>", re.IGNORECASE
)


def _render() -> str:
    return layout.page(
        chrome=layout.Chrome((), "0.0.0"),
        href="index.html",
        title="T",
        summary="s",
        body="<p>Text.</p>",
        edit_path=None,
    )


def test_first_focusable_link_targets_main_content() -> None:
    html = _render()
    first = _FOCUSABLE.search(html)
    assert first is not None
    assert 'href="#main"' in first.group(0)
    assert 'class="skip"' in first.group(0)


def test_main_content_carries_matching_id() -> None:
    assert '<main id="main">' in _render()


def _declarations(selector: str) -> dict[str, str]:
    """Return the declarations of the stylesheet rule whose selector list holds `selector`."""
    for rule in re.finditer(r"([^{}]+)\{([^{}]*)\}", theme.CSS):
        if selector in {each.strip() for each in rule.group(1).split(",")}:
            pairs = (item.split(":", 1) for item in rule.group(2).split(";") if ":" in item)
            return {name.strip(): value.strip() for name, value in pairs}
    return {}


def _vertical_shift(selector: str) -> str:
    shift = re.fullmatch(r"translateY\((.+)\)", _declarations(selector).get("transform", ""))
    assert shift is not None, f"{selector} sets no vertical transform"
    return shift.group(1)


def test_the_skip_link_is_moved_out_of_view_until_it_has_focus() -> None:
    hidden = _declarations(".skip")
    assert hidden.get("position") == "absolute"
    assert hidden.get("top") == "0"
    assert _vertical_shift(".skip").startswith("-")
    assert not _vertical_shift(".skip:focus").startswith("-")
