"""The generator's own branches, which reading the built site cannot reach.

`test_documentation_site.py` reads `site/docs/` — what a visitor is served — and
that is the right check for everything the current pages exercise. It is also why
it cannot see a branch no current page happens to take: a path nothing triggers
renders nothing, so a site built from it looks perfect.

Two such branches, both deliberate, neither previously run by anything:

- a heading carrying a link is left in the body rather than lifted into the shell,
  because lifting it would render the link without the rewriter and ship a raw
  `.md` href. No page has a link in its `# ` heading today;
- tables are wrapped by substituting on `<table>`, which is only safe because the
  markdown parser escapes raw HTML. Nothing said so, and nothing would have
  noticed if that setting changed.

A third gap sits beside those two, for the opposite reason: `cost_bucket` always
runs, but nothing compares its answer to the page a rule lands on, so a wrong
bucket renders exactly as cleanly as a right one — a declared `0` filed next to a
declared `3` looks like an ordinary page, not a defect. Pinned directly against
the function, below.

The stylesheet is pinned for what a reader of a wide page needs and no built page
can show to a test: a scroll cue that stays visible, and headings that break inside
a long code span.
"""

import re

import pytest

from sitegen import explorer, render
from sitegen.theme import CSS


def _declarations(selector: str) -> str:
    """Join every declaration block of the stylesheet whose selector list names `selector`."""
    uncommented = re.sub(r"/\*.*?\*/", "", CSS, flags=re.DOTALL)
    blocks = re.findall(r"([^{}]+)\{([^{}]*)\}", uncommented)
    return ";".join(
        body
        for selectors, body in blocks
        if selector in (part.strip() for part in selectors.split(","))
    ).replace(" ", "")


def test_a_heading_with_a_link_stays_in_the_body_rather_than_losing_its_rewrite() -> None:
    """The branch the whole docs tree currently avoids by having no such heading.

    Lifting it would render the link through `renderInline`, which does not go
    through the link resolver — so the page would ship an unrewritten `.md` href
    that a reader clicks and a link checker never sees. Two headings is the lesser
    outcome, and this pins that it is the one taken.
    """
    heading, body = render.split_heading("# See [the rules](rules.md)\n\ntext\n")

    assert heading == ""
    assert body.startswith("# See [the rules](rules.md)")


def test_a_plain_heading_is_still_lifted_out_of_the_body() -> None:
    """The other side, so the assertion above cannot pass by nothing being lifted ever."""
    heading, body = render.split_heading("# `guardana taxonomy`\n\ntext\n")

    assert "guardana taxonomy" in heading
    assert not body.startswith("#")


def test_the_parser_escapes_raw_html_so_the_table_wrapper_cannot_reach_prose() -> None:
    """`wrap_tables` substitutes on the literal `<table>`, and that is safe for one reason only.

    Raw HTML is off, so a document mentioning `<table>` in prose or in a code fence
    renders it escaped and the substitution never sees it. Turning raw HTML on would
    make the wrapper start opening `<div>`s inside somebody's example and never
    close them — silent, and visible only as a broken layout on one page.
    """
    markdown = (
        "Prose mentioning <table> literally.\n\n"
        "```html\n<table><tr><td>x</td></tr></table>\n```\n\n"
        "| a | b |\n|---|---|\n| 1 | 2 |\n"
    )

    html = render.render(markdown, lambda href: href).html
    wrapped = render.wrap_tables(html)

    assert "&lt;table&gt;" in html, "raw HTML is no longer escaped; the table wrapper is now unsafe"
    assert wrapped.count('<div class="table-wrap">') == 1
    assert wrapped.count("</div>") == html.count("</table>")


@pytest.mark.parametrize("markdown", ["", "\n\n", "text with no heading\n"])
def test_a_page_with_no_opening_heading_keeps_its_body_whole(markdown: str) -> None:
    """The third way out of that loop, which an empty or heading-less page takes."""
    heading, body = render.split_heading(markdown)

    assert heading == ""
    assert body == markdown


@pytest.mark.parametrize(
    ("declared", "bucket"),
    [
        (None, "undeclared"),
        (0, "zero"),
        (2, "1-4"),
        (9, "5-plus"),
    ],
)
def test_cost_bucket_keeps_a_declared_zero_out_of_the_cheapest_paid_band(
    declared: int | None, bucket: str
) -> None:
    """`0 <= _CHEAP` reads true, so a two-branch version files a free rule as "1 to 4".

    A rule that cannot say what it will spend, a rule that spends nothing, and a
    rule that spends something are three different facts. Before this test, only
    the first and third had a bucket of their own — a declared `0` landed on the
    same page as a declared `2`, which is the false claim this pins shut.
    """
    assert explorer.cost_bucket({"estimated_requests": declared}) == bucket


def _explorer_entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "severity": "HIGH",
        "surface": "runtime",
        "family": "prompt",
        "impact": "active",
        "target_kind": "endpoint",
        "estimated_requests": 1,
        "evaluator": "canary",
        "maturity": "stable",
        "destructive": False,
        "requires": ["chat"],
        "detection": "invariant",
    }
    entry.update(overrides)
    return entry


def test_a_rule_page_states_what_its_findings_are() -> None:
    assert "<li><b>Detection</b>invariant</li>" in explorer.rule_properties(_explorer_entry(), "")


def test_a_rule_entry_without_a_detection_reads_as_undeclared() -> None:
    """A `rules.json` written before the field existed says nothing, which is not a label."""
    entry = _explorer_entry()
    del entry["detection"]

    assert "<li><b>Detection</b>undeclared</li>" in explorer.rule_properties(entry, "")


@pytest.mark.parametrize("box", ["pre", ".table-wrap"])
def test_a_wide_block_scrolls_in_its_own_box_with_a_cue_that_stays_visible(box: str) -> None:
    """An overlay scrollbar is drawn only while scrolling, so a cut-off line reads as complete.

    The scrollbar is styled so WebKit and Blink keep it drawn, and an edge shadow that
    the content covers once scrolled to that end marks the side with more to read in
    browsers that keep overlay scrollbars.
    """
    assert "overflow-x:auto" in _declarations(box)
    assert "height:" in _declarations(f"{box}::-webkit-scrollbar")
    assert "background:" in _declarations(f"{box}::-webkit-scrollbar-thumb")
    assert "no-repeatlocal" in _declarations(box)
    assert "no-repeatscroll" in _declarations(box)


@pytest.mark.parametrize("heading", ["main h1", "main h2", "main h3", "main h4"])
def test_a_long_code_span_in_a_heading_wraps_instead_of_leaving_the_column(heading: str) -> None:
    """A dotted id or a signature has no space to break at, so the heading must break inside it."""
    assert "overflow-wrap:anywhere" in _declarations(heading)
