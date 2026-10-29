"""`reference-summary`: one run as a Markdown summary — the verdict, then each channel.

Every value that came from the run is escaped, so a rule title, a file name or a reason
cannot open a link, an HTML tag or a new table row in whatever renders the Markdown.
"""

from collections.abc import Iterable, Sequence

from guardana.core.output import RendererSpec
from guardana.core.verify import Verification

NAME = "reference-summary"

_SPECIAL = frozenset("\\`*_[]<>|&~#")


def spec() -> RendererSpec:
    """Return the `reference-summary` format."""
    return RendererSpec(
        name=NAME,
        summary="the run as a Markdown summary: the verdict, every finding, error and gap",
        render=render,
    )


def render(verification: Verification) -> str:
    """Write `verification` as Markdown text."""
    result = verification.result
    questions = [
        f"{question}: {result.stopped_by}" if str(question) == "stopped" else str(question)
        for question in verification.open_questions
    ]
    lines = [
        f"# Guardana run {escape(verification.manifest.run_id)}",
        "",
        "| | |",
        "|---|---|",
        f"| Target | {escape(verification.manifest.target.ref)} |",
        f"| Gate | **{escape(str(verification.gate))}** |",
        f"| Exit code | {verification.exit_code} |",
        f"| Open questions | {escape(', '.join(questions)) or 'none'} |",
        f"| Rules run | {len(result.rules_run)} |",
        f"| Cases recorded | {len(result.assessments)} |",
    ]
    lines += _section(
        "Findings",
        ("Severity", "Rule", "Title", "Location", "Evidence"),
        [
            (f.severity.name, f.rule_id, f.title, f.target_ref, f.evidence.summary)
            for f in result.findings
        ],
    )
    lines += _section(
        "Inconclusive",
        ("Rule", "Location", "Reason"),
        [(f.rule_id, f.target_ref, f.evidence.summary) for f in result.unverified],
    )
    lines += _section(
        "Waived",
        ("Rule", "Location"),
        [(f.rule_id, f.target_ref) for f in result.waived],
    )
    lines += _section(
        "Errors",
        ("Source", "Stage", "Reason"),
        [(e.source, e.stage, e.reason) for e in result.errors],
    )
    lines += _section(
        "Skipped",
        ("Rule", "Reason", "Detail"),
        [(s.rule_id, str(s.reason), s.detail) for s in result.rules_skipped],
    )
    lines += _section(
        "Coverage shortfalls",
        ("Name", "Kind", "Detail"),
        [(s.name, str(s.kind), s.detail) for s in result.coverage_shortfall],
    )
    return "\n".join(lines) + "\n"


def _section(title: str, header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    """Return a heading with the row count and a table, or nothing for an empty channel."""
    if not rows:
        return []
    return [
        "",
        f"## {title} ({len(rows)})",
        "",
        _row(header),
        _row("---" for _ in header),
        *(_row(escape(cell) for cell in row) for row in rows),
    ]


def _row(cells: Iterable[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def escape(text: str) -> str:
    """Return `text` on one line, with every character Markdown or HTML would read escaped."""
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    flat = " ".join(printable.split())
    return "".join(f"\\{ch}" if ch in _SPECIAL else ch for ch in flat)
