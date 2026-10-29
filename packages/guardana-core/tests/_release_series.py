"""The release series the documentation follows."""

import re
from pathlib import Path

from guardana.core import __version__

_CHANGELOG = Path(__file__).resolve().parents[3] / "CHANGELOG.md"
_FINAL = re.compile(r"(\d+)\.(\d+)\.\d+")
_FINAL_HEADING = re.compile(r"^## \[(\d+)\.(\d+)\.\d+\]", re.MULTILINE)


def stable_series() -> tuple[int, int]:
    """Return `(major, minor)` of the newest final release.

    A pre-release moves no stable tag and ships no milestone, so for one the series is the
    newest final release `CHANGELOG.md` records; for a final release it is its own.
    """
    final = _FINAL.fullmatch(__version__)
    if final is not None:
        return int(final.group(1)), int(final.group(2))
    found = _FINAL_HEADING.search(_CHANGELOG.read_text(encoding="utf-8"))
    if found is None:
        raise LookupError("CHANGELOG.md records no final release")
    return int(found.group(1)), int(found.group(2))
