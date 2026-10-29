"""Render `docs/**.md`, the rule registry and `notes/*.md` into the static site under `site/`.

Split across small modules for the reason the engine is: one concept per file, so
a change to how links are rewritten does not sit in the same file as the palette.

`build` and `build_notes` are the only entry points anybody outside this package needs.
"""

from sitegen.build import build
from sitegen.errors import SiteBuildError
from sitegen.notes import build_notes

__all__ = ["SiteBuildError", "build", "build_notes"]
