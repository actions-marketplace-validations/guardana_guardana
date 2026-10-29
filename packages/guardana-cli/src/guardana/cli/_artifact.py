"""The directory a recipe run leaves for a reviewer, which never shows a stale or partial green.

The directory is claimed with a placeholder before anything runs and replaced whole when
the run ends, so an interrupted run leaves "did not finish" behind and never last week's
`junit.xml`. A directory Guardana did not write is refused, never deleted.
"""

import json
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path

from guardana.report.junit import unfinished_document

MARKER = "guardana-artifact.json"
"""Names the files a run wrote; its presence is what lets a later run replace the directory."""

ARTIFACT_SCHEMA_VERSION = 1


class ArtifactRefusedError(Exception):
    """The output directory exists and Guardana did not write it."""


def claim(directory: Path, recipe: str) -> None:
    """Put a placeholder in `directory` saying the run has not finished.

    Raises `ArtifactRefusedError` for a directory with files and no marker, or a path
    that is not a plain directory.
    """
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise ArtifactRefusedError(f"{directory} is not a plain directory the run can replace")
    foreign = _not_written_by_a_run(directory) if directory.exists() else []
    if foreign:
        raise ArtifactRefusedError(
            f"{directory} holds files Guardana did not write ({', '.join(foreign[:5])}); "
            f"move them or name another output.directory in the recipe"
        )
    detail = f"recipe {recipe} started a run that has not finished; nothing here is a result"
    publish(
        directory,
        {
            "report.txt": f"{detail}\n",
            "junit.xml": unfinished_document("guardana.recipe", "the run did not finish", detail),
        },
        status="incomplete",
    )


def publish(directory: Path, files: Mapping[str, str], status: str) -> None:
    """Replace `directory` with exactly `files` and the marker, in one rename where possible."""
    parent = directory.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{directory.name}.", dir=parent))
    for name, text in files.items():
        # Bytes, so no platform translates line endings away from what a digest covers.
        (staging / name).write_bytes(text.encode("utf-8"))
    marker = {"schema_version": ARTIFACT_SCHEMA_VERSION, "status": status, "files": sorted(files)}
    (staging / MARKER).write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")
    if not directory.exists():
        staging.rename(directory)
        return
    retired = Path(tempfile.mkdtemp(prefix=f".{directory.name}.old.", dir=parent))
    retired.rmdir()
    directory.rename(retired)
    staging.rename(directory)
    shutil.rmtree(retired)


def _not_written_by_a_run(directory: Path) -> list[str]:
    """Name every entry the directory's index does not list, so a run never deletes it."""
    present = sorted(entry.name for entry in directory.iterdir())
    if not present:
        return []
    try:
        index = json.loads((directory / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return present
    listed = index.get("files") if isinstance(index, dict) else None
    if not isinstance(listed, list):
        return present
    return [name for name in present if name != MARKER and name not in listed]
