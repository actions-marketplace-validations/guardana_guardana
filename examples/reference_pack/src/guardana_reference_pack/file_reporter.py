"""`reference-file://<dir>`: the run's Markdown summary, written to `<dir>/guardana-<run id>.md`.

`prepare` only checks the locator. `deliver` writes through a temporary file in the same
directory, `fsync`s it and moves it into place with `os.replace`, so a reader never sees
half a summary. A directory that does not exist is `unreachable`; an `OSError` while
writing is `rejected`; a run id that cannot name a file is `not_sent`.
"""

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from guardana.core.output import Delivery, DeliveryStatus, ReporterRequest, ReporterSpec
from guardana.core.verify import Verification

from guardana_reference_pack.summary import render

NAME = "reference-file"

_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class LocatorRefusedError(ValueError):
    """A locator `prepare` refuses."""


def spec() -> ReporterSpec:
    """Return the `reference-file` reporter."""
    return ReporterSpec(
        name=NAME,
        summary="the run's Markdown summary, written to a directory as guardana-<run id>.md",
        prepare=prepare,
    )


def prepare(request: ReporterRequest) -> "FileDeliverer":
    """Check the locator names a directory path and return a deliverer; touches nothing.

    Raises `LocatorRefusedError` for an empty locator or one holding a NUL byte.
    """
    locator = request.locator
    if not locator.strip():
        raise LocatorRefusedError(f"no directory: give one after {NAME}://")
    if "\x00" in locator:
        raise LocatorRefusedError("the directory holds a NUL byte")
    directory = Path(locator)
    return FileDeliverer(destination=str(directory), directory=directory)


@dataclass(slots=True)
class FileDeliverer:
    """One prepared directory, ready to receive one run."""

    destination: str
    directory: Path

    def sent_secrets(self) -> tuple[str, ...]:
        """Return nothing: the summary carries no credential of the reporter's own."""
        return ()

    def deliver(self, verification: Verification) -> Delivery:
        """Write the summary and say what became of it."""
        run_id = verification.manifest.run_id
        if _RUN_ID.fullmatch(run_id) is None:
            return Delivery(DeliveryStatus.NOT_SENT, detail="the run id cannot name a file")
        if not self.directory.exists():
            return Delivery(DeliveryStatus.UNREACHABLE, detail="the directory does not exist")
        try:
            _write_atomically(self.directory / f"guardana-{run_id}.md", render(verification))
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            return Delivery(DeliveryStatus.REJECTED, detail=reason, attempts=1)
        return Delivery(DeliveryStatus.DELIVERED, attempts=1)


def _write_atomically(path: Path, text: str) -> None:
    """Write `text` to `path` through a synced temporary file in the same directory."""
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
