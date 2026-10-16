#!/usr/bin/env python3
"""Refuse to publish over a file PyPI already holds with different bytes.

Run by `.github/workflows/release.yml` before each upload that skips existing files:

    python scripts/check_pypi_digests.py dist/
    python scripts/check_pypi_digests.py dist-reference/

For every wheel and sdist in the directory, the project and version are read from the
file name, PyPI's JSON API (`https://pypi.org/pypi/<project>/<version>/json`) is asked
which files it already serves, and a file PyPI serves under the same name must carry the
same sha256. A version PyPI does not have yet passes: nothing would be skipped.

It reads the directory and the network (pypi.org), and writes nothing.

Exit codes: 0 every file is new to PyPI or identical to what it serves, 1 a file differs,
2 PyPI could not be read or a file name could not be parsed — never a pass.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

_INDEX = "https://pypi.org/pypi/{project}/{version}/json"
_DIST = re.compile(r"^(?P<project>[A-Za-z0-9_.]+)-(?P<version>[^-]+?)(?:-.*\.whl|\.tar\.gz)$")
_OK, _DIFFERS, _UNCHECKED = 0, 1, 2

Fetch = Callable[[str], dict[str, object] | None]


def _fetch(url: str) -> dict[str, object] | None:
    """Return PyPI's JSON for a release, None when PyPI has no such version."""
    try:
        with urllib.request.urlopen(url, timeout=30) as reply:  # noqa: S310 — a fixed https URL
            loaded: dict[str, object] = json.load(reply)
            return loaded
    except urllib.error.HTTPError as exc:
        if exc.code == 404:  # noqa: PLR2004 — PyPI's "no such version"
            return None
        raise


def _published(document: dict[str, object]) -> dict[str, str]:
    """Map each file PyPI serves for a release to its sha256."""
    urls = document.get("urls")
    served: dict[str, str] = {}
    for entry in urls if isinstance(urls, list) else []:
        if not isinstance(entry, dict):
            continue
        name, digests = entry.get("filename"), entry.get("digests")
        if isinstance(name, str) and isinstance(digests, dict):
            digest = digests.get("sha256")
            if isinstance(digest, str):
                served[name] = digest
    return served


def check(files: Iterable[Path], fetch: Fetch = _fetch) -> int:
    """Compare each built file with the one PyPI serves under its name, printing a line each."""
    outcome = _OK
    releases: dict[tuple[str, str], dict[str, str] | None] = {}
    for path in sorted(files):
        match = _DIST.match(path.name)
        if match is None:
            print(f"NOT CHECKED {path.name}: not a wheel or sdist name this script reads")
            outcome = max(outcome, _UNCHECKED)
            continue
        key = (match["project"], match["version"])
        if key not in releases:
            try:
                document = fetch(_INDEX.format(project=key[0], version=key[1]))
            except (OSError, ValueError) as exc:
                print(f"NOT CHECKED {path.name}: PyPI could not be read ({exc})")
                outcome = max(outcome, _UNCHECKED)
                continue
            releases[key] = None if document is None else _published(document)
        served = releases[key]
        if served is None or path.name not in served:
            print(f"NEW {path.name}")
            continue
        built = hashlib.sha256(path.read_bytes()).hexdigest()
        if built != served[path.name]:
            print(f"DIFFERS {path.name}: PyPI serves sha256 {served[path.name]}, built {built}")
            outcome = max(outcome, _DIFFERS)
        else:
            print(f"SAME {path.name}")
    return outcome


def main(argv: list[str] | None = None) -> int:
    """Parse the arguments and check the directory's distributions against PyPI."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory", type=Path, help="the directory holding the built files")
    arguments = parser.parse_args(argv)
    files = [*arguments.directory.glob("*.whl"), *arguments.directory.glob("*.tar.gz")]
    if not files:
        print(f"NOT CHECKED {arguments.directory}: no wheel or sdist in it")
        return _UNCHECKED
    return check(files)


if __name__ == "__main__":
    sys.exit(main())
