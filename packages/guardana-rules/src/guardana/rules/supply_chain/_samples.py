"""The artifact trees the supply-chain rules sample themselves against.

Each tree is written afresh whenever a rule's fixtures are materialised, so no sample
sees a file another one left behind, and nothing malicious is ever checked in: the
payloads below are bytes and strings a scan reads, never code anything runs.
"""

import io
import json
import zipfile
from collections.abc import Mapping

from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome
from guardana.core.testing import files_target
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES

SOURCE_READ_LIMIT = 256
"""The Python read limit a sample's target is given, so a file past it is a few hundred bytes."""

DECLINED_BY_THE_RULE = (
    "the target could not read the file, and the rule declines it by name as coverage "
    "the run did not get, so the run is indeterminate whatever fail_on_error says"
)


def sample(
    name: str, outcome: FixtureOutcome, files: Mapping[str, bytes | str], note: str = ""
) -> DeclaredFixture:
    """Declare one sample over a fresh tree holding `files`, keyed by relative path."""
    return DeclaredFixture(name, outcome, lambda: files_target(files), note)


def past_the_source_limit(name: str, path: str, tail: str) -> DeclaredFixture:
    """Declare an inconclusive sample whose `path` runs past the target's read limit.

    `tail` lies beyond the limit, so the target leaves the file unread and the rule
    reports it as an unscanned component rather than passing over it.
    """
    padded = b"#" * SOURCE_READ_LIMIT + b"\n" + tail.encode()
    return DeclaredFixture(
        name,
        FixtureOutcome.INCONCLUSIVE,
        lambda: files_target({path: padded}, source_read_limit=SOURCE_READ_LIMIT),
        DECLINED_BY_THE_RULE,
    )


def past_the_scan_bound(tail: str, *, bound: int = MAX_SCAN_BYTES) -> bytes:
    """Return a text file longer than a rule's read bound, with `tail` past it."""
    return b" " * bound + b"\n" + tail.encode()


def keras_archive(layers: list[dict[str, object]]) -> bytes:
    """Build a `.keras` zip whose `config.json` declares a sequential model of `layers`."""
    config = {"class_name": "Sequential", "config": {"name": "sample", "layers": layers}}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("config.json", json.dumps(config))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
    return buffer.getvalue()


def notebook(*cells: str) -> str:
    """Build an `.ipynb` document holding one code cell per source string."""
    return json.dumps(
        {
            "cells": [
                {"cell_type": "code", "metadata": {}, "outputs": [], "source": source}
                for source in cells
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )
