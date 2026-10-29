"""A digest of what a profile asks for, the same on every machine that reads the same file.

Recorded in a saved run so a narrowed profile named like a preset no longer reads as
the preset. It covers the settings, not the files they point to: a rule directory's
contents are recorded per rule, by digest, in the manifest's rule records.
"""

import json
from collections.abc import Mapping
from dataclasses import Field, fields, is_dataclass
from datetime import date, time
from enum import Enum
from pathlib import Path, PurePath

from guardana.core.fingerprint import digest_of
from guardana.core.profile.model import Profile
from guardana.core.redaction import OMITTED_WHEN_DEFAULT

_FORMAT = "profile-v1"
"""Part of every digest, so a change to what is covered changes every digest with it."""

_LEFT_OUT = frozenset({"name", "source", "plugins", "delivery_required"})
"""Not what the profile asks of a run: its label, where it was read from, the trust a flag
can replace whole (the manifest records the trust in force on its own), and whether its
deliveries must be acknowledged, which is decided after the verdict."""

_PATHS_BESIDE_THE_PROFILE = frozenset({"rule_paths", "calibration_paths", "contract_paths"})


def profile_digest(profile: Profile) -> str:
    """Return an algorithm-qualified digest of every setting `profile` applies to a run.

    Relative entries are digested as written in the file, so `--profile ci/guardana.yaml`
    and the same file read from inside `ci/` agree. A value of a type this cannot encode
    raises `TypeError` rather than being skipped.
    """
    body = {
        member.name: _encode(_as_written(profile, member.name))
        for member in fields(profile)
        if member.name not in _LEFT_OUT
    }
    return digest_of(_FORMAT, json.dumps(body, sort_keys=True, separators=(",", ":")))


def _as_written(profile: Profile, name: str) -> object:
    """Undo the loader's anchoring of relative entries to the profile's directory."""
    value = getattr(profile, name)
    if name not in _PATHS_BESIDE_THE_PROFILE or profile.source is None:
        return value
    parent = str(profile.source.parent)
    prefix = f"{parent}{'/' if not parent.endswith('/') else ''}"
    return tuple(
        entry[len(prefix) :] if parent != "." and entry.startswith(prefix) else entry
        for entry in value
    )


def _encode(value: object) -> object:  # noqa: PLR0911 — one branch per JSON shape
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Enum):
        return f"{type(value).__name__}.{value.name}"
    if is_dataclass(value) and not isinstance(value, type):
        return {
            member.name: _encode(getattr(value, member.name))
            for member in fields(value)
            if not _omitted(member, getattr(value, member.name))
        }
    if isinstance(value, Mapping):
        return {str(key): _encode(item) for key, item in value.items()}
    if isinstance(value, frozenset | set):
        return sorted(
            (_encode(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True)
        )
    if isinstance(value, tuple | list):
        return [_encode(item) for item in value]
    if isinstance(value, date | time):
        return value.isoformat()
    if isinstance(value, PurePath | Path):
        return value.as_posix()
    raise TypeError(f"cannot digest a profile value of type {type(value).__name__}")


def _omitted(member: "Field[object]", value: object) -> bool:
    """Whether a field marked `OMITTED_WHEN_DEFAULT` holds its default and stays out."""
    return bool(member.metadata.get(OMITTED_WHEN_DEFAULT)) and value == member.default
