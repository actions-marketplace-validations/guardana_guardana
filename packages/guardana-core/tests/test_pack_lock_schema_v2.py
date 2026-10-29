"""Lock schema 2: every digest sits one level below the id it pins.

Schema 1 wrote `<rule id>: <hex>` on one line. A rule id may say `secret`, `key` or
`token`, and a secret scanner reads a keyword beside a high-entropy value as a
credential, so a repository keeping the lock failed its own secret scan. Schema 2
writes `<id>: {digest: <hex>}` for rules and catalogues alike, and schema 1 is still
read, migrated in memory, so a teammate's older lock keeps gating.
"""

import re
from typing import Any

import pytest
import yaml
from guardana.core.pack.lock import (
    LOCK_SCHEMA_VERSION,
    Installed,
    Lock,
    catalogue_digest,
    lock_from_dict,
    lock_of,
    lock_to_dict,
)
from guardana.core.pack.model import ApiRange as Range
from guardana.core.pack.model import PackError, PackManifest
from guardana.core.taxonomy import TaxonomyRef

_RULE = "acme.output.api_secret_token_key"
_CATALOGUE = "ACME-SECRET-KEYS"
_REF = TaxonomyRef(scheme=_CATALOGUE, id="ASK-1", title="Keys stay out of replies")

_ID_BESIDE_A_DIGEST = re.compile(
    r"^\s*(?!digest:)[^\s:]+:\s+['\"]?(sha256:)?[0-9a-f]{12,}['\"]?\s*$"
)
"""A line pairing an id with a high-entropy value, which is what a secret scanner flags."""


def _lock() -> Lock:
    manifest = PackManifest(
        name="acme-guardana-rules",
        extension_api=Range(minimum=1, below=2),
        source="guardana-pack.yaml",
        rules=(_RULE,),
        taxonomies=(_CATALOGUE,),
    )
    installed = Installed(
        rules={_RULE: "5f81dbb2a6b93970"},
        catalogues={_CATALOGUE: catalogue_digest([_REF])},
    )
    return lock_of([("acme-guardana-rules", "0.3.1", manifest)], installed)


def _written(lock: Lock) -> str:
    return yaml.safe_dump(lock_to_dict(lock), sort_keys=False)


def _as_schema_1(document: dict[str, Any]) -> dict[str, Any]:
    """The same lock in the flat layout the previous schema wrote."""
    flat: dict[str, Any] = yaml.safe_load(yaml.safe_dump(document))
    flat["schema_version"] = 1
    for pack in flat["packs"]:
        for group in ("rules", "taxonomies"):
            pack[group] = {name: entry["digest"] for name, entry in pack[group].items()}
    return flat


def test_a_written_lock_puts_no_id_on_the_same_line_as_a_digest() -> None:
    text = _written(_lock())

    offending = [line for line in text.splitlines() if _ID_BESIDE_A_DIGEST.match(line)]

    assert not offending, "lines a secret scanner reads as a credential:\n" + "\n".join(offending)
    assert "5f81dbb2a6b93970" in text, "the rule digest is not in the lock at all"
    assert catalogue_digest([_REF]) in text, "the catalogue digest is not in the lock at all"


def test_the_flat_layout_is_what_the_line_check_catches() -> None:
    """The inversion: the check above has to fire on the layout it replaced."""
    text = yaml.safe_dump(_as_schema_1(lock_to_dict(_lock())), sort_keys=False)

    assert any(_ID_BESIDE_A_DIGEST.match(line) for line in text.splitlines())


def test_a_written_lock_nests_rules_and_catalogues_under_digest() -> None:
    document = lock_to_dict(_lock())

    assert document["schema_version"] == 2
    (pack,) = document["packs"]
    assert pack["rules"] == {_RULE: {"digest": "5f81dbb2a6b93970"}}
    assert pack["taxonomies"] == {_CATALOGUE: {"digest": catalogue_digest([_REF])}}


def test_a_schema_2_lock_reads_back_exactly_and_says_it_was_not_migrated() -> None:
    restored = lock_from_dict(yaml.safe_load(_written(_lock())), "guardana-lock.yaml")

    assert restored == _lock()
    assert restored.migrated_from is None


def test_a_schema_1_lock_reads_as_the_same_lock_and_records_the_migration() -> None:
    restored = lock_from_dict(_as_schema_1(lock_to_dict(_lock())), "guardana-lock.yaml")

    assert restored.migrated_from == 1
    assert restored.schema_version == 2
    assert restored.packs == _lock().packs
    assert restored.unlocked == _lock().unlocked
    assert restored.extension_api == _lock().extension_api


def test_a_lock_from_a_newer_guardana_says_upgrade_and_never_regenerate() -> None:
    """Regenerating would overwrite a teammate's newer lock with an older layout."""
    document = lock_to_dict(_lock())
    document["schema_version"] = LOCK_SCHEMA_VERSION + 1

    with pytest.raises(PackError) as refused:
        lock_from_dict(document, "guardana-lock.yaml")

    assert "newer Guardana" in str(refused.value)
    assert "upgrade" in str(refused.value)
    assert "regenerate" not in str(refused.value)


@pytest.mark.parametrize("version", [0, -1])
def test_a_lock_version_nobody_wrote_keeps_the_regenerate_refusal(version: int) -> None:
    document = lock_to_dict(_lock())
    document["schema_version"] = version

    with pytest.raises(PackError, match="regenerate it"):
        lock_from_dict(document, "guardana-lock.yaml")


@pytest.mark.parametrize(
    "entry",
    [
        "5f81dbb2a6b93970",
        {},
        {"digest": 7},
        {"digest": "5f81dbb2a6b93970", "algorithm": "sha256"},
    ],
)
def test_a_schema_2_entry_that_is_not_exactly_a_digest_is_refused(entry: object) -> None:
    """A flat value under schema 2 is a layout mismatch, not a digest to trust."""
    document = lock_to_dict(_lock())
    document["packs"][0]["rules"][_RULE] = entry

    with pytest.raises(PackError, match="digest"):
        lock_from_dict(document, "guardana-lock.yaml")


def test_a_schema_1_lock_with_a_nested_entry_is_refused() -> None:
    document = _as_schema_1(lock_to_dict(_lock()))
    document["packs"][0]["rules"][_RULE] = {"digest": "5f81dbb2a6b93970"}

    with pytest.raises(PackError, match="digest"):
        lock_from_dict(document, "guardana-lock.yaml")
