import json
from pathlib import Path

import pytest
from guardana.core.rule import RuleLoadError
from guardana.core.severity import Severity
from guardana.rules.supply_chain._advisories import ADVISORY_KINDS, load_advisories, version_matches


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_bundled_dataset_loads() -> None:
    advisories = load_advisories()
    assert advisories
    assert {advisory.package for advisory in advisories} >= {"ultralytics", "transformers"}


def test_every_bundled_advisory_is_sourced_and_typed() -> None:
    # An advisory nobody can check is an assertion, not evidence.
    for advisory in load_advisories():
        assert advisory.reference.startswith("https://"), advisory.id
        assert advisory.kind in ADVISORY_KINDS, advisory.id
        assert advisory.versions, advisory.id


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ("8.3.41", "8.3.41", True),
        ("8.3.41", "8.3.410", False),
        ("<5.3.0", "4.57.0", True),
        ("<5.3.0", "5.3.0", False),
        ("<5.3.0", "5.4.1", False),
        (">=3.0.0,<3.11.3", "3.10.0", True),
        (">=3.0.0,<3.11.3", "2.15.0", False),
        (">=3.0.0,<3.11.3", "3.11.3", False),
        ("*", "0.0.1", True),
        ("<2.6.0", "2.6.0rc1", False),
        ("<5.3.0", "not-a-version", False),
    ],
)
def test_version_matching(spec: str, version: str, expected: bool) -> None:
    assert version_matches(spec, version) is expected


def test_a_malformed_dataset_fails_loudly(tmp_path: Path) -> None:
    # A dataset that silently loads as empty would turn a blocklist into a
    # rubber stamp — exactly the gate-you-think-you-configured failure.
    path = tmp_path / "advisories.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="advisor"):
        load_advisories(path)


def test_an_unknown_key_is_rejected(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "X",
                "package": "p",
                "kind": "malicious_release",
                "versions": ["1.0"],
                "severity": "high",
                "summary": "s",
                "reference": "https://example.invalid",
                "typo": 1,
            }
        ],
    }
    with pytest.raises(RuleLoadError, match="typo"):
        load_advisories(_write(tmp_path, document))


def test_an_unknown_kind_is_rejected(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "X",
                "package": "p",
                "kind": "rumour",
                "versions": ["1.0"],
                "severity": "high",
                "summary": "s",
                "reference": "https://example.invalid",
            }
        ],
    }
    with pytest.raises(RuleLoadError, match="kind"):
        load_advisories(_write(tmp_path, document))


def test_a_future_schema_version_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleLoadError, match="schema_version"):
        load_advisories(_write(tmp_path, {"schema_version": 99, "advisories": []}))


def test_a_bad_severity_is_rejected(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "X",
                "package": "p",
                "kind": "malicious_release",
                "versions": ["1.0"],
                "severity": "apocalyptic",
                "summary": "s",
                "reference": "https://example.invalid",
            }
        ],
    }
    with pytest.raises(RuleLoadError, match="severity"):
        load_advisories(_write(tmp_path, document))


def test_a_valid_custom_dataset_loads(tmp_path: Path) -> None:
    document = {
        "schema_version": 1,
        "advisories": [
            {
                "id": "ACME-1",
                "package": "acme-ml",
                "kind": "malicious_release",
                "versions": ["1.0"],
                "severity": "critical",
                "summary": "s",
                "reference": "https://example.invalid",
            }
        ],
    }
    advisories = load_advisories(_write(tmp_path, document))
    assert advisories[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "not a JSON object"),
        ({"schema_version": 1, "advisories": {}}, "must be a list"),
        ({"schema_version": 1, "advisories": [42]}, "must be an object"),
        ({"schema_version": 1, "advisories": [{"id": "X", "package": "p"}]}, "missing"),
        (
            {
                "schema_version": 1,
                "advisories": [
                    {
                        "id": "X",
                        "package": "p",
                        "kind": "malicious_release",
                        "versions": [],
                        "severity": "high",
                        "summary": "s",
                        "reference": "https://example.invalid",
                    }
                ],
            },
            "non-empty list",
        ),
    ],
)
def test_a_dataset_we_cannot_fully_understand_is_refused(
    tmp_path: Path, document: object, message: str
) -> None:
    with pytest.raises(RuleLoadError, match=message):
        load_advisories(_write(tmp_path, document))


def test_an_unparseable_comparator_bound_never_matches() -> None:
    assert version_matches("<not.a.version", "1.0.0") is False
    assert version_matches("~=1.0", "1.0") is False


@pytest.mark.parametrize(
    ("spec", "version"),
    [
        ("8.3.41", "8.3.041"),
        ("8.3.41", "8.3.41.0"),
        ("8.3.41", "8.3.41.0.0"),
        ("8.3.41", "08.03.41"),
        ("8.3.41", "v8.3.41"),
        ("8.3.41", "V8.3.41"),
        ("8.3.41", "0!8.3.41"),
        ("8.3.41", " 8.3.41 "),
        ("1.0rc1", "1.0.0-rc.1"),
        ("1.0rc1", "1.0c1"),
        ("1.0rc1", "1.0.0pre1"),
        ("1.0rc1", "1.0preview1"),
        ("1.0a0", "1.0alpha"),
        ("1.0b2", "1.0-beta-2"),
        ("1.0.post1", "1.0-1"),
        ("1.0.post1", "1.0.rev1"),
        ("1.0.post0", "1.0.post"),
        ("1.0.dev0", "1.0dev"),
        ("1.0.dev3", "1.0-DEV-3"),
        ("1!2.0", "1!2.0.0"),
    ],
)
def test_an_exact_advisory_version_matches_every_spelling_pip_treats_as_equal(
    spec: str, version: str
) -> None:
    assert version_matches(spec, version) is True


@pytest.mark.parametrize(
    ("spec", "version"),
    [
        ("8.3.41", "8.3.4"),
        ("8.3.41", "8.3.410"),
        ("8.3.41", "8.3.41.1"),
        ("8.3.41", "8.3.41rc1"),
        ("8.3.41", "8.3.41.post1"),
        ("8.3.41", "8.3.41.dev0"),
        ("8.3.41", "1!8.3.41"),
        ("1.0rc1", "1.0rc2"),
        ("1.0rc1", "1.0b1"),
        ("8.3.41", "8.3.41-foo"),
        ("8.3.41", ""),
    ],
)
def test_an_exact_advisory_version_does_not_match_a_different_release(
    spec: str, version: str
) -> None:
    assert version_matches(spec, version) is False


def test_a_local_label_on_the_pin_is_the_same_public_release_and_is_reported() -> None:
    # A locally built `8.3.41+cpu` carries the source of the compromised public release.
    assert version_matches("8.3.41", "8.3.41+cpu") is True
    assert version_matches("8.3.41", "8.3.41+ubuntu.1") is True


def test_a_local_label_on_the_advisory_matches_only_that_build() -> None:
    assert version_matches("8.3.41+cpu", "8.3.41+CPU") is True
    assert version_matches("8.3.41+ubuntu.1", "8.3.41+ubuntu-01") is True
    assert version_matches("8.3.41+cpu", "8.3.41") is False
    assert version_matches("8.3.41+cpu", "8.3.41+cu121") is False


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ("8.3.41", "8.3.41", True),
        ("1.0rc1", "1.0RC1", True),
        ("8.3.41", "8.3.041", False),
        ("8.3.41", "8.3.41.0", False),
        ("8.3.41", "v8.3.41", False),
        ("<9.0", "8.3.41", True),
        ("<9.0", "9.0.0", False),
        ("<9.0", "not-a-version", False),
    ],
)
def test_arbitrary_equality_compares_the_literal_string(
    spec: str, version: str, expected: bool
) -> None:
    assert version_matches(spec, version, arbitrary=True) is expected


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ("<0.2.72", "0.2.071", True),
        ("<0.2.72", "0.2.072", False),
        ("<0.2.72", "0.2.72.0", False),
        ("<=0.2.72", "0.2.72.0", True),
        (">=3.0.0,<3.11.3", "3", True),
        (">=3.0.0,<3.11.3", "v3.11.2", True),
        ("<2.6.0", "0!2.5.1", True),
        ("<2.6.0", "1!1.0", False),
        ("<2.6.0", "2.5.1+cpu", True),
        ("<2.6.0", "2.5.0rc1", True),
        ("<2.6.0", "2.5.1.post3", True),
        ("<2.6.0", "2.6.0.dev1", False),
        ("<=2.6.0", "2.6.0rc1", True),
        ("<=2.6.0", "2.6.0.post1", False),
        (">=2.6.0", "2.6.0rc1", False),
        (">=2.6.0", "2.6.0.post1", True),
        (">2.6.0", "2.6.0.post1", False),
        (">2.6.0", "2.6.1a1", True),
        ("<2.6.0rc1", "2.5.0", True),
        ("<2.6.0rc1", "2.6.0a1", True),
        ("<2.6.0rc2", "2.6.0rc1", True),
        (">1.0.post1", "1.0.post2", True),
        ("<2.6.0.post2", "2.6.0rc1", True),
        (">1.0a1", "1.0a1.post1", False),
        ("<=2.6.0rc1", "2.6.0a1", True),
        ("<2.6.0+cpu", "2.5.0", False),
    ],
)
def test_comparators_order_versions_as_pep_440_does(
    spec: str, version: str, expected: bool
) -> None:
    assert version_matches(spec, version) is expected


def test_an_exact_version_pep_440_cannot_read_matches_only_the_same_text() -> None:
    assert version_matches("1.0.0-custom", "1.0.0-CUSTOM")
    assert not version_matches("1.0.0-custom", "1.0.0-other")
