"""`guardana taxonomy` — the only way an author finds out what to write.

Without it, learning that a rule must say `LLM01:2025` rather than `LLM01` means
reading the engine's source. The listing also prints the catalogue digests a run
manifest pins, which is what lets somebody check a three-year-old report against a
build without asking anybody to remember which edition was installed.
"""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import EXPLODING_MODULE, MARKING_MODULE, FakeSite
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.entrypoints import EVALUATOR_GROUP, RULE_GROUP, TARGET_GROUP, TAXONOMY_GROUP
from guardana.core.taxonomy import TaxonomyRef, register
from guardana.core.taxonomy._builtin import index as _taxonomy_registry
from typer.testing import CliRunner

runner = CliRunner()


def test_the_listing_names_both_editions_and_their_digests() -> None:
    result = runner.invoke(app, ["taxonomy"])

    assert result.exit_code == 0, result.output
    assert "OWASP-LLM-2025" in result.output
    assert "OWASP-LLM-2026" in result.output
    assert "LLM07:2025" in result.output
    assert result.output.count("digest sha256:") >= 6


def test_one_reference_prints_what_it_corresponds_to_today() -> None:
    result = runner.invoke(app, ["taxonomy", "LLM07:2025"])

    assert result.exit_code == 0, result.output
    assert "System Prompt Leakage" in result.output
    assert "LLM08:2026 Hidden Context Exposure (broader)" in result.output
    # Never the matching number: LLM07:2026 is Misinformation.
    assert "LLM07:2026" not in result.output


def test_an_under_specified_reference_names_every_candidate() -> None:
    result = runner.invoke(app, ["taxonomy", "LLM01"])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "LLM01:2025" in result.output
    assert "LLM01:2026" in result.output


def test_an_unknown_reference_says_so_rather_than_printing_nothing() -> None:
    result = runner.invoke(app, ["taxonomy", "LLM99:2025"])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "no installed catalogue defines" in result.output


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def _install(site: FakeSite, group: str) -> None:
    site.distribution("acme-pack", (group, "acme", site.module(MARKING_MODULE).name))


@pytest.mark.parametrize("trust", [[], ["--plugins", "disabled"]], ids=["default", "disabled"])
def test_a_refused_taxonomy_provider_makes_a_miss_unproven_rather_than_absent(
    site: FakeSite, trust: list[str]
) -> None:
    """The catalogue that would have defined the reference may be exactly the one refused."""
    _install(site, TAXONOMY_GROUP)

    result = runner.invoke(app, ["taxonomy", "LLM99:2025", *trust])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "no installed catalogue" not in result.output
    assert "no loaded catalogue" in result.stderr
    assert "1 provider(s) were refused by plugin trust" in " ".join(result.stderr.split())


@pytest.mark.parametrize("group", [RULE_GROUP, EVALUATOR_GROUP, TARGET_GROUP])
def test_a_refused_pack_that_provides_no_taxonomy_leaves_a_typo_a_usage_error(
    site: FakeSite, group: str
) -> None:
    """Only a refused `guardana.taxonomies` provider could have defined the reference."""
    _install(site, group)

    result = runner.invoke(app, ["taxonomy", "LLM99:2025"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "no installed catalogue defines" in result.output
    assert "refused by plugin trust" not in result.output


def test_a_taxonomy_provider_that_fails_to_import_makes_a_miss_unproven_rather_than_absent(
    site: FakeSite,
) -> None:
    """Admitted and broken is no more proof of absence than refused."""
    site.distribution("acme-pack", (TAXONOMY_GROUP, "acme", site.module(EXPLODING_MODULE).name))

    result = runner.invoke(app, ["taxonomy", "LLM99:2025", "--plugins", "all"])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "no installed catalogue" not in result.output
    stderr = " ".join(result.stderr.split())
    assert "1 provider(s) failed to load" in stderr
    assert "refused by plugin trust" not in stderr


@pytest.mark.parametrize("group", [RULE_GROUP, EVALUATOR_GROUP, TARGET_GROUP])
def test_a_failed_pack_that_provides_no_taxonomy_leaves_a_typo_a_usage_error(
    site: FakeSite, group: str
) -> None:
    """Only a `guardana.taxonomies` provider that did not load could have defined the reference."""
    site.distribution("acme-pack", (group, "acme", site.module(EXPLODING_MODULE).name))

    result = runner.invoke(app, ["taxonomy", "LLM99:2025", "--plugins", "all"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "no installed catalogue defines" in result.output
    assert "may be theirs" not in result.output


def test_the_json_form_carries_the_edition_as_its_own_field() -> None:
    result = runner.invoke(app, ["taxonomy", "LLM08:2026", "--format", "json"])

    payload = json.loads(result.output)

    assert payload["scheme"] == "OWASP-LLM"
    assert payload["edition"] == "2026"
    assert payload["framework"] == "OWASP-LLM-2026"
    assert payload["corresponds_to"] == [
        {
            "reference": "LLM07:2025",
            "framework": "OWASP-LLM-2025",
            "title": "System Prompt Leakage",
            "relation": "narrower",
            "note": (
                "renamed and widened past the system prompt to tool schemas, retrieved "
                "content and credentials embedded in context"
            ),
        }
    ]


def test_the_catalogue_listing_is_machine_readable() -> None:
    result = runner.invoke(app, ["taxonomy", "--format", "json"])

    catalogues = {entry["framework"]: entry for entry in json.loads(result.output)}

    assert catalogues["MITRE-ATLAS"]["edition"] is None
    assert catalogues["MITRE-ATLAS"]["version"] == "5.6.0"
    assert catalogues["OWASP-LLM-2026"]["edition"] == "2026"
    assert len(catalogues["OWASP-LLM-2026"]["entries"]) == 10


@pytest.fixture
def acme_control() -> Iterator[TaxonomyRef]:
    """Register one reference the way an installed pack does, then take it back.

    Global by nature — a taxonomy registry is process-wide, because a rule resolves
    its mapping against whatever is installed — so the removal is the fixture's
    whole job.
    """
    ref = TaxonomyRef("ACME-CONTROLS-1", "ACME-14", "Model change control")
    register(ref)
    yield ref
    _taxonomy_registry.forget("ACME-14")


def test_the_listing_shows_a_reference_an_installed_package_registered(
    acme_control: TaxonomyRef,
) -> None:
    """The listing did discovery and then printed the built-ins, which are not the same set.

    A company that installs its own control catalogue runs this command to confirm
    the pack is there and was told, in effect, that it is not. Nothing had ever
    registered through `guardana.taxonomies`, so the one command that would have
    shown the gap had nothing to show it with.
    """
    result = runner.invoke(app, ["taxonomy"])

    assert result.exit_code == 0, result.output
    assert "ACME-CONTROLS-1" in result.output
    assert "ACME-14" in result.output
    assert "Model change control" in result.output


def test_a_package_registered_reference_carries_no_catalogue_digest(
    acme_control: TaxonomyRef,
) -> None:
    """Visible, and not pretending to provenance it has not got.

    A digest is what a run manifest pins so a report stays checkable years later.
    A package registers references rather than a catalogue file, so there is
    nothing to hash — and `null` is how a script tells the two apart without a
    flag being invented for it.
    """
    listing = {
        entry["framework"]: entry
        for entry in json.loads(runner.invoke(app, ["taxonomy", "--format", "json"]).output)
    }

    assert listing["ACME-CONTROLS-1"]["digest"] is None
    assert listing["ACME-CONTROLS-1"]["entries"] == [
        {"reference": "ACME-14", "id": "ACME-14", "rank": None, "title": "Model change control"}
    ]
    assert listing["OWASP-LLM-2026"]["digest"] is not None
