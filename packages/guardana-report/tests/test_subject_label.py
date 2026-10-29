"""A run a recipe started says what answered, first, in the terminal and in the CI test view."""

from dataclasses import replace
from xml.etree.ElementTree import fromstring

import pytest
from guardana.core.manifest import (
    FixturesRecord,
    RecipeRecord,
    RunManifest,
    SubjectKind,
    SubjectSource,
)
from guardana.core.report import ScanResult
from guardana.core.testing import manifest_for
from guardana.report import get_renderer

_DIGEST = "sha256:" + "ab" * 32


def _result() -> ScanResult:
    return ScanResult((), ("acme.r",), ())


def _run(kind: SubjectKind | None) -> RunManifest:
    run = manifest_for(_result())
    if kind is None:
        return run
    recipe = RecipeRecord(
        name="support-bot",
        digest=_DIGEST,
        lock_digest=_DIGEST,
        kind=kind,
        source=SubjectSource.CONNECTION,
    )
    return replace(run, recipe=recipe)


def test_a_model_harness_run_says_so_on_its_first_line() -> None:
    rendered = get_renderer("human", run=_run(SubjectKind.MODEL_HARNESS)).render(_result())

    first = rendered.splitlines()[0]
    assert first.startswith("subject: model harness, from a connection — recipe support-bot")
    assert "without the application" in first


@pytest.mark.parametrize(
    ("kind", "name"),
    [
        (SubjectKind.MODEL_HARNESS, "guardana (model harness)"),
        (SubjectKind.APPLICATION, "guardana (application)"),
        (None, "guardana"),
    ],
)
def test_the_junit_suite_is_named_after_what_answered(kind: SubjectKind | None, name: str) -> None:
    rendered = get_renderer("junit", run=_run(kind)).render(_result())

    assert fromstring(rendered).get("name") == name  # noqa: S314 — our own output


def test_a_run_no_recipe_started_prints_no_subject_line() -> None:
    rendered = get_renderer("human", run=_run(None)).render(_result())

    assert not rendered.startswith("subject:")


def test_a_run_given_fixtures_names_them_and_what_they_declare() -> None:
    fixtures = FixturesRecord(
        name="support-bot",
        digest=_DIGEST,
        data="synthetic",
        tenants=("acme", "globex"),
        documents=3,
        records=2,
        tools=0,
        markers=1,
    )
    run = replace(_run(SubjectKind.APPLICATION), fixtures=fixtures)

    rendered = get_renderer("human", run=run).render(_result()).splitlines()
    plain = get_renderer("human", run=_run(None)).render(_result())

    assert rendered[1] == (
        "fixtures: support-bot (data: synthetic, as declared); tenants acme, globex; "
        "3 document(s), 2 record(s), 0 tool(s)"
    )
    assert "fixtures:" not in plain
