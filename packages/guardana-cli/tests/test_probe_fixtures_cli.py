"""`--fixtures` asks the application's own index as each tenant, every tenant on one meter.

The application is `SeededApplication` behind the CLI's transport seam, so every tenant
endpoint `probe`, `plan probe` and `recipe run` build is the one the test counts.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from guardana.cli import _endpoint
from guardana.cli import recipe as recipe_cli
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.fixtures import DOCUMENTS_CHANNEL, Fixtures, load_fixtures
from guardana.core.testing.seeded import SeededApplication, tenant_key
from guardana.rules.seeded.cross_tenant_answer import CrossTenantAnswerRule
from guardana.rules.seeded.poisoned_document import PoisonedDocumentRule
from typer.testing import CliRunner, Result

runner = CliRunner()

TENANCY_CHECK = CrossTenantAnswerRule.meta.id
POISONING_CHECK = PoisonedDocumentRule.meta.id

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_URL = "http://application.test"
_CHECKS = f"include: ['{TENANCY_CHECK}', '{POISONING_CHECK}']"


def normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def _document() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "name": "support-bot",
        "data": "synthetic",
        "tenants": {"acme": {"api_key_env": "ACME_KEY"}, "globex": {"api_key_env": "GLOBEX_KEY"}},
        "documents": [
            {"id": "acme-loyalty", "tenant": "acme", "topic": "the loyalty programme"},
            {
                "id": "acme-returns",
                "tenant": "acme",
                "topic": "returning an order",
                "poisoned": True,
            },
            {"id": "globex-shipping", "tenant": "globex", "topic": "shipping times"},
        ],
        "records": {
            "orders": [
                {"id": "A-100", "tenant": "acme", "fields": {"total": 40}},
                {"id": "G-200", "tenant": "globex", "fields": {"total": 90}},
            ]
        },
    }


@pytest.fixture
def team(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Write a fixtures file and a profile selecting the two checks; set each tenant's key."""
    (tmp_path / "guardana-fixtures.yaml").write_text(
        yaml.safe_dump(_document(), sort_keys=False), encoding="utf-8"
    )
    (tmp_path / "guardana.yaml").write_text(f"rules:\n  {_CHECKS}\n", encoding="utf-8")
    monkeypatch.setenv("ACME_KEY", tenant_key("acme"))
    monkeypatch.setenv("GLOBEX_KEY", tenant_key("globex"))
    return tmp_path


def _serve(
    monkeypatch: pytest.MonkeyPatch,
    team: Path,
    *,
    leaking: frozenset[str] = frozenset(),
    unseeded: frozenset[str] = frozenset(),
) -> SeededApplication:
    fixtures = load_fixtures(team / "guardana-fixtures.yaml")
    application = SeededApplication(fixtures, leaking=leaking, unseeded=unseeded)
    monkeypatch.setattr(_endpoint, "transport_factory", lambda: application)
    return application


def _probe(team: Path, *extra: str) -> tuple[Result, dict[str, Any]]:
    output = team / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            _URL,
            "--model",
            "app",
            "--fixtures",
            str(team / "guardana-fixtures.yaml"),
            "--profile",
            str(team / "guardana.yaml"),
            "--format",
            "json",
            "--output",
            str(output),
            *extra,
        ],
    )
    run: dict[str, Any] = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
    return result, run


def _fixtures(team: Path) -> Fixtures:
    return load_fixtures(team / "guardana-fixtures.yaml")


def test_a_tenant_reading_another_tenants_document_fails_the_probe(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch, team, leaking=frozenset({DOCUMENTS_CHANNEL}))

    result, document = _probe(team)

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    rules = {finding["rule_id"] for finding in document["findings"]}
    assert rules == {TENANCY_CHECK}


def test_a_filter_that_holds_passes_and_the_saved_run_records_the_fixtures(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team)

    result, document = _probe(team)

    assert result.exit_code == ExitCode.OK, result.output
    run = document["run"]
    assert run["fixtures"]["digest"] == _fixtures(team).digest
    assert run["fixtures"]["tenants"] == ["acme", "globex"]
    assert {tenant for tenant, _question in application.asked} == {"acme", "globex"}


def test_the_saved_run_records_what_the_seeded_checks_were_priced_at(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch, team)
    fixtures = _fixtures(team)

    result, document = _probe(team)

    assert result.exit_code == ExitCode.OK, result.output
    declared = {
        rule["id"]: rule["declared_requests"]
        for rule in document["run"]["rules"]
        if rule["id"] in {TENANCY_CHECK, POISONING_CHECK}
    }
    items, tenants, poisoned = len(fixtures.items), len(fixtures.tenant_names), 1
    assert declared == {TENANCY_CHECK: items * tenants, POISONING_CHECK: poisoned}


def test_an_unseeded_item_leaves_the_probe_indeterminate_under_the_default_profile(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch, team, unseeded=frozenset({"documents/globex-shipping"}))

    result, document = _probe(team)

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    kinds = [gap["kind"] for gap in document["run"]["coverage"]["shortfall"]]
    assert "seed_not_reached" in kinds


def test_fixtures_demand_their_checks_so_a_passive_probe_cannot_pass(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team)

    result, document = _probe(team, "--safety", "passive")

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    demanded = [
        gap["name"]
        for gap in document["run"]["coverage"]["shortfall"]
        if gap["kind"] == "demanded_check"
    ]
    assert sorted(demanded) == [POISONING_CHECK, TENANCY_CHECK]
    assert application.asked == []


def test_one_request_budget_bounds_every_tenant_together(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team)

    result, document = _probe(team, "--max-requests", "3")

    assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
    assert len(application.asked) == 3
    assert document["run"]["usage"]["requests"] == 3


def test_the_plan_prices_one_request_per_item_and_tenant_per_trial_and_sends_nothing(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team)
    monkeypatch.delenv("ACME_KEY")
    monkeypatch.delenv("GLOBEX_KEY")
    fixtures = _fixtures(team)

    result = runner.invoke(
        app,
        [
            "plan",
            "probe",
            "--url",
            _URL,
            "--model",
            "app",
            "--fixtures",
            str(team / "guardana-fixtures.yaml"),
            "--profile",
            str(team / "guardana.yaml"),
            "--trials",
            "2",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output
    plan = json.loads(result.stdout)
    items, tenants, poisoned = len(fixtures.items), len(fixtures.tenant_names), 1
    assert plan["requests"]["max"] == (items * tenants + poisoned) * 2
    assert plan["complete"] is True
    assert application.asked == []


def test_the_plan_refuses_fixtures_whose_checks_the_run_would_not_select(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _serve(monkeypatch, team)

    result = runner.invoke(
        app,
        [
            "plan",
            "probe",
            "--url",
            _URL,
            "--model",
            "app",
            "--fixtures",
            str(team / "guardana-fixtures.yaml"),
            "--profile",
            str(team / "guardana.yaml"),
            "--safety",
            "passive",
        ],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert f"{TENANCY_CHECK} is required by this run" in normalised(result.output)


def test_fixtures_beside_an_mcp_server_are_refused(team: Path) -> None:
    result = runner.invoke(
        app,
        ["probe", "--mcp", "http://mcp.test", "--fixtures", str(team / "guardana-fixtures.yaml")],
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "--fixtures" in normalised(result.output)


def test_a_probe_sending_as_one_of_its_tenants_is_refused_before_anything_is_sent(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team)

    result, _ = _probe(team, "--api-key-env", "ACME_KEY")

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "the run's own connection" in normalised(result.output)
    assert application.asked == []


# The recipe: its lock's stand-in carries seeded data, and its run asks as every tenant


@pytest.fixture(autouse=True)
def _pinned_distributions(monkeypatch: pytest.MonkeyPatch) -> None:
    """This checkout installs Guardana itself editable; a user's install is from an index."""
    monkeypatch.setattr(recipe_cli, "moves_under_one_version", lambda _distribution: False)


def _recipe(team: Path) -> Path:
    recipe = team / "guardana-recipe.yaml"
    recipe.write_text(
        "schema_version: 2\n"
        "name: support-bot\n"
        "profile: guardana.yaml\n"
        "subject:\n"
        "  kind: application\n"
        "  fixtures: guardana-fixtures.yaml\n"
        "  connection:\n"
        f"    url: {_URL}\n"
        "    model: app\n",
        encoding="utf-8",
    )
    return recipe


def test_the_lock_pins_the_seeded_checks_because_its_stand_in_carries_seeded_data(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team)
    recipe = _recipe(team)

    result = runner.invoke(app, ["recipe", "lock", str(recipe)])

    assert result.exit_code == ExitCode.OK, result.output
    lock = yaml.safe_load((team / "guardana-recipe.lock.yaml").read_text(encoding="utf-8"))
    assert {TENANCY_CHECK, POISONING_CHECK} <= set(lock["rules"])
    assert application.asked == []


def test_a_recipe_run_asks_as_every_tenant_and_records_its_fixtures(
    team: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _serve(monkeypatch, team, leaking=frozenset({"records/orders"}))
    recipe = _recipe(team)
    assert runner.invoke(app, ["recipe", "lock", str(recipe)]).exit_code == ExitCode.OK

    result = runner.invoke(app, ["recipe", "run", str(recipe)])

    assert result.exit_code == ExitCode.POLICY_FAILED, result.output
    document = json.loads((team / "guardana-artifact" / "run.json").read_text(encoding="utf-8"))
    assert document["run"]["fixtures"]["digest"] == _fixtures(team).digest
    assert {finding["rule_id"] for finding in document["findings"]} == {TENANCY_CHECK}
    assert {tenant for tenant, _question in application.asked} == {"acme", "globex"}
