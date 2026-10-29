"""`guardana fixtures render` writes what a team seeds, or exits 3 and writes nothing."""

import json
from pathlib import Path

import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.fixtures import load_fixtures
from typer.testing import CliRunner

runner = CliRunner()


def _fixtures(tmp_path: Path, **changes: object) -> Path:
    document: dict[str, object] = {
        "schema_version": 1,
        "name": "support-bot",
        "data": "synthetic",
        "tenants": {"acme": {"api_key_env": "ACME_KEY"}, "globex": {"api_key_env": "GLOBEX_KEY"}},
        "documents": [
            {"id": "acme-returns", "tenant": "acme", "topic": "returns", "poisoned": True},
            {"id": "globex-shipping", "tenant": "globex", "topic": "shipping times"},
        ],
        **changes,
    }
    path = tmp_path / "guardana-fixtures.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def test_render_writes_documents_jsonl_for_the_teams_ingestion(tmp_path: Path) -> None:
    path = _fixtures(tmp_path)
    out = tmp_path / "seed" / "nested"

    result = runner.invoke(app, ["fixtures", "render", str(path), "--out", str(out)])

    assert result.exit_code == ExitCode.OK, result.output
    lines = [json.loads(line) for line in (out / "documents.jsonl").read_text().splitlines()]
    loaded = load_fixtures(path)
    assert lines == [{"id": d.id, "tenant": d.owner, "text": d.text} for d in loaded.documents]
    assert loaded.documents[0].markers.presence in lines[0]["text"]
    assert "2 document(s), 1 poisoned" in " ".join(result.output.split())


def test_render_replaces_an_earlier_rendering_whole(tmp_path: Path) -> None:
    out = tmp_path / "seed"
    out.mkdir()
    (out / "documents.jsonl").write_text('{"id": "stale"}\n' * 10, encoding="utf-8")

    result = runner.invoke(app, ["fixtures", "render", str(_fixtures(tmp_path)), "--out", str(out)])

    assert result.exit_code == ExitCode.OK, result.output
    assert "stale" not in (out / "documents.jsonl").read_text()
    assert sorted(p.name for p in out.iterdir()) == ["documents.jsonl"]


def test_a_refused_file_exits_3_and_writes_nothing(tmp_path: Path) -> None:
    path = _fixtures(tmp_path, data="production")
    out = tmp_path / "seed"

    result = runner.invoke(app, ["fixtures", "render", str(path), "--out", str(out)])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "`data` must be `synthetic`" in " ".join(result.output.split())
    assert not out.exists()


def test_render_without_out_is_refused_as_usage(tmp_path: Path) -> None:
    result = runner.invoke(app, ["fixtures", "render", str(_fixtures(tmp_path))])

    assert result.exit_code == ExitCode.INVALID_USAGE
