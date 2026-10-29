"""`guardana fixtures render` — the documents a team seeds into its own index, markers included."""

import os
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.fixtures import FIXTURES_NAME, FixturesError, load_fixtures, render_documents

fixtures_app = typer.Typer(
    help="Declare the synthetic data an application runs with, and render what the team seeds.",
    no_args_is_help=True,
)

DOCUMENTS_FILE = "documents.jsonl"


def render(
    out: Annotated[
        Path, typer.Option("--out", help="The directory to write documents.jsonl into.")
    ],
    file: Annotated[Path, typer.Argument(help="The fixtures file.")] = Path(FIXTURES_NAME),
) -> None:
    """Write DIR/documents.jsonl (`id`, `tenant`, `text`) for the team's own ingestion.

    Each document's text carries its retrieval term and presence marker, and a poisoned
    one its instruction; they are derived from the item as declared, so seed again after
    any edit. Nothing is sent and no key is read.
    """
    try:
        fixtures = load_fixtures(file)
        text = render_documents(fixtures)
    except FixturesError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    target = out / DOCUMENTS_FILE
    try:
        out.mkdir(parents=True, exist_ok=True)
        _write_atomically(target, text)
    except OSError as exc:
        typer.echo(f"error: cannot write {target}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    poisoned = sum(1 for item in fixtures.documents if item.poisoned)
    typer.echo(
        f"wrote {target}: {len(fixtures.documents)} document(s), {poisoned} poisoned, for "
        f"{len(fixtures.tenants)} tenant(s); seed them into the application's own index"
    )


def _write_atomically(path: Path, text: str) -> None:
    """Replace `path` whole, so an index never ingests half a rendering."""
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


fixtures_app.command(name="render")(render)
