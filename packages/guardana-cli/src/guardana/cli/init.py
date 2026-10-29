"""`guardana init`: a starter policy file, or a starter project to scan, fix and rescan."""

import importlib.resources
import json
import struct
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from guardana.cli.exit_codes import ExitCode

_TEMPLATE = """\
name: default
rules:
  include: ["guardana.*"]
fail_on:
  severity: high
  min_confidence: 0.0
"""

_DEFAULT_POLICY = Path("guardana.yaml")

_STARTER_MESSAGE = "Guardana starter: loading this file would have run code."


def init(
    path: Annotated[
        Path | None,
        typer.Argument(help="Where to write the policy file; default guardana.yaml"),
    ] = None,
    starter: Annotated[
        Path | None,
        typer.Option(
            "--starter",
            help="Write a starter project into this new or empty directory instead",
        ),
    ] = None,
) -> None:
    """Write a starter guardana.yaml policy file, or with --starter a project to try."""
    if starter is not None:
        if path is not None:
            raise typer.BadParameter("pass either a path or --starter, not both")
        _write_starter(starter)
        return
    target = path if path is not None else _DEFAULT_POLICY
    if target.exists():
        typer.echo(f"{target} already exists; not overwriting.")
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    target.write_text(_TEMPLATE)
    typer.echo(f"Wrote {target}")


def _starter_files() -> dict[str, bytes]:
    """Return every file of the starter project, keyed by its path inside the directory."""
    return {
        "README.md": _template("README.md.tmpl"),
        "checks/codename.yaml": _template("codename.yaml.tmpl"),
        "model/weights.pkl": _planted_pickle(),
        "safe/weights.safetensors": _clean_safetensors(),
    }


def _planted_pickle() -> bytes:
    """Build a pickle whose loading calls `builtins.print` and nothing else.

    Built from opcodes at run time so no pickle file ships inside the package, where
    the project's own scan of its sources would flag it.
    """
    message = _STARTER_MESSAGE.encode("utf-8")
    return (
        b"\x80\x02"  # PROTO 2
        + b"cbuiltins\nprint\n"  # GLOBAL
        + b"X"  # BINUNICODE
        + struct.pack("<I", len(message))
        + message
        + b"\x85"  # TUPLE1
        + b"R"  # REDUCE
        + b"."  # STOP
    )


def _clean_safetensors() -> bytes:
    """Build the smallest well-formed safetensors file: one float32 tensor."""
    header = json.dumps(
        {"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}},
        separators=(",", ":"),
    ).encode("utf-8")
    header += b" " * (-len(header) % 8)
    return struct.pack("<Q", len(header)) + header + struct.pack("<f", 1.0)


def _template(name: str) -> bytes:
    return importlib.resources.files("guardana.cli._starter").joinpath(name).read_bytes()


def _write_starter(directory: Path) -> None:
    if directory.exists() and not directory.is_dir():
        _refuse(f"{directory} exists and is not a directory")
    if directory.is_dir() and any(directory.iterdir()):
        _refuse(f"{directory} is not empty; the starter goes into a new or empty directory")
    for relative, content in _starter_files().items():
        destination = directory / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    typer.echo(f"Wrote a starter project to {directory}")
    typer.echo(f"Next: cd {directory} and follow README.md")


def _refuse(message: str) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=ExitCode.INVALID_USAGE)
