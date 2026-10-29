"""`guardana case add|list` — promote one reviewed failure into a regression case.

`add` turns one kept exchange into a case of a YAML suite's dataset and proves, before
anything is written, that the case's expectation fails the reply that failed and passes a
correct one. It writes only with `--write`; the person who runs it so is the promotion.
Reply and input text reach the output only on a terminal or with `--show`, so a dry run
scripted in CI does not copy what a redactor missed into a log.
"""

import json
import os
import site
import stat
import sys
import sysconfig
import tempfile
import unicodedata
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust
from guardana.cli.exit_codes import ExitCode
from guardana.core.dataset import DatasetCase, DatasetError, read_dataset_text, render_case
from guardana.core.fingerprint import digest_of
from guardana.core.promotion import (
    Promotion,
    PromotionRefusedError,
    Reviewed,
    SuiteFile,
    open_suite,
    promote,
    promoted_case,
    select_exchange,
)
from guardana.core.recording import RecordedExchange, Recording, RecordingError, read_recording
from guardana.core.registry import Registry
from guardana.core.regression import Breach, PairProof, prove, unprovable_reason

case_app = typer.Typer(
    help="Promote a reviewed failure from a recording into a regression case of a suite.",
    no_args_is_help=True,
)

ShowOption = Annotated[
    bool,
    typer.Option(
        "--show", help="Print input and reply text even when the output is not a terminal."
    ),
]

_PREVIEW = 120
_BREACH_EXIT = {
    Breach.WRONG_WAY: ExitCode.POLICY_FAILED,
    Breach.DECLINED: ExitCode.INDETERMINATE,
    Breach.RAISED: ExitCode.INVALID_USAGE,
}


class _Refused(Exception):  # noqa: N818 — named for the outcome the command reports
    """A refusal before the proof, exit `3`."""


@case_app.command("add")
def add(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; the command's surface
    rule: Annotated[Path, typer.Argument(help="The YAML suite file whose dataset gains the case.")],
    source: Annotated[
        Path, typer.Option("--from", help="The recording holding the kept exchange.")
    ],
    expect: Annotated[
        str, typer.Option("--expect", help="The case's own expectation, a JSON object.")
    ],
    accepted_file: Annotated[
        Path, typer.Option("--accepted-file", help="A file holding a correct reply.")
    ],
    version: Annotated[
        str, typer.Option("--version", help="The dataset's new version; must differ.")
    ],
    key: Annotated[
        str | None, typer.Option("--key", help="The exchange's key, as `case list` prints it.")
    ] = None,
    line: Annotated[
        int | None, typer.Option("--line", min=1, help="The exchange's line in the recording.")
    ] = None,
    label: Annotated[
        str | None, typer.Option("--label", help="What the case guards against, as a tag.")
    ] = None,
    input_file: Annotated[
        Path | None,
        typer.Option("--input-file", help="A rewritten question, in place of the recorded one."),
    ] = None,
    observed_file: Annotated[
        Path | None,
        typer.Option(
            "--observed-file",
            help="A stand-in for a redacted failing reply that reproduces the failure.",
        ),
    ] = None,
    write: Annotated[
        bool, typer.Option("--write", help="Write the dataset; without it nothing is written.")
    ] = False,
    show: ShowOption = False,
) -> None:
    """Add one kept exchange to a suite's dataset as a regression case proven on both sides.

    Exit `0` written, or shown without `--write` · `1` a side of the proof graded the
    wrong way · `2` a side declined · `3` a refused input, recording, rule, evaluator or
    flag, or an evaluator that raised.
    """
    full = show or _terminal()
    try:
        suite = _writable_suite(rule)
        recording = _recording(source)
        exchange = select_exchange(recording, key=key, line=line)
        reviewed = Reviewed(
            expect=_expectation(expect),
            accepted=_text(accepted_file, "--accepted-file"),
            label=label,
            input=None if input_file is None else _text(input_file, "--input-file"),
            observed=None if observed_file is None else _text(observed_file, "--observed-file"),
        )
        promotion = promote(suite, promoted_case(recording, exchange, reviewed), version)
        proof = _proof(promotion)
    except (_Refused, PromotionRefusedError) as exc:
        typer.echo(f"error: {_escaped(str(exc))}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from None
    for text in _describe(suite, recording, exchange, promotion, proof, full=full):
        typer.echo(text)
    breach = proof.breach
    if breach is not None:
        typer.echo(
            f"refused: the expectation does not separate the two replies "
            f"({proof.describe()}); a pair holds only when observed fails and accepted passes. "
            f"Nothing was written.",
            err=True,
        )
        raise typer.Exit(code=_BREACH_EXIT[breach])
    if not write:
        typer.echo("dry run: nothing was written; run again with --write to add the case")
        return
    try:
        _write_atomically(suite, promotion.text)
    except _Refused as exc:
        typer.echo(f"error: {_escaped(str(exc))}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from None
    typer.echo(
        f"wrote {suite.dataset_path}: {promotion.dataset.identity}, case on line "
        f"{promotion.case.line}; relock the recipe that runs this suite and commit both"
    )


@case_app.command("list")
def list_cases(
    recording_path: Annotated[Path, typer.Argument(metavar="RECORDING", help="The recording.")],
    show: ShowOption = False,
) -> None:
    """List every kept exchange: its line, rule, key and whether its reply is altered.

    Exit `0` listed · `3` a recording that cannot be read.
    """
    try:
        recording = _recording(recording_path)
    except _Refused as exc:
        typer.echo(f"error: {_escaped(str(exc))}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from None
    full = show or _terminal()
    for exchange in recording.exchanges:
        if exchange.declined is not None:
            reply = "declined"
        else:
            reply = "altered" if recording.reply_altered(exchange) else "verbatim"
        typer.echo(
            f"line {exchange.line}  rule {_escaped(exchange.rule)}  "
            f"key {_escaped(exchange.key or '-')}  reply {reply}"
        )
        if full:
            typer.echo(f"    input: {_preview(_joined(exchange))}")
            typer.echo(f"    reply: {_reply_preview(exchange)}")
    if not full:
        typer.echo("input and reply text are not printed off a terminal; pass --show to print them")


def _terminal() -> bool:
    """Whether standard output is a terminal a person reads, not a log a pipeline keeps."""
    return sys.stdout.isatty()


def _writable_suite(path: Path) -> SuiteFile:
    """Open the suite at `path`, refusing one Guardana may not or cannot rewrite."""
    if path.suffix not in {".yaml", ".yml"} or not path.is_file():
        raise _Refused(f"{path} is not a YAML suite file")
    if _installed(path):
        raise _Refused(
            f"{path} belongs to an installed distribution; add the case to the suite in its "
            f"own source tree"
        )
    suite = open_suite(path)
    target = suite.dataset_path
    if not os.access(target, os.W_OK) or not os.access(target.parent, os.W_OK):
        raise _Refused(f"{target} or its directory is not writable")
    return suite


def _installed(path: Path) -> bool:
    """Whether `path` lies where installed distributions live."""
    resolved = path.resolve()
    if {"site-packages", "dist-packages"} & set(resolved.parts):
        return True
    roots = {sysconfig.get_paths()[name] for name in ("purelib", "platlib")}
    roots.update(site.getsitepackages())
    roots.add(site.getusersitepackages())
    return any(resolved.is_relative_to(Path(root).resolve()) for root in roots)


def _recording(path: Path) -> Recording:
    try:
        return read_recording(path)
    except RecordingError as exc:
        raise _Refused(str(exc)) from exc


def _expectation(raw: str) -> dict[str, object]:
    try:
        parsed: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _Refused(f"--expect is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise _Refused("--expect must be a JSON object of the evaluator's fields")
    return parsed


def _text(path: Path, flag: str) -> str:
    """Read a reviewer's file, dropping the one line ending an editor adds at the end."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _Refused(f"{flag} {path} could not be read: {exc}") from exc
    text = text.removesuffix("\n").removesuffix("\r")
    if not text.strip():
        raise _Refused(f"{flag} {path} is empty")
    return text


def _proof(promotion: Promotion) -> PairProof:
    """Grade the case's two replies with the suite's evaluator, refusing one that cannot."""
    rule = promotion.rule
    evaluator_id = rule.meta.evaluator or ""
    evaluator = (
        Registry.discover(resolve_trust(None, None, None).trust).evaluators().get(evaluator_id)
    )
    reason = unprovable_reason(evaluator_id, evaluator)
    if reason is not None or evaluator is None:
        raise _Refused(f"{reason}; the case cannot be proven without sending, so it is refused")
    case = promotion.case
    if case.pair is None:
        raise _Refused("the promoted case carries no pair")
    return prove(evaluator, case.messages, case.expectation, case.pair)


def _describe(  # noqa: PLR0913 — every fact the summary names
    suite: SuiteFile,
    recording: Recording,
    exchange: RecordedExchange,
    promotion: Promotion,
    proof: PairProof,
    *,
    full: bool,
) -> list[str]:
    """Name what would be written; quote it only when `full`."""
    case = promotion.case
    pair = case.pair
    tags = _escaped(", ".join(case.tags))
    lines = [
        f"suite: {promotion.rule.meta.id} ({suite.path})",
        f"dataset: {suite.dataset_path} {suite.dataset.identity} -> "
        f"{promotion.dataset.identity}, new case on line {case.line}",
        f"from: {_escaped(recording.identity)} line {exchange.line}, "
        f"rule {_escaped(exchange.rule)}, key {_escaped(exchange.key or '-')}",
        _measure("input", _input_text(promotion)),
    ]
    if pair is not None:
        lines.append(_measure("observed", pair.observed))
        lines.append(_measure("accepted", pair.accepted))
    lines.append(f"expect: {', '.join(sorted(case.expectation.fields)) or '(the suite default)'}")
    lines.append(f"tags: {tags}")
    lines.append(f"proof: {proof.describe()}")
    if full:
        lines.append(f"    observed: {_escaped(proof.observed.reason)}")
        lines.append(f"    accepted: {_escaped(proof.accepted.reason)}")
        lines.append(f"case: {_escaped(_case_line(promotion))}")
    else:
        lines.append("the case's text is not printed off a terminal; pass --show to print it")
    return lines


def _case_line(promotion: Promotion) -> str:
    entry = next(c for c in promotion.dataset.cases if c.line == promotion.case.line)
    return render_case(entry)


def _input_text(promotion: Promotion) -> str:
    entry: DatasetCase = next(c for c in promotion.dataset.cases if c.line == promotion.case.line)
    if isinstance(entry.input, str):
        return entry.input
    return json.dumps([[m.role, m.content] for m in entry.input], ensure_ascii=False)


def _measure(what: str, text: str) -> str:
    return f"{what}: {len(text)} characters, {digest_of(text)}"


def _joined(exchange: RecordedExchange) -> str:
    if len(exchange.input) == 1:
        return exchange.input[0].content
    return " | ".join(f"{m.role}: {m.content}" for m in exchange.input)


def _reply_preview(exchange: RecordedExchange) -> str:
    """Quote the reply, or name the decline the line holds in its place."""
    declined = exchange.declined
    if declined is not None:
        return f"[declined: {_escaped(declined.name)} (HTTP {declined.status})]"
    return _preview(exchange.reply or "")


def _preview(text: str) -> str:
    escaped = _escaped(text)
    return escaped if len(escaped) <= _PREVIEW else f"{escaped[: _PREVIEW - 1]}…"


def _escaped(text: str) -> str:
    """Escape every control character, so a recorded reply cannot drive the terminal."""
    return "".join(
        ascii(ch)[1:-1] if unicodedata.category(ch).startswith("C") else ch for ch in text
    )


def _write_atomically(suite: SuiteFile, text: str) -> None:
    """Replace the dataset in one step under a lock file, refusing when either file changed.

    The lock keeps two `case add` runs from both proving against one version and the later
    replacing the earlier's case; it excludes only writers that take it too.
    """
    target = suite.dataset_path
    lock = target.with_name(f".{target.name}.lock")
    try:
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        raise _Refused(
            f"{lock} exists, so another `guardana case add` is writing {target}; nothing was "
            f"written. If none is running, remove {lock} and run again"
        ) from None
    except OSError as exc:
        raise _Refused(f"{lock} could not be created: {exc}") from exc
    try:
        _refuse_changed(suite)
        _replace(target, text)
    finally:
        lock.unlink(missing_ok=True)


def _refuse_changed(suite: SuiteFile) -> None:
    """Refuse when the suite or its dataset is no longer the text the case was proven against."""
    target = suite.dataset_path
    try:
        current = read_dataset_text(target)
    except DatasetError as exc:
        raise _Refused(str(exc)) from exc
    if current != suite.dataset_text:
        raise _Refused(f"{target} changed while the case was being proven; nothing was written")
    try:
        rule = suite.path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _Refused(f"{suite.path} could not be read again: {exc}") from exc
    if rule != suite.text:
        raise _Refused(f"{suite.path} changed while the case was being proven; nothing was written")


def _replace(target: Path, text: str) -> None:
    """Write `text` beside `target` and rename it over `target`, keeping its permissions."""
    mode = stat.S_IMODE(target.stat().st_mode)
    handle, temporary = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).chmod(mode)
        Path(temporary).replace(target)
    except OSError as exc:
        Path(temporary).unlink(missing_ok=True)
        raise _Refused(f"{target} could not be written: {exc}") from exc


__all__ = ["case_app"]
