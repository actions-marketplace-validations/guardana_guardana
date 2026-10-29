"""Prove an installed format or reporter keeps the output contract, from its own test suite.

Each check runs the output over `sample_verifications()` — real engine output, a stopped
and an empty run among them — through the same boundary a run uses, and names every
problem it finds at once.
"""

import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Final, cast
from urllib.parse import urlsplit

from guardana.core.origin import Origin
from guardana.core.output import (
    Deliverer,
    DeliveryStatus,
    OutputError,
    PreparedReporter,
    RendererSpec,
    ReporterRequest,
    ReporterSpec,
    SelectedRenderer,
    deliver,
    is_output_name,
    is_reserved_renderer_name,
    is_reserved_reporter_name,
    render,
)
from guardana.core.testing import Receiver, sample_verifications
from guardana.core.verify import Verification

_UNATTRIBUTED: Final = Origin()

_PATCHED: Final = (
    (socket.socket, "connect"),
    (socket.socket, "connect_ex"),
    (socket, "create_connection"),
    (socket, "getaddrinfo"),
)
"""Every way to reach the network the prepare check refuses, as (owner, attribute)."""

_REFUSING_LOCK = threading.Lock()


class OutputContractError(AssertionError):
    """An installed format or reporter that does not keep the output contract."""


class _NetworkRefusedError(OSError):
    """What a refused connection or lookup raises while `prepare` runs."""


def assert_renderer_conforms(spec: RendererSpec, *, name: str | None = None) -> None:
    """Refuse a format that a run could not select or that fails on any sample run.

    `name` is the entry point's name, `spec.name` when left out; it must be a valid output
    name no built-in format reserves, and `spec.name` must equal it. `render` must return
    text holding more than whitespace for every sample, called through
    `guardana.core.output.render`, so the format sees exactly what `--format` would hand it.
    Raises `OutputContractError`.
    """
    problems = _name_problems(spec.name, name, is_reserved_renderer_name, "format")
    selected = SelectedRenderer(name=spec.name, spec=spec, origin=_UNATTRIBUTED)
    for sample in sample_verifications():
        try:
            text = render(selected, sample)
        except OutputError as exc:
            problems.append(f"render failed on {_described(sample)}: {exc.reason}")
            continue
        if not text.strip():
            problems.append(f"render failed on {_described(sample)}: it returned only whitespace")
    _raise_for(f"the format {spec.name!r}", problems)


def assert_reporter_conforms(  # noqa: PLR0913 — three destinations, a name and their receiver
    spec: ReporterSpec,
    *,
    delivered: str,
    rejected: str,
    unreachable: str,
    name: str | None = None,
    receiver: Receiver | None = None,
) -> None:
    """Refuse a reporter that sends while preparing or misreports any delivery.

    `delivered`, `rejected` and `unreachable` are locators, as written after `<name>://`,
    for a destination that accepts, one that answers and refuses, and one that does not
    answer; `guardana.core.testing.receiver()` serves all three for an HTTP reporter. For
    every sample and locator, `prepare` must reach no network (`socket.socket.connect`,
    `connect_ex`, `socket.create_connection` and `socket.getaddrinfo` are refused while it
    runs; a subprocess or a C extension is not covered) and return a deliverer whose
    `destination` is a `str` and whose `sent_secrets()` is a tuple of `str`; delivered
    through `guardana.core.output.deliver`, the run must come back with exactly that
    locator's status. `unknown` is always a failure, reported with its detail. `name` is
    checked as for a format. With `receiver`, the `receiver()` that `delivered` points at,
    every sample the delivered locator yields `delivered` for must have reached it as exactly
    one request; a `delivered` locator elsewhere is a failure, since nothing can be counted.
    Raises `OutputContractError`.
    """
    problems = _name_problems(spec.name, name, is_reserved_reporter_name, "reporter")
    counted = receiver
    if receiver is not None and _address(receiver.accepting) not in delivered:
        problems.append(
            f"the delivered locator does not point at the receiver passed "
            f"({receiver.accepting}), so the requests it got cannot be counted"
        )
        counted = None
    expected = (
        ("delivered", delivered, DeliveryStatus.DELIVERED),
        ("rejected", rejected, DeliveryStatus.REJECTED),
        ("unreachable", unreachable, DeliveryStatus.UNREACHABLE),
    )
    for sample in sample_verifications():
        for label, locator, status in expected:
            at = counted if status is DeliveryStatus.DELIVERED else None
            problems.extend(_delivery_problems(spec, sample, label, locator, status, at))
    _raise_for(f"the reporter {spec.name!r}", list(dict.fromkeys(problems)))


def _delivery_problems(  # noqa: PLR0913, PLR0917 — one delivery and where it is counted
    spec: ReporterSpec,
    sample: Verification,
    label: str,
    locator: str,
    status: DeliveryStatus,
    counted: Receiver | None,
) -> list[str]:
    """Prepare for `locator`, deliver `sample`, and name everything that went wrong.

    With `counted`, the requests its accepting URL got during a `delivered` delivery must
    number exactly one.
    """
    with _network_refused() as tried:
        try:
            deliverer: object = spec.prepare(ReporterRequest(locator=locator))
        except (Exception, SystemExit) as exc:
            deliverer = exc
    problems = [
        f"prepare tried to reach the network for the {label} locator ({address}); "
        f"it must only check the request and send nothing"
        for address in dict.fromkeys(tried)
    ]
    if isinstance(deliverer, (Exception, SystemExit)):
        problems.append(
            f"prepare raised {type(deliverer).__name__}: {deliverer} for the {label} locator"
        )
        return problems
    shape, secrets = _shape_problems(deliverer)
    if shape:
        return problems + shape
    prepared = _prepared(spec, cast("Deliverer", deliverer), secrets)
    before = 0 if counted is None else len(counted.received)
    outcome = deliver(prepared, sample)
    if counted is not None and outcome.status is DeliveryStatus.DELIVERED:
        sent = _requests_at(counted, before)
        if sent != 1:
            problems.append(
                f"the {label} locator yielded delivered for {_described(sample)}, and the "
                f"receiver got {sent} requests at the delivered locator, not 1"
            )
    if outcome.status is DeliveryStatus.UNKNOWN:
        problems.append(
            f"the {label} locator yielded unknown for {_described(sample)}: {outcome.detail}"
        )
    elif outcome.status is not status:
        detail = f": {outcome.detail}" if outcome.detail else ""
        problems.append(
            f"the {label} locator yielded {outcome.status} for {_described(sample)}, "
            f"not {status}{detail}"
        )
    return problems


def _address(url: str) -> str:
    """Return `url` without its scheme: the host, port and path a locator must contain."""
    parts = urlsplit(url)
    return f"{parts.netloc}{parts.path}"


def _requests_at(counted: Receiver, since: int) -> int:
    """Count the requests the accepting URL of `counted` got after the first `since` received."""
    path = urlsplit(counted.accepting).path
    return sum(1 for request in counted.received[since:] if request.path.startswith(path))


def _shape_problems(deliverer: object) -> tuple[list[str], tuple[str, ...]]:
    """Name each way what `prepare` returned is not a deliverer; return its secrets too."""
    problems: list[str] = []
    destination = getattr(deliverer, "destination", None)
    if not isinstance(destination, str):
        problems.append(
            f"prepare returned a deliverer whose destination is "
            f"{type(destination).__name__}, not str"
        )
    if not callable(getattr(deliverer, "deliver", None)):
        problems.append("prepare returned a deliverer with no callable deliver")
    sent_secrets = getattr(deliverer, "sent_secrets", None)
    if not callable(sent_secrets):
        problems.append("prepare returned a deliverer with no callable sent_secrets")
        return problems, ()
    try:
        secrets = sent_secrets()
    except (Exception, SystemExit) as exc:
        problems.append(f"sent_secrets() raised {type(exc).__name__}: {exc}")
        return problems, ()
    if not isinstance(secrets, tuple):
        problems.append(f"sent_secrets() returned {type(secrets).__name__}, not a tuple of str")
        return problems, ()
    strays = dict.fromkeys(type(value).__name__ for value in secrets if not isinstance(value, str))
    problems.extend(
        f"sent_secrets() returned a tuple holding {kind}, not only str" for kind in strays
    )
    return problems, tuple(value for value in secrets if isinstance(value, str))


def _prepared(
    spec: ReporterSpec, deliverer: Deliverer, secrets: tuple[str, ...]
) -> PreparedReporter:
    """Hold a checked deliverer as selection would, so `deliver` treats it as in a run."""
    return PreparedReporter(
        name=spec.name,
        spec=spec,
        deliverer=deliverer,
        origin=_UNATTRIBUTED,
        destination=deliverer.destination,
        secrets=secrets,
    )


def _name_problems(
    spec_name: object, name: str | None, is_reserved: Callable[[str], bool], noun: str
) -> list[str]:
    """Name each way `name` could not be selected, or does not match the spec's own."""
    if not isinstance(spec_name, str):
        return [f"the spec's name is {type(spec_name).__name__}, not str"]
    wanted = spec_name if name is None else name
    problems: list[str] = []
    if is_reserved(wanted):
        problems.append(f"{wanted!r} is reserved for a built-in {noun} or for Guardana")
    elif not is_output_name(wanted):
        problems.append(f"{wanted!r} is not an output name: [a-z][a-z0-9-]*, at most 40 characters")
    if spec_name != wanted:
        problems.append(f"the spec is named {spec_name!r}, not {wanted!r}, so selection refuses it")
    return problems


def _described(sample: Verification) -> str:
    """Say which sample run this is, in words a failure message can use."""
    result = sample.result
    said = f"the {sample.manifest.target.kind} run that ended {sample.gate}"
    if result.stopped_by is not None:
        said += f", stopped by {result.stopped_by}"
    if not result.rules_run:
        said += ", no rule run"
    kinds = sorted({str(shortfall.kind) for shortfall in result.coverage_shortfall})
    if kinds:
        said += f", shortfall {', '.join(kinds)}"
    return said


def _raise_for(subject: str, problems: list[str]) -> None:
    if problems:
        raise OutputContractError(
            f"{subject} does not keep the output contract:\n  " + "\n  ".join(problems)
        )


@contextmanager
def _network_refused() -> Iterator[list[str]]:
    """Refuse every connection and lookup through `socket` for the block; yield what was tried.

    A refusal raises, and is also recorded, so a `prepare` that swallows the error is
    still caught.
    """
    tried: list[str] = []

    def refuse(*args: object, **kwargs: object) -> object:
        address = next((arg for arg in args if not isinstance(arg, socket.socket)), None)
        tried.append(repr(address))
        raise _NetworkRefusedError(f"the network is refused while prepare runs: {address!r}")

    with _REFUSING_LOCK:
        saved = [(owner, attribute, getattr(owner, attribute)) for owner, attribute in _PATCHED]
        try:
            for owner, attribute, _ in saved:
                setattr(owner, attribute, refuse)
            yield tried
        finally:
            for owner, attribute, original in saved:
                setattr(owner, attribute, original)
