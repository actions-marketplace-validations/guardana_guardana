"""The output checks pass a conforming format and reporter and refuse each way one breaks.

Every refusal is an `OutputContractError` whose message says what is wrong, so a pack
author reads the fix in the failure rather than in this file.
"""

import socket
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field, replace
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

import pytest
from guardana.core.output import (
    Delivery,
    DeliveryStatus,
    RendererSpec,
    ReporterRequest,
    ReporterSpec,
)
from guardana.core.testing import receiver
from guardana.core.testing.receiver import Receiver
from guardana.core.verify import Verification
from guardana.testing import OutputContractError, assert_renderer_conforms, assert_reporter_conforms

_DIRECT = build_opener(ProxyHandler({}))


def _post(url: str, body: bytes) -> int:
    request = Request(url, data=body, method="POST")  # noqa: S310 — a loopback URL the test made
    with _DIRECT.open(request, timeout=5) as response:
        status: int = response.status
        return status


def _summary(verification: Verification) -> str:
    return f"{verification.manifest.run_id},{verification.gate}\r\n"


def _renderer(render: Callable[[Verification], str], name: str = "acme-summary") -> RendererSpec:
    return RendererSpec(name=name, summary="one line per run", render=render)


@dataclass
class _Post:
    """A deliverer that posts the run id and reads the answer as a reporter should."""

    url: str
    destination: str = "http://127.0.0.1"
    attempts_on_success: int = 1

    def sent_secrets(self) -> tuple[str, ...]:
        """Withhold the full URL, which says more than the destination."""
        return (self.url,)

    def deliver(self, verification: Verification) -> Delivery:
        """Post once and say what became of it."""
        request = Request(self.url, data=verification.manifest.run_id.encode(), method="POST")  # noqa: S310 — a loopback URL the test made
        try:
            with _DIRECT.open(request, timeout=5) as response:
                return Delivery(
                    DeliveryStatus.DELIVERED,
                    attempts=self.attempts_on_success,
                    http_status=response.status,
                )
        except HTTPError as exc:
            exc.close()
            return Delivery(DeliveryStatus.REJECTED, attempts=1, http_status=exc.code)
        except URLError as exc:
            return Delivery(DeliveryStatus.UNREACHABLE, detail=str(exc.reason), attempts=1)


def _prepare(request: ReporterRequest) -> _Post:
    return _Post(url=request.locator)


def _reporter(prepare: Callable[[ReporterRequest], object]) -> ReporterSpec:
    return ReporterSpec(name="acme-post", summary="posts the run id", prepare=prepare)  # type: ignore[arg-type]


@pytest.fixture
def served() -> Iterator[Receiver]:
    with receiver() as urls:
        yield urls


def _check(spec: ReporterSpec, served: Receiver) -> None:
    assert_reporter_conforms(
        spec, delivered=served.accepting, rejected=served.refusing, unreachable=served.closed
    )


def _refusal(check: Callable[[], None]) -> str:
    with pytest.raises(OutputContractError) as refused:
        check()
    return str(refused.value)


def test_a_conforming_format_passes() -> None:
    assert_renderer_conforms(_renderer(_summary))


def test_the_contract_error_is_an_assertion_error() -> None:
    assert issubclass(OutputContractError, AssertionError)


def test_a_format_that_returns_no_text_is_refused_for_every_sample() -> None:
    said = _refusal(lambda: assert_renderer_conforms(_renderer(lambda v: "")))

    assert "acme-summary" in said
    assert said.count("it returned no text") == 5
    assert "stopped by budget_exhausted" in said


def test_a_format_that_returns_only_whitespace_is_refused_for_every_sample() -> None:
    said = _refusal(lambda: assert_renderer_conforms(_renderer(lambda v: " \n\t")))

    assert said.count("it returned only whitespace") == 5


def test_a_format_that_raises_is_refused_with_what_it_raised() -> None:
    def raises(verification: Verification) -> str:
        raise ValueError("cannot write the table")

    said = _refusal(lambda: assert_renderer_conforms(_renderer(raises)))

    assert "ValueError: cannot write the table" in said


def test_a_format_that_fails_only_on_a_stopped_run_is_refused_for_that_run_alone() -> None:
    def misses_stops(verification: Verification) -> str:
        return "" if verification.result.stopped_by else _summary(verification)

    said = _refusal(lambda: assert_renderer_conforms(_renderer(misses_stops)))

    assert said.count("it returned no text") == 1
    assert "stopped by budget_exhausted" in said


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("json", "reserved"),
        ("guardana-csv", "reserved"),
        ("Acme_Table", "is not an output name"),
    ],
)
def test_a_format_named_outside_the_rules_is_refused(name: str, reason: str) -> None:
    said = _refusal(lambda: assert_renderer_conforms(_renderer(_summary, name=name)))

    assert reason in said


def test_a_format_whose_spec_names_another_entry_point_is_refused() -> None:
    said = _refusal(lambda: assert_renderer_conforms(_renderer(_summary), name="acme-table"))

    assert "named 'acme-summary', not 'acme-table'" in said


def test_a_format_sees_the_run_through_the_redaction_boundary() -> None:
    seen: list[Verification] = []

    def keeps(verification: Verification) -> str:
        seen.append(verification)
        return _summary(verification)

    assert_renderer_conforms(_renderer(keeps))

    assert len(seen) == 5
    assert all(v.stop_messages == () and v.judge_stops == () for v in seen)


def test_a_conforming_reporter_passes(served: Receiver) -> None:
    _check(_reporter(_prepare), served)

    assert sorted(r.path for r in served.received) == ["/accept"] * 5 + ["/refuse"] * 5


def test_a_reporter_that_sends_during_prepare_is_refused(served: Receiver) -> None:
    def calls_home(request: ReporterRequest) -> _Post:
        with suppress(OSError):
            _post(request.locator, b"hello")
        return _Post(url=request.locator)

    said = _refusal(lambda: _check(_reporter(calls_home), served))

    assert "prepare tried to reach the network" in said
    assert all(r.body != b"hello" for r in served.received)


def test_a_reporter_that_only_resolves_a_name_during_prepare_is_refused(served: Receiver) -> None:
    def resolves(request: ReporterRequest) -> _Post:
        with suppress(OSError):
            socket.getaddrinfo("hooks.example.com", 443)
        return _Post(url=request.locator)

    said = _refusal(lambda: _check(_reporter(resolves), served))

    assert "prepare tried to reach the network" in said


def test_the_network_is_back_once_prepare_returns(served: Receiver) -> None:
    def calls_home(request: ReporterRequest) -> _Post:
        with suppress(OSError):
            socket.create_connection(("127.0.0.1", 9), timeout=1)
        return _Post(url=request.locator)

    _refusal(lambda: _check(_reporter(calls_home), served))

    assert _post(served.accepting, b"{}") == 200


def test_a_reporter_whose_delivery_is_unknown_is_refused_with_the_detail(served: Receiver) -> None:
    @dataclass
    class _Raises(_Post):
        def deliver(self, verification: Verification) -> Delivery:
            raise RuntimeError("the queue is full")

    said = _refusal(lambda: _check(_reporter(lambda r: _Raises(url=r.locator)), served))

    assert "unknown" in said
    assert "RuntimeError: the queue is full" in said


def test_a_reporter_whose_locators_do_not_yield_their_status_is_refused(served: Receiver) -> None:
    @dataclass
    class _AlwaysRejected(_Post):
        def deliver(self, verification: Verification) -> Delivery:
            return Delivery(DeliveryStatus.REJECTED, attempts=1, http_status=403)

    said = _refusal(lambda: _check(_reporter(lambda r: _AlwaysRejected(url=r.locator)), served))

    assert "the delivered locator yielded rejected" in said
    assert "the unreachable locator yielded rejected" in said
    assert "the rejected locator" not in said


def test_a_reporter_claiming_delivered_without_an_acknowledgement_is_refused(
    served: Receiver,
) -> None:
    said = _refusal(
        lambda: _check(_reporter(lambda r: _Post(url=r.locator, attempts_on_success=0)), served)
    )

    assert "returned delivered without an acknowledgement" in said


def test_a_reporter_whose_prepare_raises_is_refused(served: Receiver) -> None:
    def refuses(request: ReporterRequest) -> _Post:
        raise ValueError("no secret set")

    said = _refusal(lambda: _check(_reporter(refuses), served))

    assert "prepare raised ValueError: no secret set" in said


@dataclass
class _Shaped:
    destination: object = "http://127.0.0.1"
    secrets: object = field(default_factory=tuple)

    def sent_secrets(self) -> object:
        return self.secrets

    def deliver(self, verification: Verification) -> Delivery:
        return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)


@pytest.mark.parametrize(
    ("deliverer", "reason"),
    [
        (_Shaped(destination=None), "destination is NoneType, not str"),
        (_Shaped(secrets=["s"]), "sent_secrets() returned list, not a tuple of str"),
        (_Shaped(secrets=(1,)), "sent_secrets() returned a tuple holding int, not only str"),
    ],
    ids=["destination", "list", "not-str"],
)
def test_a_deliverer_of_the_wrong_shape_is_refused(
    served: Receiver, deliverer: _Shaped, reason: str
) -> None:
    said = _refusal(lambda: _check(_reporter(lambda r: replace(deliverer)), served))

    assert reason in said


def test_a_reporter_named_outside_the_rules_is_refused(served: Receiver) -> None:
    spec = replace(_reporter(_prepare), name="https")

    said = _refusal(lambda: _check(spec, served))

    assert "reserved" in said


def _check_counted(spec: ReporterSpec, served: Receiver, *, delivered: str | None = None) -> None:
    assert_reporter_conforms(
        spec,
        delivered=served.accepting if delivered is None else delivered,
        rejected=served.refusing,
        unreachable=served.closed,
        receiver=served,
    )


def test_a_conforming_reporter_passes_with_its_requests_counted(served: Receiver) -> None:
    _check_counted(_reporter(_prepare), served)


@dataclass
class _Silent(_Post):
    """Says `delivered` to the accepting URL without sending anything there."""

    accepting: str = ""

    def deliver(self, verification: Verification) -> Delivery:
        if self.url == self.accepting:
            return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=200)
        return super().deliver(verification)


def test_a_reporter_that_says_delivered_and_sends_nothing_is_refused(served: Receiver) -> None:
    spec = _reporter(lambda r: _Silent(url=r.locator, accepting=served.accepting))

    _check(spec, served)
    said = _refusal(lambda: _check_counted(spec, served))

    assert said.count("the receiver got 0 requests at the delivered locator, not 1") == 5
    assert "stopped by budget_exhausted" in said


@dataclass
class _Twice(_Post):
    def deliver(self, verification: Verification) -> Delivery:
        super().deliver(verification)
        return super().deliver(verification)


def test_a_reporter_that_sends_one_run_twice_is_refused(served: Receiver) -> None:
    said = _refusal(lambda: _check_counted(_reporter(lambda r: _Twice(url=r.locator)), served))

    assert said.count("the receiver got 2 requests at the delivered locator, not 1") == 5


def test_a_delivered_locator_away_from_the_receiver_cannot_be_counted(served: Receiver) -> None:
    with receiver() as elsewhere:
        said = _refusal(
            lambda: _check_counted(_reporter(_prepare), served, delivered=elsewhere.accepting)
        )

    assert "the delivered locator does not point at the receiver passed" in said
