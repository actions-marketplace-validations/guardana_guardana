"""`acme-webhook` against a receiver Guardana did not write.

The receiver verifies every delivery with the reference `standardwebhooks` verifier
before it answers, so a delivered run is one a third party's code accepted. Waits
between attempts are recorded instead of slept.
"""

import re
import socket
import threading
from pathlib import Path

import pytest
from acme_doubles import ADMIT, SECRET, Receiver
from acme_outputs import webhook
from guardana.cli.main import app
from guardana.core.gate import GateOutcome
from guardana.core.output import Delivery, DeliveryStatus, ReporterRequest
from guardana.core.report import ScanResult
from guardana.core.testing import manifest_for
from guardana.core.verify import Verification
from typer.testing import CliRunner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_OTHER_SECRET = SECRET.replace("whsec_", "whsec_AAAA")


def _verification() -> Verification:
    result = ScanResult(findings=(), rules_run=("acme.quiet",), rules_skipped=())
    return Verification(result=result, manifest=manifest_for(result), gate=GateOutcome.PASS)


def _deliver(url: str, waits: list[float]) -> Delivery:
    prepared = webhook.prepare(
        ReporterRequest(locator=url), environ={webhook.SECRET_VARIABLE: SECRET}, sleep=waits.append
    )
    return prepared.deliver(_verification())


def test_a_204_is_delivered_once(receiver: Receiver) -> None:
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery == Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)
    assert [r.verified for r in receiver.received] == [True]
    assert receiver.received[0].payload is not None
    assert receiver.received[0].payload["data"]["run_id"] == _verification().manifest.run_id
    assert waits == []


def test_a_503_then_a_204_is_delivered_in_two_attempts_under_one_id(receiver: Receiver) -> None:
    receiver.script[:] = [503, 204]
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery == Delivery(DeliveryStatus.DELIVERED, attempts=2, http_status=204)
    assert [r.answered for r in receiver.received] == [503, 204]
    assert all(r.verified for r in receiver.received)
    assert len({r.webhook_id for r in receiver.received}) == 1
    assert waits == [1.0]


def test_a_retry_after_in_seconds_is_honoured(receiver: Receiver) -> None:
    receiver.script[:] = [429, 204]
    waits: list[float] = []

    delivery = _deliver_with_retry_after(receiver, "3", waits)

    assert delivery.status is DeliveryStatus.DELIVERED
    assert waits == [3.0]


@pytest.mark.parametrize("retry_after", ["Wed, 21 Oct 2026 07:28:00 GMT", "60"])
def test_a_retry_after_that_is_not_seconds_or_passes_the_deadline_ends_the_retries(
    receiver: Receiver, retry_after: str
) -> None:
    receiver.script[:] = [429, 204]
    waits: list[float] = []

    delivery = _deliver_with_retry_after(receiver, retry_after, waits)

    assert delivery == Delivery(
        DeliveryStatus.REJECTED,
        detail="the receiver did not accept the delivery",
        attempts=1,
        http_status=429,
    )
    assert waits == []


def test_a_410_is_rejected_without_a_retry(receiver: Receiver) -> None:
    receiver.script[:] = [410, 204]
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery == Delivery(
        DeliveryStatus.REJECTED,
        detail="the receiver no longer accepts deliveries",
        attempts=1,
        http_status=410,
    )
    assert len(receiver.received) == 1
    assert waits == []


def test_a_redirect_is_rejected_and_not_followed(receiver: Receiver) -> None:
    receiver.script[:] = [307]
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery.status is DeliveryStatus.REJECTED
    assert delivery.http_status == 307
    assert len(receiver.received) == 1


def test_a_receiver_that_keeps_failing_decides_on_the_third_attempt(receiver: Receiver) -> None:
    receiver.script[:] = [503]
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery.status is DeliveryStatus.REJECTED
    assert (delivery.attempts, delivery.http_status) == (3, 503)
    assert waits == [1.0, 2.0]


def test_a_closed_port_is_unreachable_after_three_attempts(closed_port: int) -> None:
    waits: list[float] = []

    delivery = _deliver(f"http://127.0.0.1:{closed_port}/hook", waits)

    assert delivery.status is DeliveryStatus.UNREACHABLE
    assert delivery.attempts == 3
    assert delivery.http_status is None
    assert delivery.detail
    assert waits == [1.0, 2.0]


def test_an_answer_that_is_not_http_is_no_answer() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        def garble() -> None:
            for _ in range(3):
                connection, _address = listener.accept()
                with connection:
                    connection.recv(65536)
                    connection.sendall(b"not http at all\r\n\r\n")

        thread = threading.Thread(target=garble, daemon=True)
        thread.start()
        waits: list[float] = []

        delivery = _deliver(f"http://127.0.0.1:{port}/hook", waits)
        thread.join(timeout=5)

    assert delivery == Delivery(
        DeliveryStatus.UNREACHABLE, detail="the receiver's answer could not be read", attempts=3
    )
    assert waits == [1.0, 2.0]


def test_a_delivery_signed_with_another_secret_is_refused_by_the_verifier(
    receiver: Receiver,
) -> None:
    receiver.secret = _OTHER_SECRET
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery.status is DeliveryStatus.REJECTED
    assert delivery.http_status == 401
    assert [r.verified for r in receiver.received] == [False]


def test_a_delivery_ignores_every_proxy_variable(
    receiver: Receiver, closed_port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A proxy would see the signed summary and could answer for the receiver."""
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(variable, f"http://127.0.0.1:{closed_port}")
    for variable in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(variable, raising=False)
    waits: list[float] = []

    delivery = _deliver(receiver.url, waits)

    assert delivery == Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)
    assert [r.verified for r in receiver.received] == [True]


def test_a_scan_delivers_and_keeps_the_verdicts_exit_code(
    receiver: Receiver, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(webhook.SECRET_VARIABLE, SECRET)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "bad.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["scan", str(tree), "--reporter", f"acme-webhook://{receiver.url}", *ADMIT]
    )

    assert result.exit_code == 1, result.output
    lines = [
        line for line in _ANSI.sub("", result.stderr).splitlines() if line.startswith("delivery:")
    ]
    assert lines == [
        f"delivery: delivered — acme-webhook to {receiver.origin} (HTTP 204, 1 attempt)"
    ]
    (received,) = receiver.received
    assert received.verified
    assert received.payload is not None
    assert received.payload["data"]["gate"] == "fail"
    assert received.payload["data"]["exit_code"] == 1
    assert "/hook" not in result.stderr


def _deliver_with_retry_after(receiver: Receiver, value: str, waits: list[float]) -> Delivery:
    receiver.retry_after = value
    return _deliver(receiver.url, waits)
