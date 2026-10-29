"""A submission counts as delivered only when the collector itself says it accepted it.

Any `2xx` is not enough: a proxy, a captive portal or the wrong service at the
collector's address answers `200` too, and a fleet reporting into one would read as
delivered while nothing was stored.
"""

import json
from urllib.error import HTTPError

import pytest
from _answering_collector import COLLECTOR_ACKNOWLEDGEMENT, answering
from guardana.core.report.result import ScanResult
from guardana.core.reporter import HttpReporter, UnacknowledgedSubmissionError

_EMPTY = ScanResult((), (), ())


def _submit(url: str) -> None:
    HttpReporter(url).submit(_EMPTY, source="ci")


@pytest.mark.parametrize(
    "body",
    [
        COLLECTOR_ACKNOWLEDGEMENT,
        json.dumps(
            {
                "status": "ok",
                "duplicate": True,
                "stored": 0,
                "accepted_by": "ci",
                "project": "acme/web",
            }
        ).encode(),
    ],
    ids=["minimal", "full"],
)
def test_the_collectors_acknowledgement_is_a_delivery(body: bytes) -> None:
    with answering(200, body) as collector:
        _submit(collector.url)

    assert collector.heard == ["/findings"]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (200, json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode()),
        (200, b'{"status": "error"}'),
        (200, b'{"status": "OK"}'),
        (200, b'["ok"]'),
        (200, b"ok"),
        (200, b""),
        (204, b""),
        (202, b'{"accepted": true}'),
        (
            200,
            b'{"status": "ok", "duplicate": false, "stored": 0, "padding": "'
            + b" " * (64 * 1024)
            + b'"}',
        ),
        (200, b"[" * 60_000),
        (200, b'{"status": "ok"}'),
        (200, b'{"status": "ok", "storage": "memory", "pending_migrations": 0}'),
        (200, b'{"status": "ok", "duplicate": false}'),
        (200, b'{"status": "ok", "stored": 0}'),
        (200, b'{"status": "ok", "duplicate": false, "stored": "0"}'),
        (200, b'{"status": "ok", "duplicate": false, "stored": true}'),
        (200, b'{"status": "ok", "duplicate": false, "stored": 1.0}'),
        (200, b'{"status": "ok", "duplicate": 0, "stored": 0}'),
        (200, b'{"status": "error", "duplicate": false, "stored": 0}'),
    ],
    ids=[
        "chat-reply",
        "status-error",
        "status-upper",
        "list",
        "plain-text",
        "empty",
        "no-content",
        "other-json",
        "oversized",
        "deeply-nested",
        "health-check",
        "readiness-check",
        "no-stored",
        "no-duplicate",
        "stored-text",
        "stored-boolean",
        "stored-float",
        "duplicate-number",
        "error-with-counts",
    ],
)
def test_a_2xx_without_the_collectors_acknowledgement_is_not_a_delivery(
    status: int, body: bytes
) -> None:
    with answering(status, body) as collector, pytest.raises(UnacknowledgedSubmissionError) as e:
        _submit(collector.url)

    assert str(e.value) == "the response was not a collector acknowledgement"
    assert collector.heard == ["/findings"]


def test_a_refusal_is_still_a_rejection() -> None:
    with answering(403, b'{"detail": "key pinned to staging"}') as collector:
        with pytest.raises(HTTPError) as rejected:
            _submit(collector.url)
        rejected.value.close()

    assert rejected.value.code == 403
