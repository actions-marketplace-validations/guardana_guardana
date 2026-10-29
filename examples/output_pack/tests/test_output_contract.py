"""Both outputs keep the output contract, checked by Guardana's own kit as any pack would.

The kit runs each output over real engine runs, a stopped and an empty one among them,
and the webhook against a receiver with an accepting, a refusing and a closed URL.
"""

from collections.abc import Iterator
from dataclasses import replace
from functools import partial

import pytest
from acme_doubles import SECRET
from acme_outputs import provide_table, provide_webhook, webhook
from guardana.core.testing import Receiver, receiver
from guardana.testing import assert_renderer_conforms, assert_reporter_conforms


def _no_wait(_seconds: float) -> None:
    """Skip the webhook's backoff, so the unreachable deliveries do not sleep."""


@pytest.fixture
def served() -> Iterator[Receiver]:
    """The kit's receiver, for the length of one test."""
    with receiver() as urls:
        yield urls


def test_the_table_keeps_the_output_contract() -> None:
    assert_renderer_conforms(provide_table(), name="acme-table")


def test_the_webhook_keeps_the_output_contract(
    served: Receiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(webhook.SECRET_VARIABLE, SECRET)
    spec = replace(provide_webhook(), prepare=partial(webhook.prepare, sleep=_no_wait))

    assert_reporter_conforms(
        spec,
        delivered=served.accepting,
        rejected=served.refusing,
        unreachable=served.closed,
        name="acme-webhook",
        receiver=served,
    )

    assert {r.path for r in served.received} == {"/accept", "/refuse"}
