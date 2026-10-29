"""A collector's rejection is explained in its own words, and never read without a bound."""

import io
import json
from email.message import Message
from urllib.error import HTTPError

from guardana.cli import _reporting


class _Body(io.BytesIO):
    """A response body that refuses to be read whole, as an endless stream would."""

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            raise AssertionError("the body was read without a bound")
        return super().read(size)


def _rejection(body: bytes) -> HTTPError:
    return HTTPError("http://collector/", 403, "Forbidden", Message(), _Body(body))


def test_the_collectors_own_detail_is_shown() -> None:
    reason = _reporting._why(_rejection(json.dumps({"detail": "key pinned to staging"}).encode()))

    assert reason == "key pinned to staging"


def test_an_oversized_error_body_gives_the_fallback_and_is_never_read_whole() -> None:
    padding = " " * (_reporting._MAX_DETAIL_BYTES + 10)
    body = ("{" + padding + '"detail": "past the cap"}').encode()

    reason = _reporting._why(_rejection(body))

    assert "past the cap" not in reason
    assert "schema version" in reason
