"""The installed-outputs page states the reference webhook's limits as the webhook enforces them."""

import re
from pathlib import Path

from acme_outputs import webhook

_PAGE = Path(__file__).resolve().parents[3] / "docs" / "outputs.md"
_WORDS = {"two": 2, "three": 3, "four": 4, "five": 5}


def _page() -> str:
    return _PAGE.read_text(encoding="utf-8")


def test_the_page_states_the_attempts_and_the_deadline_the_webhook_uses() -> None:
    stated = re.search(r"At most (\w+) attempts within (\d+) seconds", _page())

    assert stated is not None, f"{_PAGE} no longer states the webhook's attempts and deadline"
    attempts, seconds = stated.groups()
    assert _WORDS.get(attempts, attempts) == webhook.MAX_ATTEMPTS
    assert int(seconds) == webhook.DEADLINE_SECONDS


def test_the_page_states_how_many_findings_the_webhook_sends() -> None:
    stated = re.search(r"up to (\d+) findings", _page())

    assert stated is not None, f"{_PAGE} no longer states how many findings the webhook sends"
    assert int(stated.group(1)) == webhook.MAX_FINDINGS
