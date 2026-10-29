"""The installed-outputs page states the delivery deadline the engine enforces."""

import re
from pathlib import Path

from guardana.core.output import DELIVERY_DEADLINE_SECONDS

_PAGE = Path(__file__).resolve().parents[3] / "docs" / "outputs.md"


def test_the_outputs_page_states_the_delivery_deadline_in_seconds() -> None:
    stated = re.findall(r"ran past (\d+) seconds", _PAGE.read_text(encoding="utf-8"))

    assert stated, f"{_PAGE} no longer states how long a delivery may run"
    assert {int(seconds) for seconds in stated} == {DELIVERY_DEADLINE_SECONDS}
