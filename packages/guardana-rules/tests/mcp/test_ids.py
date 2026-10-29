"""The structure of identifiers a server hands out, named without quoting one."""

import pytest
from _offline import refuse_name_lookups
from guardana.rules.mcp._ids import counts_up, id_structure

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

_RANDOM = (
    "7f3a1c04-1b2d-4e5f-8a9b-0c1d2e3f4a5b",
    "b19e2d55-6c7f-4a01-9d3e-2f8b7c6a5d40",
)


def test_issued_ids_count_up_only_in_the_order_they_were_issued() -> None:
    issued = ["session-0003", "session-0001", "session-0002"]

    assert not counts_up(issued, ordered=True)
    assert counts_up(issued, ordered=False)


def test_a_listing_in_any_order_is_a_counter_once_its_tails_are_sorted() -> None:
    listed = ["task-0000000000000031", "task-0000000000000029", "task-0000000000000030"]

    named = id_structure(listed, ordered=False)

    assert named is not None
    assert "counter" in named
    assert "task" not in named
    assert "0000" not in named


def test_a_repeated_id_and_a_short_id_are_named() -> None:
    assert "repeated" in (id_structure([_RANDOM[0], _RANDOM[0]], ordered=False) or "")
    assert "as short as 5 characters" in (id_structure(["ab3f9", "zq81c"], ordered=False) or "")


def test_random_ids_and_a_single_id_show_no_structure() -> None:
    assert id_structure(_RANDOM, ordered=False) is None
    assert id_structure(["1"], ordered=False) is None
