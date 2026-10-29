"""The supported surface of `guardana.core.doubles`, and its signatures, are pinned.

An application wires these names into its own code, so a change here is a change to a
supported API, announced under "Changed — breaking" with what to write instead.
"""

import inspect

from guardana.core import doubles


def test_the_supported_names_are_exactly_the_documented_ones() -> None:
    assert set(doubles.__all__) == {
        "INSTRUMENTED",
        "PRODUCER",
        "Doubles",
        "DoublesError",
        "open_doubles",
    }


def test_open_doubles_takes_the_fixtures_file_and_a_required_trace_keyword() -> None:
    parameters = inspect.signature(doubles.open_doubles).parameters

    assert list(parameters) == ["fixtures", "trace"]
    assert parameters["trace"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["trace"].default is inspect.Parameter.empty


def test_the_doubles_take_the_documented_calls() -> None:
    signature = inspect.signature
    assert list(signature(doubles.Doubles.acting_as).parameters) == ["self", "tenant"]
    assert list(signature(doubles.Doubles.call).parameters) == ["self", "name", "arguments"]
    assert list(signature(doubles.Doubles.tool).parameters) == ["self", "name"]
    assert list(signature(doubles.Doubles.close).parameters) == ["self"]
