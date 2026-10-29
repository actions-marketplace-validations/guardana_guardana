"""A tool call's arguments decoded the way a check reads them.

Every key-value pair is kept, duplicates included: a decoder that keeps only the
last duplicate lets `{"path": "/tmp/*", "path": "/tmp/a.log"}` show a check the
harmless value while a lenient tool acts on the other. Keys and values are kept
apart, because a key is a name and a value is what the model chose to pass.
"""

import json


class _Pairs(list[tuple[str, object]]):
    """A decoded JSON object, every pair kept in order; distinct from a JSON array."""


_NOT_JSON = object()


def argument_keys(arguments: str) -> tuple[str, ...]:
    """Every key at any depth of the arguments; none when they are not JSON."""
    parsed = _parsed(arguments)
    return () if parsed is _NOT_JSON else _walk(parsed)[0]


def argument_values(arguments: str) -> tuple[object, ...]:
    """Every scalar value at any depth, keys left out; the raw text when not JSON."""
    parsed = _parsed(arguments)
    return (arguments,) if parsed is _NOT_JSON else _walk(parsed)[1]


def as_text(value: object) -> str:
    """Render a decoded scalar as text: a string as it is, anything else as its JSON form."""
    return value if isinstance(value, str) else json.dumps(value)


def _parsed(arguments: str) -> object:
    try:
        return json.loads(arguments, object_pairs_hook=_Pairs)
    except (ValueError, RecursionError):
        return _NOT_JSON


def _walk(parsed: object) -> tuple[tuple[str, ...], tuple[object, ...]]:
    keys: list[str] = []
    values: list[object] = []
    # An explicit stack: the arguments come from the model under test, and their
    # nesting depth is theirs to choose.
    pending: list[object] = [parsed]
    while pending:
        item = pending.pop()
        if isinstance(item, _Pairs):
            for key, value in reversed(item):
                keys.append(key)
                pending.append(value)
        elif isinstance(item, list):
            pending.extend(reversed(item))
        else:
            values.append(item)
    return tuple(keys), tuple(values)
