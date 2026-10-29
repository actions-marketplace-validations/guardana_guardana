"""The name rules doctor and selection share: one definition of unselectable and colliding."""

from importlib.metadata import EntryPoint

import pytest
from guardana.core.entrypoints import (
    RENDERER_GROUP,
    REPORTER_GROUP,
    RULE_GROUP,
    InstalledEntryPoint,
)
from guardana.core.output import output_collisions, unselectable_reason


def _entry(group: str, name: str, distribution: str, version: str = "1.0") -> InstalledEntryPoint:
    value = f"{distribution.replace('-', '_')}:provide"
    return InstalledEntryPoint(
        group=group,
        name=name,
        value=value,
        module=value.split(":", 1)[0],
        distribution=distribution,
        version=version,
        entry_point=EntryPoint(name=name, value=value, group=group),
    )


@pytest.mark.parametrize(
    ("group", "name", "reason"),
    [
        (RENDERER_GROUP, "json", "reserved name"),
        (RENDERER_GROUP, "guardana-table", "reserved name"),
        (REPORTER_GROUP, "server", "reserved name"),
        (RENDERER_GROUP, "Acme_Table", "invalid name"),
        (RENDERER_GROUP, "acme-table", None),
        (REPORTER_GROUP, "json", None),
    ],
)
def test_unselectable_reason_names_reserved_before_invalid(
    group: str, name: str, reason: str | None
) -> None:
    assert unselectable_reason(group, name) == reason


def test_unselectable_reason_refuses_a_group_that_is_not_an_output_group() -> None:
    with pytest.raises(ValueError, match="not an output entry-point group"):
        unselectable_reason(RULE_GROUP, "acme")


def test_output_collisions_ignore_rule_groups_and_unselectable_names() -> None:
    found = output_collisions(
        [
            _entry(RENDERER_GROUP, "acme-table", "acme-a"),
            _entry(RENDERER_GROUP, "acme-table", "acme-b", "2.0"),
            _entry(RENDERER_GROUP, "json", "acme-a"),
            _entry(RENDERER_GROUP, "json", "acme-b"),
            _entry(RULE_GROUP, "acme", "acme-a"),
            _entry(RULE_GROUP, "acme", "acme-b"),
            _entry(REPORTER_GROUP, "acme-table", "acme-a"),
        ]
    )
    assert [(c.group, c.name, c.distributions) for c in found] == [
        (RENDERER_GROUP, "acme-table", ("acme-a 1.0", "acme-b 2.0"))
    ]
