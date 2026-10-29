"""Every built-in format name is reserved, so no installed format can take one."""

from guardana.core.output import RESERVED_RENDERER_NAMES
from guardana.report import RENDERER_NAMES


def test_every_built_in_format_name_is_reserved_for_installed_formats() -> None:
    assert set(RENDERER_NAMES) <= RESERVED_RENDERER_NAMES
