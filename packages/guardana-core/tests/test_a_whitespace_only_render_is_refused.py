"""An installed format that renders only whitespace fails, as the conformance kit says it must."""

import pytest
from guardana.core.origin import Origin
from guardana.core.output import OutputError, RendererSpec, SelectedRenderer, render
from guardana.core.testing import sample_verifications
from guardana.core.verify import Verification
from guardana.testing import assert_renderer_conforms


def _blank(verification: Verification) -> str:
    return " \n\t"


_SPEC = RendererSpec(name="blank", summary="writes nothing visible", render=_blank)


def test_control_the_kit_refuses_the_format() -> None:
    with pytest.raises(AssertionError, match="whitespace"):
        assert_renderer_conforms(_SPEC)


def test_render_refuses_a_format_that_returned_only_whitespace() -> None:
    selected = SelectedRenderer("blank", _SPEC, Origin(distribution="acme-blank", version="1"))

    try:
        rendered = render(selected, sample_verifications()[0])
    except OutputError:
        return
    raise AssertionError(f"render accepted {rendered!r} as a report")
