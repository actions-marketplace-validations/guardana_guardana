"""The file-scan private-key pattern costs time linear in the text after an unclosed header."""

from _cost import growth
from guardana.rules._secrets import _PRIVATE_KEY_WITH_BODY

_HEADER = "-----BEGIN " + "PRIVATE KEY-----"


def _search(text: str) -> object:
    return _PRIVATE_KEY_WITH_BODY[1].search(text)


def _growth(unit: str, small: int, large: int) -> float:
    return growth(_search, _HEADER + unit * small, _HEADER + unit * large)


def test_control_an_unclosed_base64_body_costs_linear_time() -> None:
    assert _growth("A", 250_000, 1_000_000) < 1.3


def test_an_unclosed_header_followed_by_whitespace_costs_linear_time() -> None:
    assert _growth(" ", 4000, 16000) < 1.3
