"""The authorization rules never pass a server whose second authorization server went unread."""

from pathlib import Path
from typing import Any

import pytest
from test_mcp_probe_reads_every_authorization_server import _ISSUER, _probe

_SECOND = "https://192.0.2.20"
_RULES = ("guardana.mcp.authorization_discovery", "guardana.mcp.issuer_identification")


def _said(document: dict[str, Any], rule: str) -> list[str]:
    return [
        entry["evidence"]["summary"]
        for channel in ("findings", "unverified")
        for entry in document[channel]
        if entry["rule_id"] == rule
    ]


@pytest.mark.parametrize("rule", _RULES)
def test_control_one_conforming_authorization_server_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rule: str
) -> None:
    _, document = _probe(tmp_path, monkeypatch, [_ISSUER])

    assert rule in {entry["id"] for entry in document["run"]["rules"]}
    assert _said(document, rule) == []


@pytest.mark.parametrize("rule", _RULES)
def test_a_second_authorization_server_is_never_passed_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rule: str
) -> None:
    _, document = _probe(tmp_path, monkeypatch, [_ISSUER, _SECOND])

    assert any("192.0.2.20" in said for said in _said(document, rule)), _said(document, rule)
