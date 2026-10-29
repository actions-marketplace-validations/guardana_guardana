"""An approved MCP manifest names its server without the credential its URL carried.

A pin is committed next to the code, so a key in the server's query would be
committed with it. The pin stores, compares and prints the address the way a `ref`
shows it; a pin written before that, with the raw address, still compares.
"""

import json
from collections.abc import Mapping
from pathlib import Path

from guardana.core.rule import RuleContext
from guardana.core.target import McpServerTarget
from guardana.rules.agent.mcp_server_manifest import McpServerManifestRule, pin_document

_MARKER = "s3cretvalue"
_SERVER = f"https://93.184.215.14/mcp?key={_MARKER}"


class _Server:
    """An MCP transport offering one tool."""

    def speak(self, wire: object) -> None:
        pass

    def request(self, method: str, params: Mapping[str, object]) -> Mapping[str, object]:
        if method == "initialize":
            return {"protocolVersion": "2025-11-25"}
        return {"tools": [{"name": "refund", "description": "Refund an order."}]}

    def notify(self, method: str) -> None:
        pass

    def close(self) -> None:
        return None


def _target(url: str = _SERVER) -> McpServerTarget:
    return McpServerTarget(url, transport=_Server())


def _run(target: McpServerTarget, document: object, tmp_path: Path) -> list[str]:
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    findings = McpServerManifestRule().run(target, RuleContext(config={"pin": str(path)}))
    return [
        f"{f.verdict.outcome if f.verdict else 'finding'}: {f.evidence.summary}" for f in findings
    ]


def test_a_written_pin_records_the_server_without_its_query() -> None:
    document = pin_document(_SERVER, _target().list_tools())

    assert _MARKER not in json.dumps(document)
    assert str(document["server"]).startswith("https://93.184.215.14/mcp?[redacted:query:")


def test_a_pin_holding_the_raw_address_still_compares(tmp_path: Path) -> None:
    raw: dict[str, object] = dict(pin_document(_SERVER, _target().list_tools()))
    raw["server"] = _SERVER

    assert _run(_target(), raw, tmp_path) == []


def test_a_pin_for_another_query_is_refused_and_printed_without_either_secret(
    tmp_path: Path,
) -> None:
    other: dict[str, object] = dict(pin_document(_SERVER, _target().list_tools()))
    other["server"] = "https://93.184.215.14/mcp?key=otherkey"

    outcomes = _run(_target(), other, tmp_path)

    assert len(outcomes) == 1
    assert outcomes[0].startswith("inconclusive: the pinned manifest was approved for")
    assert _MARKER not in outcomes[0]
    assert "otherkey" not in outcomes[0]
