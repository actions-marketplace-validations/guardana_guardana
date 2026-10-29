"""A server built on the `mcp` SDK that dies, changes revision or speaks an older one.

The SDK's own wire and era routing on the other side, so a misreading Guardana shares
with its scripted double cannot pass here: the run stops and is kept when the server
goes away or drops the agreed revision, an `initialize` answered with `2025-06-18`
opens no conversation, and a server whose discovery lists only modern revisions is
asked whether it still serves the handshake era.
"""

import json
import re
from pathlib import Path

import mcp_servers as mcp
import pytest
from guardana.cli.main import app
from guardana.core.target import LegacyOffer, McpServerTarget
from guardana.core.target._mcp_wire import LEGACY_WIRE
from sdk_harness import Factory, serving
from typer.testing import CliRunner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VARIABLE = "GUARDANA_CONFORMANCE_MCP_TOKEN"


def _plain(output: str) -> str:
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def _probe(
    factory: Factory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, credential: bool
) -> tuple[int, str, dict[str, object], str]:
    """Probe the fixture through the CLI; return the exit code, stderr, saved run, URL."""
    written = tmp_path / "run.json"
    flags = ["--mcp-token-env", _VARIABLE] if credential else []
    monkeypatch.setenv(_VARIABLE, mcp.CREDENTIAL)
    with serving(factory) as origin:
        url = f"{origin.url}{mcp.MCP_PATH}"
        result = CliRunner().invoke(
            app, ["probe", "--mcp", url, *flags, "--format", "json", "--output", str(written)]
        )
    document = json.loads(written.read_text(encoding="utf-8"))
    return result.exit_code, _plain(result.stderr), document, url


def test_a_server_that_stops_answering_part_way_stops_the_run_and_keeps_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, stderr, saved, url = _probe(
        mcp.stops_answering_after(2), tmp_path, monkeypatch, credential=False
    )

    assert code == 4, stderr
    assert saved["run"]["result_summary"]["stopped_by"] == "target_unavailable"  # type: ignore[index]
    assert f"error: the MCP server at {url} did not answer" in stderr


def test_a_server_whose_revisions_change_after_discovery_stops_as_target_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, stderr, saved, url = _probe(
        mcp.revisions_change_after_discovery, tmp_path, monkeypatch, credential=False
    )

    assert code == 4, stderr
    assert saved["run"]["result_summary"]["stopped_by"] == "target_changed"  # type: ignore[index]
    assert (
        f"error: the MCP server at {url} stopped accepting revision 2026-07-28 during the run; "
        f"it now offers {', '.join(mcp.NOW_SUPPORTED)}"
    ) in stderr


def test_an_initialize_answered_with_an_older_revision_agrees_nothing_and_grades_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, stderr, saved, _ = _probe(
        mcp.legacy_answering_older_revision, tmp_path, monkeypatch, credential=True
    )

    assert code == 2, stderr
    assert saved["run"]["coverage"]["protocols"] == {}  # type: ignore[index]
    assert saved["findings"] == []
    unverified = saved["unverified"]
    assert isinstance(unverified, list)
    authorization = [f for f in unverified if f["rule_id"].startswith("guardana.mcp.")]
    assert authorization, "no authorization rule said anything about the server"
    for finding in authorization:
        assert finding["verdict"]["outcome"] == "inconclusive", finding["rule_id"]
        assert f"answered initialize with {mcp.OLDER_REVISION}" in finding["evidence"]["summary"]


def _legacy_offer(factory: Factory) -> tuple[LegacyOffer, tuple[str, ...]]:
    with serving(factory) as origin:
        target = McpServerTarget(f"{origin.url}{mcp.MCP_PATH}", credential=mcp.CREDENTIAL)
        try:
            view = target.authorization()
            return view.legacy_offer, view.sessions.ids
        finally:
            target.close()


def test_a_dual_era_server_listing_only_modern_revisions_is_found_by_the_legacy_probe() -> None:
    offer, ids = _legacy_offer(mcp.dual_era_gated)

    assert offer.wire == LEGACY_WIRE
    assert offer.opening is not None
    assert offer.opening.version == mcp.LEGACY_REVISION
    assert len(ids) == 3, "the dual-era server's sessions were not sampled"


def test_a_modern_only_server_is_observed_to_refuse_the_handshake_era() -> None:
    offer, ids = _legacy_offer(mcp.modern_only_gated)

    assert offer.modern_only
    assert ids == ()
