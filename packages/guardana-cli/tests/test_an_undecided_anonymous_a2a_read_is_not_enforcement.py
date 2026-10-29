"""One anonymous read refused never hides another anonymous read that settled nothing."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.main import app
from guardana.core.target import A2aAgentTarget
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.testing import ScriptedA2aAgent
from typer.testing import CliRunner

runner = CliRunner()
_URL = "https://agent.invalid/"
_A = "audit-caller-a-token-0123456789"
_B = "audit-caller-b-token-9876543210"
_TASK = "8a2c4e6f-1b3d-4f5a-9c7e-0d2b4f6a8c1e"
_RULE = "guardana.a2a.caller_identity"


class _CrashesOnAnonymousList(ScriptedA2aAgent):
    """Refuses an anonymous `GetTask`, but fails with HTTP 500 on an anonymous `ListTasks`."""

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        anonymous = "Authorization" not in (headers or {})
        if (
            method == "POST"
            and anonymous
            and json.loads(body or b"{}").get("method") == "ListTasks"
        ):
            return RawReply(500, {"Content-Type": "text/plain"}, b"internal error")
        return super().__call__(
            url, method=method, body=body, headers=headers, alongside=alongside, discovery=discovery
        )


def _probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: ScriptedA2aAgent) -> Any:  # noqa: ANN401
    monkeypatch.setenv("CALLER_A", _A)
    monkeypatch.setenv("CALLER_B", _B)

    def build(connection: Any) -> A2aAgentTarget:  # noqa: ANN401 — the connection the CLI built
        return A2aAgentTarget(
            connection.address,
            credential=connection.credential,
            other_credential=connection.other_credential,
            sender=agent,
        )

    monkeypatch.setattr("guardana.cli._a2a_run.build_a2a_target", build)
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "probe",
            "--a2a",
            _URL,
            "--a2a-token-env",
            "CALLER_A",
            "--a2a-other-token-env",
            "CALLER_B",
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    return result, json.loads(saved.read_text(encoding="utf-8"))


def _said(document: dict[str, Any]) -> list[str]:
    return [
        entry["rule_id"]
        for channel in ("findings", "unverified")
        for entry in document[channel]
        if entry["rule_id"] == _RULE
    ]


def test_control_an_agent_answering_anonymous_reads_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = ScriptedA2aAgent(
        _URL, callers={_A: "alice", _B: "bob"}, tasks={"alice": [_TASK]}, enforced=False
    )

    _, document = _probe(tmp_path, monkeypatch, agent)

    assert _said(document) == [_RULE]


def test_an_anonymous_list_that_failed_is_not_read_as_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _CrashesOnAnonymousList(
        _URL, callers={_A: "alice", _B: "bob"}, tasks={"alice": [_TASK]}
    )

    result, document = _probe(tmp_path, monkeypatch, agent)

    assert _said(document), (result.exit_code, document["run"]["result_summary"])
