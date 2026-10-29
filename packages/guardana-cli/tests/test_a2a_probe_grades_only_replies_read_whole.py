"""`probe --a2a` grades only replies it read whole: every listing page and every card byte."""

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.target import A2aAgentTarget
from guardana.core.target._mcp_http import MAX_RESPONSE_BYTES, DiscoveryScope, RawReply, send
from guardana.core.testing import ScriptedA2aAgent
from guardana.core.testing.a2a import agent_card
from typer.testing import CliRunner, Result

runner = CliRunner()
_URL = "https://agent.invalid/"
_A = "audit-caller-a-token-0123456789"
_B = "audit-caller-b-token-9876543210"
_TASK = "8a2c4e6f-1b3d-4f5a-9c7e-0d2b4f6a8c1e"
_OTHERS_TASK = "3f9d1c2b-7a6e-4b5d-8c4f-1e2d3c4b5a69"
_VISIBILITY = "guardana.a2a.task_visibility"
_CARD_RULE = "guardana.a2a.agent_card"


def _optional_card() -> dict[str, Any]:
    """A card that accepts a bearer token and also a caller presenting nothing."""
    card = agent_card("https://agent.invalid/a2a")
    return {**card, "securityRequirements": [{"schemes": {"bearer": {}}}, {}]}


class _AnonymousListing(ScriptedA2aAgent):
    """Answers an anonymous `ListTasks` with a scripted result; everything else as configured."""

    def __init__(self, result: Mapping[str, object], **behaviour: Any) -> None:  # noqa: ANN401
        super().__init__(_URL, **behaviour)
        self.anonymous_result = dict(result)

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
        asked = json.loads(body or b"{}") if method == "POST" else {}
        if asked.get("method") == "ListTasks" and "Authorization" not in (headers or {}):
            self.requests.append((method, url, dict(headers or {})))
            payload = {"jsonrpc": "2.0", "id": asked["id"], "result": self.anonymous_result}
            return RawReply(200, {"Content-Type": "application/json"}, json.dumps(payload).encode())
        return super().__call__(
            url, method=method, body=body, headers=headers, alongside=alongside, discovery=discovery
        )


class _ServedWhole:
    """An HTTP response holding the whole body, read only as far as the caller asks."""

    status = 200
    headers: Mapping[str, str] = MappingProxyType({"Content-Type": "application/json"})

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, size: int) -> bytes:
        return self._body[:size]

    def __enter__(self) -> "_ServedWhole":
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Opener:
    """Stands in for the network under the real `send`, serving one body to every request."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def open(self, request: object, timeout: float) -> _ServedWhole:
        return _ServedWhole(self._body)


class _CardThroughTheRealReader(ScriptedA2aAgent):
    """Fetches its card through the real bounded `send`; answers JSON-RPC as configured."""

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
        if method == "GET":
            self.requests.append((method, url, dict(headers or {})))
            return send(url, method="GET", headers=headers)
        return super().__call__(
            url, method=method, body=body, headers=headers, alongside=alongside, discovery=discovery
        )


def _probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: ScriptedA2aAgent
) -> tuple[Result, dict[str, Any] | None]:
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
    document = json.loads(saved.read_text(encoding="utf-8")) if saved.exists() else None
    return result, document


def _said(document: Mapping[str, Any] | None, rule: str) -> list[str]:
    if document is None:
        raise RuntimeError("the probe saved no run")
    return [
        entry["evidence"]["summary"]
        for channel in ("findings", "unverified")
        for entry in document[channel]
        if entry["rule_id"] == rule
    ]


def _listing_agent(result: Mapping[str, object]) -> _AnonymousListing:
    return _AnonymousListing(
        result,
        card=_optional_card(),
        callers={_A: "alice", _B: "bob"},
        tasks={"alice": [_TASK]},
    )


def test_control_an_anonymous_listing_showing_a_task_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = {"tasks": [{"id": _OTHERS_TASK, "contextId": "ctx"}], "nextPageToken": ""}

    _, document = _probe(tmp_path, monkeypatch, _listing_agent(listing))

    assert _said(document, _VISIBILITY)


def test_an_empty_anonymous_page_with_a_continuation_is_not_cleared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = {"tasks": [], "nextPageToken": "more"}

    result, document = _probe(tmp_path, monkeypatch, _listing_agent(listing))

    assert _said(document, _VISIBILITY), result.exit_code


def test_an_anonymous_listing_whose_tasks_is_not_a_list_is_not_cleared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, document = _probe(tmp_path, monkeypatch, _listing_agent({"tasks": "not-a-list"}))

    assert _said(document, _VISIBILITY), result.exit_code


def _card_agent(monkeypatch: pytest.MonkeyPatch, tail: bytes) -> tuple[ScriptedA2aAgent, int]:
    card = json.dumps(agent_card("https://agent.invalid/a2a")).encode("utf-8")
    body = card + tail
    monkeypatch.setattr(
        "guardana.core.target._mcp_http.build_opener", lambda *handlers: _Opener(body)
    )
    agent = _CardThroughTheRealReader(
        _URL, callers={_A: "alice", _B: "bob"}, tasks={"alice": [_TASK]}
    )
    return agent, len(body)


def test_control_a_whole_card_is_graded_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, _ = _card_agent(monkeypatch, b"")

    result, document = _probe(tmp_path, monkeypatch, agent)

    assert result.exit_code == ExitCode.OK, result.output
    assert _said(document, _CARD_RULE) == []


def test_control_a_card_followed_by_content_that_is_not_json_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, _ = _card_agent(monkeypatch, b" trailing")

    result, _ = _probe(tmp_path, monkeypatch, agent)

    assert result.exit_code != ExitCode.OK


def test_a_card_cut_at_the_read_ceiling_is_not_graded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, size = _card_agent(monkeypatch, b" " * MAX_RESPONSE_BYTES + b" trailing")
    if size <= MAX_RESPONSE_BYTES + 1:
        raise RuntimeError("the card body does not reach past the read ceiling")

    result, document = _probe(tmp_path, monkeypatch, agent)

    assert result.exit_code != ExitCode.OK or _said(document, _CARD_RULE), result.exit_code
