import io
import json
import re
from collections.abc import Mapping, Sequence
from email.message import Message
from pathlib import Path
from typing import Self
from urllib.error import HTTPError

import pytest
import typer
from guardana.cli._target_locator import resolve_target, target_options
from guardana.cli.main import app
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import CheckError
from guardana.core.target import (
    Capability,
    ChatMessage,
    EndpointTarget,
    LocatorError,
    Target,
    TargetKind,
)
from typer.testing import CliRunner

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(output: str) -> str:
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


class _Located(Target):
    kind = TargetKind.ARTIFACT
    scheme = "acme-files"

    def __init__(self, ref: str) -> None:
        self._ref = ref

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        if "unknown" in options:
            raise LocatorError("unknown option")
        return cls(f"acme-files://{locator}:{options.get('mode', 'default')}")

    def capabilities(self) -> set[Capability]:
        return set()

    @property
    def ref(self) -> str:
        return self._ref


class _Endpoint(Target):
    kind = TargetKind.ENDPOINT
    scheme = "acme-endpoint"

    def __init__(self, ref: str) -> None:
        self._ref = ref

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        if options:
            raise LocatorError("this test target accepts no options")
        return cls(f"acme-endpoint://{locator}")

    def capabilities(self) -> set[Capability]:
        return {Capability.CHAT}

    @property
    def ref(self) -> str:
        return self._ref

    @property
    def model(self) -> str:
        return "scripted"

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        return "I cannot help with that request."


class _Refuses:
    """A chat transport that declines every request, as a careful model would."""

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        return "I cannot help with that request."


class _ChatPack(EndpointTarget):
    """A pack's endpoint target built on the built-in one, with no system prompt of its own."""

    scheme = "acme-chat"

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        return cls("http://chat.test", locator, transport=_Refuses())


_ECHOED_KEY = "gw-live-7Q2mZp9XvR4tL8kN3bW6"


class _EchoesKey:
    """A chat transport whose application refuses every request, quoting the key it was sent."""

    status = 400

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        body = f'{{"error":"bad body for key {api_key}"}}'.encode()
        raise HTTPError(base_url, self.status, "refused", Message(), io.BytesIO(body))


class _KeyedPack(EndpointTarget):
    """A pack's endpoint target that authenticates with a key no built-in pattern knows."""

    scheme = "acme-keyed"

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        return cls("http://chat.test", locator, api_key=_ECHOED_KEY, transport=_EchoesKey())


class _Unavailable(_Located):
    scheme = "unavailable"

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        raise OSError("connection refused")


def _fallback() -> Target:
    return _Located("fallback")


def test_resolve_target_passes_the_unparsed_locator_and_named_options() -> None:
    registry = Registry()
    registry.register_target(_Located)

    target = resolve_target(
        registry,
        locator="acme-files://bucket/key?part=1",
        options=["mode=strict"],
        kind=TargetKind.ARTIFACT,
        fallback=_fallback,
    )

    assert target.ref == "acme-files://bucket/key?part=1:strict"


@pytest.mark.parametrize("value", ["missing-equals", "=empty-key"])
def test_target_options_refuse_malformed_pairs(value: str) -> None:
    with pytest.raises(typer.BadParameter, match="key=value"):
        target_options([value])


def test_target_options_refuse_duplicate_keys() -> None:
    with pytest.raises(typer.BadParameter, match="more than once"):
        target_options(["mode=one", "mode=two"])


@pytest.mark.parametrize("locator", ["missing-separator", "://empty", "acme-files://"])
def test_target_locator_refuses_malformed_values(locator: str) -> None:
    with pytest.raises(typer.BadParameter, match="scheme://value"):
        resolve_target(
            Registry(),
            locator=locator,
            options=[],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )


def test_unknown_or_wrong_kind_targets_are_usage_errors() -> None:
    registry = Registry()
    registry.register_target(_Located)

    with pytest.raises(typer.BadParameter, match="unknown target scheme"):
        resolve_target(
            registry,
            locator="missing://x",
            options=[],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )
    with pytest.raises(typer.BadParameter, match="accepts only endpoint targets"):
        resolve_target(
            registry,
            locator="acme-files://x",
            options=[],
            kind=TargetKind.ENDPOINT,
            fallback=_fallback,
        )


def test_options_without_a_locator_are_refused() -> None:
    with pytest.raises(typer.BadParameter, match="needs --target"):
        resolve_target(
            Registry(),
            locator=None,
            options=["mode=strict"],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )


def test_no_locator_uses_the_legacy_fallback() -> None:
    target = resolve_target(
        Registry(),
        locator=None,
        options=[],
        kind=TargetKind.ARTIFACT,
        fallback=_fallback,
    )

    assert target.ref == "fallback"


def test_a_target_rejected_option_is_a_usage_error() -> None:
    registry = Registry()
    registry.register_target(_Located)

    with pytest.raises(typer.BadParameter, match="unknown option"):
        resolve_target(
            registry,
            locator="acme-files://x",
            options=["unknown=yes"],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )


def test_an_unreachable_target_has_its_own_exit_code() -> None:
    registry = Registry()
    registry.register_target(_Unavailable)

    with pytest.raises(typer.Exit) as stopped:
        resolve_target(
            registry,
            locator="unavailable://x",
            options=[],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )

    assert stopped.value.exit_code == 4


@pytest.mark.parametrize(
    "locator",
    [
        "unavailable://operator:hunter2pw@host.invalid/models?token=s3cret-value",
        "unavailable://host.invalid/models?token=s3cret-value#hunter2pw",
    ],
)
def test_an_unreachable_target_error_never_prints_its_credentials(
    locator: str, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = Registry()
    registry.register_target(_Unavailable)

    with pytest.raises(typer.Exit):
        resolve_target(
            registry, locator=locator, options=[], kind=TargetKind.ARTIFACT, fallback=_fallback
        )

    printed = capsys.readouterr().err
    assert "s3cret-value" not in printed
    assert "hunter2pw" not in printed
    assert "unavailable://host.invalid/models?[redacted:query:" in printed
    assert "connection refused" in printed


class _EchoesItsOptions(_Located):
    """A target whose connection error repeats what it was built with, at length."""

    scheme = "echoes"

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        raise OSError(f"connection refused for {locator} with {dict(options)} " + "x" * 2000)


def test_an_unreachable_target_error_withholds_its_options_and_is_bounded(
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = Registry()
    registry.register_target(_EchoesItsOptions)

    with pytest.raises(typer.Exit) as stopped:
        resolve_target(
            registry,
            locator="echoes://operator:hunter2pw@host.invalid/models?token=s3cret-value",
            options=["api_key=opt-secret-9431", "region=eu-west"],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )

    printed = capsys.readouterr().err
    assert stopped.value.exit_code == 4
    assert "connection refused" in printed
    for secret in ("opt-secret-9431", "eu-west", "hunter2pw", "s3cret-value"):
        assert secret not in printed
    assert "[cut from" in printed
    assert len(printed.strip()) <= len("error: ") + 500


def test_a_wrong_kind_target_error_never_prints_its_credentials() -> None:
    registry = Registry()
    registry.register_target(_Located)

    with pytest.raises(typer.BadParameter) as refused:
        resolve_target(
            registry,
            locator="acme-files://operator:hunter2pw@x?token=s3cret-value",
            options=[],
            kind=TargetKind.ENDPOINT,
            fallback=_fallback,
        )

    assert "s3cret-value" not in str(refused.value)
    assert "hunter2pw" not in str(refused.value)
    assert "acme-files://x?[redacted:query:" in str(refused.value)


def test_an_unknown_scheme_blames_trust_only_for_a_recorded_refusal() -> None:
    """A reason that merely reads like a refusal is not one; `Registry.refused` decides."""
    registry = Registry()
    registry.record_load_error(
        CheckError("acme", "discovery", "entry point refused: plugin trust is allowlist")
    )

    with pytest.raises(typer.BadParameter) as refused:
        resolve_target(
            registry,
            locator="acme-files://x",
            options=[],
            kind=TargetKind.ARTIFACT,
            fallback=_fallback,
        )

    assert "plugin trust refused" not in str(refused.value)


def test_scan_keeps_a_plugin_owned_locator_ref_verbatim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    registry.register_target(_Located)
    monkeypatch.setattr(
        Registry,
        "discover",
        classmethod(lambda cls, trust=True: registry),
    )
    output = tmp_path / "run.json"
    locator = f"acme-files://{tmp_path}"

    result = runner.invoke(
        app,
        ["scan", "--target", locator, "--format", "json", "--output", str(output)],
    )

    assert result.exit_code in (0, 2), result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["run"]["target"]["ref"] == f"{locator}:default"


_CANARY = "guardana.prompt.system_prompt_leak.canary"


def test_the_plan_selects_the_canary_rules_probe_then_runs_on_an_installed_planter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_endpoint(monkeypatch, _ChatPack)
    output = tmp_path / "probe.json"

    planned = runner.invoke(
        app, ["plan", "probe", "--target", "acme-chat://support", "--format", "json"]
    )
    probed = runner.invoke(
        app,
        ["probe", "--target", "acme-chat://support", "--format", "json", "--output", str(output)],
    )

    assert planned.exit_code == 0, planned.output
    assert probed.exit_code in (0, 1, 2), probed.output
    plan = json.loads(planned.output)
    summary = json.loads(output.read_text(encoding="utf-8"))["run"]["result_summary"]
    ran = set(summary["rules_run"])
    assert _CANARY in plan["rules"]
    assert _CANARY in ran
    assert set(plan["rules"]) == ran
    assert set(plan["skipped"]) == {skip["rule_id"] for skip in summary["rules_skipped"]}


def test_kept_exchanges_of_an_installed_target_built_on_the_endpoint_are_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_endpoint(monkeypatch, _ChatPack)
    output = tmp_path / "probe.json"

    result = runner.invoke(
        app,
        [
            "probe",
            "--target",
            "acme-chat://support",
            "--keep-exchanges",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code in (0, 1, 2), result.output
    kept = tmp_path / "probe.exchanges.jsonl"
    assert kept.exists(), _plain(result.output)
    assert "kept" in _plain(result.output)


def test_kept_exchanges_are_refused_for_an_installed_target_that_keeps_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_endpoint(monkeypatch)
    output = tmp_path / "probe.json"

    result = runner.invoke(
        app,
        [
            "probe",
            "--target",
            "acme-endpoint://deployment/support",
            "--keep-exchanges",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 3, result.output
    assert "keeps none" in _plain(result.output)
    assert not output.exists()


def _install_endpoint(monkeypatch: pytest.MonkeyPatch, target: type[Target] = _Endpoint) -> None:
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    registry.register_target(target)
    monkeypatch.setattr(
        Registry,
        "discover",
        classmethod(lambda cls, trust=True: registry),
    )


def test_probe_runs_an_installed_endpoint_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_endpoint(monkeypatch)
    output = tmp_path / "probe.json"

    result = runner.invoke(
        app,
        [
            "probe",
            "--target",
            "acme-endpoint://deployment/support",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code in (0, 1, 2), result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["run"]["target"]["ref"] == "acme-endpoint://deployment/support"
    canary = next(
        skipped
        for skipped in document["run"]["result_summary"]["rules_skipped"]
        if skipped["rule_id"] == "guardana.prompt.system_prompt_leak.canary"
    )
    assert canary["missing"] == ["plant_system_prompt"]


@pytest.mark.parametrize("status", [400, 503], ids=["request-refused", "target-failed"])
def test_probe_of_an_installed_target_never_saves_or_prints_the_key_it_echoes(
    status: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_endpoint(monkeypatch, _KeyedPack)
    monkeypatch.setattr(_EchoesKey, "status", status)
    output = tmp_path / "probe.json"

    result = runner.invoke(
        app,
        ["probe", "--target", "acme-keyed://support", "--format", "json", "--output", str(output)],
    )

    assert result.exit_code in (2, 4), result.output
    saved = output.read_text(encoding="utf-8")
    assert "bad body for key [redacted:credential]" in saved
    assert _ECHOED_KEY not in saved
    assert _ECHOED_KEY not in result.output
    assert _ECHOED_KEY not in result.stderr


def test_monitor_rebuilds_an_installed_target_for_its_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_endpoint(monkeypatch)

    result = runner.invoke(
        app,
        [
            "monitor",
            "--target",
            "acme-endpoint://deployment/support",
            "--max-cycles",
            "1",
            "--interval",
            "0",
        ],
    )

    assert result.exit_code == 0, result.output


def test_plan_and_inspection_accept_the_same_installed_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_endpoint(monkeypatch)

    planned = runner.invoke(
        app, ["plan", "probe", "--target", "acme-endpoint://deployment/support"]
    )
    inspected = runner.invoke(
        app,
        [
            "target",
            "inspect",
            "--target",
            "acme-endpoint://deployment/support",
            "--format",
            "json",
        ],
    )

    assert planned.exit_code == 0, planned.output
    assert "No request was sent" in planned.output
    assert inspected.exit_code == 0, inspected.output
    assert json.loads(inspected.output)["target"]["ref"] == ("acme-endpoint://deployment/support")


@pytest.mark.parametrize(
    "command",
    [
        ["probe", "--url", "http://legacy", "--model", "m"],
        ["monitor", "--url", "http://legacy", "--model", "m"],
        ["target", "inspect", "--url", "http://legacy", "--model", "m"],
    ],
)
def test_an_endpoint_locator_refuses_legacy_connection_flags(
    command: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_endpoint(monkeypatch)

    result = runner.invoke(
        app,
        [*command, "--target", "acme-endpoint://deployment/support"],
    )

    assert result.exit_code == 3, result.output
    assert "--target cannot be combined" in _plain(result.output)
