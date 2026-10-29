import io
import re
from collections.abc import Callable
from dataclasses import replace
from email.message import Message
from urllib.error import HTTPError, URLError

import guardana.cli._endpoint as endpoint_module
import pytest
import typer
from guardana.cli._errors import EndpointFlag, remedies_for, run_against_endpoint
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.profile import default_profile
from guardana.core.redaction import EvidenceMode, RedactionPolicy
from guardana.core.target import EndpointError
from guardana.core.testing import FailingTransport
from typer.testing import CliRunner

runner = CliRunner()

_POLICY = default_profile().privacy

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def normalised(output: str) -> str:
    """Flatten styling and wrapping, which differ between a laptop and a CI runner."""
    return " ".join(_ANSI.sub("", output).replace("\u2502", " ").split())


def _rejects_the_request() -> FailingTransport:
    return FailingTransport(HTTPError("http://x", 401, "Unauthorized", {}, None))  # type: ignore[arg-type]


def test_4xx_reports_rejected_distinctly(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise HTTPError("http://x", 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action, privacy=_POLICY)
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    assert "rejected" in capsys.readouterr().err.lower()


def test_a_sustained_rate_limit_names_the_knob_that_fixes_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Reaching the CLI means the transport already retried with backoff, so the
    # generic 4xx advice ("check your auth header") would send someone to debug a
    # header that is working. The actionable answer is the concurrency limit.
    def action() -> None:
        raise HTTPError("http://x", 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint(
            "http://x", action, privacy=_POLICY, accepts=(EndpointFlag.CONCURRENCY,)
        )
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    err = capsys.readouterr().err.lower()
    assert "--concurrency" in err
    assert "auth" not in err


def test_unreachable_host_reports_could_not_reach(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise URLError("connection refused")

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action, privacy=_POLICY)
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    assert "could not reach" in capsys.readouterr().err.lower()


def test_advice_never_names_a_flag_the_command_does_not_take(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Advice the command would reject costs the reader a second failed run, so a
    # message names only the flags of the command it is printed from.
    def action() -> None:
        raise HTTPError("http://x", 401, "Unauthorized", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit):
        run_against_endpoint(
            "http://x", action, privacy=_POLICY, accepts=(EndpointFlag.API_KEY_ENV,)
        )
    err = normalised(capsys.readouterr().err)
    assert "rejected the request (HTTP 401)" in err
    assert "--adapter" not in err
    assert "--api-key-env" in err
    assert "token-env" not in err


@pytest.mark.parametrize(
    "flag", [EndpointFlag.MCP_TOKEN_ENV, EndpointFlag.A2A_TOKEN_ENV], ids=["mcp", "a2a"]
)
def test_a_refused_credential_names_the_token_flag_of_the_command(flag: EndpointFlag) -> None:
    advice = remedies_for((flag,)).auth

    assert f"{flag} names the variable holding the bearer token" in advice
    assert "--api-key-env" not in advice
    assert "--adapter" not in advice
    other = {EndpointFlag.MCP_TOKEN_ENV, EndpointFlag.A2A_TOKEN_ENV} - {flag}
    assert all(str(o) not in advice for o in other)


@pytest.mark.parametrize(
    "command", [["probe"], ["target", "inspect"]], ids=["probe", "target-inspect"]
)
def test_every_command_taking_an_adapter_names_it(
    monkeypatch: pytest.MonkeyPatch, command: list[str]
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _rejects_the_request)

    result = runner.invoke(app, [*command, "--url", "http://x", "--model", "m"])

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    err = normalised(result.output)
    assert "rejected the request (HTTP 401)" in err
    assert "--adapter" in err
    assert "--api-key-env" in err


def test_a_rate_limit_names_concurrency_only_where_it_exists(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def action() -> None:
        raise HTTPError("http://x", 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]

    with pytest.raises(typer.Exit):
        run_against_endpoint(
            "http://x", action, privacy=_POLICY, accepts=(EndpointFlag.API_KEY_ENV,)
        )
    err = normalised(capsys.readouterr().err)
    assert "--concurrency" not in err
    assert "wait for the quota to reset" in err


def _fails_with(status: int, body: bytes) -> Callable[[], None]:
    def action() -> None:
        raise HTTPError("http://x", status, "status", Message(), io.BytesIO(body))

    return action


def _message(
    capsys: pytest.CaptureFixture[str],
    status: int,
    body: bytes,
    *,
    privacy: RedactionPolicy = _POLICY,
    secrets: tuple[str, ...] = (),
) -> str:
    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint(
            "http://x",
            _fails_with(status, body),
            privacy=privacy,
            secrets=secrets,
            accepts=tuple(EndpointFlag),
        )
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    return capsys.readouterr().err


def test_a_4xx_that_is_not_about_credentials_quotes_the_body_instead_of_blaming_the_header(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = _message(capsys, 400, b'{"detail":{"code":"input_rejected"}}')

    assert "rejected the request (HTTP 400); its body begins: " in err
    assert '{"detail":{"code":"input_rejected"}}' in err
    assert "auth" not in err


@pytest.mark.parametrize("status", [401, 403, 407])
def test_a_credentials_status_keeps_the_auth_advice(
    capsys: pytest.CaptureFixture[str], status: int
) -> None:
    err = _message(capsys, status, b"denied")

    assert f"rejected the request (HTTP {status})" in err
    assert "check the auth header" in err


def test_the_quoted_body_is_bounded_redacted_and_escaped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = b"sk-ant-api03-" + b"a" * 95 + b"AA"
    err = _message(capsys, 422, b"bad\x1b[31m\n" + secret + b" " + b"x" * 1000)

    assert secret.decode() not in err
    assert "[redacted:" in err
    assert "\x1b" not in err
    assert "bad\\x1b[31m\\n" in err
    quoted = err.split("its body begins: ", 1)[1].rstrip("\n")
    assert len(quoted) == 201
    assert quoted.endswith("…")


def test_an_empty_body_is_named_rather_than_quoted(capsys: pytest.CaptureFixture[str]) -> None:
    assert "its body was empty" in _message(capsys, 404, b"")


def test_a_5xx_quotes_its_body_too(capsys: pytest.CaptureFixture[str]) -> None:
    err = _message(capsys, 503, b'{"detail":{"code":"chat_disabled"}}')

    assert "returned HTTP 503; its body begins:" in err
    assert "chat_disabled" in err


_KEY = "acme-live-0123456789abcdef"
_EMAIL = "someone@example.com"
_IP = "203.0.113.7"
_ECHO = f'{{"error":"bad key {_KEY} for {_EMAIL} from {_IP}"}}'.encode()


def test_the_quoted_body_follows_the_run_policy_and_never_holds_a_sent_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = _message(capsys, 400, _ECHO, secrets=(_KEY,))

    assert _KEY not in err
    assert "[redacted:credential]" in err
    assert _EMAIL not in err
    assert "[redacted:email:" in err
    assert _IP in err


def test_a_policy_that_redacts_addresses_removes_them_from_the_quote(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = _message(
        capsys, 503, _ECHO, privacy=replace(_POLICY, redact_ip_addresses=True), secrets=(_KEY,)
    )

    assert _IP not in err
    assert "[redacted:ip:" in err


def test_metadata_only_gives_the_status_and_the_size_and_quotes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = normalised(
        _message(
            capsys,
            400,
            _ECHO,
            privacy=RedactionPolicy(mode=EvidenceMode.METADATA_ONLY),
            secrets=(_KEY,),
        )
    )

    assert "rejected the request (HTTP 400)" in err
    assert f"its body ({len(_ECHO)} bytes) is not shown under evidence mode metadata_only" in err
    assert "bad key" not in err
    assert _EMAIL not in err


def _unusable_reply(capsys: pytest.CaptureFixture[str], privacy: RedactionPolicy) -> str:
    def action() -> None:
        raise EndpointError(f"unexpected response from http://x: {_ECHO!r}")

    with pytest.raises(typer.Exit) as exc:
        run_against_endpoint("http://x", action, privacy=privacy, secrets=(_KEY,))
    assert exc.value.exit_code == ExitCode.TARGET_UNAVAILABLE
    return normalised(capsys.readouterr().err)


def test_an_unusable_reply_is_quoted_under_the_run_policy_without_a_sent_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = _unusable_reply(capsys, _POLICY)

    assert "could not reach endpoint http://x: unexpected response" in err
    assert _KEY not in err
    assert _EMAIL not in err


def test_an_unusable_reply_under_metadata_only_gives_its_kind_and_size_and_quotes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = _unusable_reply(capsys, RedactionPolicy(mode=EvidenceMode.METADATA_ONLY))

    assert "could not reach endpoint http://x: EndpointError, its detail (" in err
    assert "bytes) is not shown under evidence mode metadata_only" in err
    assert "unexpected response" not in err
    assert "bad key" not in err


def test_a_value_too_short_to_tell_apart_is_not_withheld_from_the_quote(
    capsys: pytest.CaptureFixture[str],
) -> None:
    err = _message(capsys, 400, b"no such route", secrets=("o",))

    assert "no such route" in err


def test_the_key_a_probe_sends_never_reaches_its_error_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def echoes_the_key() -> FailingTransport:
        body = f"key {_KEY} is not valid here".encode()
        return FailingTransport(HTTPError("http://x", 400, "bad", Message(), io.BytesIO(body)))

    monkeypatch.setattr(endpoint_module, "transport_factory", echoes_the_key)
    monkeypatch.setenv("ACME_KEY", _KEY)

    result = runner.invoke(
        app, ["probe", "--url", "http://x", "--model", "m", "--api-key-env", "ACME_KEY"]
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert "is not valid here" in normalised(result.output)
    assert _KEY not in result.output
