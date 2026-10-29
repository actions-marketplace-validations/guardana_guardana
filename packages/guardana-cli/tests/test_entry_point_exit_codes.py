"""The installed `guardana` command maps a crash to 5 and an interrupt to 7.

`CliRunner` invokes `app` and never sees what the console script does with an
exception that escapes it, so these tests call `main()` — the function the entry
point names — and read the `SystemExit` it ends with.
"""

from collections.abc import Callable
from importlib.metadata import entry_points

import pytest
import typer
from guardana.cli import main as cli_main
from guardana.cli.exit_codes import ExitCode

_PAYLOAD = "payload-that-must-not-reach-stderr"


def _app_whose_command(behaviour: Callable[[], None]) -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def only() -> None:
        behaviour()

    return app


def _crash() -> None:
    raise RuntimeError(_PAYLOAD)


def _interrupt() -> None:
    raise KeyboardInterrupt


def _exit_code_of(argv: list[str] | None = None) -> object:
    with pytest.raises(SystemExit) as stopped:
        cli_main.main(argv)
    return stopped.value.code


def test_an_uncaught_exception_exits_internal_error_with_one_line_and_no_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    monkeypatch.setattr(cli_main, "app", _app_whose_command(_crash))

    code = _exit_code_of([])

    stderr = capsys.readouterr().err
    assert code == int(ExitCode.INTERNAL_ERROR)
    assert len(stderr.strip().splitlines()) == 1
    assert "RuntimeError" in stderr
    assert "GUARDANA_DEBUG=1" in stderr
    assert "defect" in stderr
    assert "Traceback" not in stderr
    assert _PAYLOAD not in stderr


def test_guardana_debug_prints_the_traceback_of_a_crash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DEBUG", "1")
    monkeypatch.setattr(cli_main, "app", _app_whose_command(_crash))

    code = _exit_code_of([])

    stderr = capsys.readouterr().err
    assert code == int(ExitCode.INTERNAL_ERROR)
    assert "Traceback" in stderr
    assert _PAYLOAD in stderr


def test_guardana_debug_set_to_anything_but_one_keeps_the_traceback_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DEBUG", "true")
    monkeypatch.setattr(cli_main, "app", _app_whose_command(_crash))

    code = _exit_code_of([])

    stderr = capsys.readouterr().err
    assert code == int(ExitCode.INTERNAL_ERROR)
    assert "Traceback" not in stderr
    assert _PAYLOAD not in stderr


def test_ctrl_c_inside_a_command_exits_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli_main, "app", _app_whose_command(_interrupt))

    code = _exit_code_of([])

    stderr = capsys.readouterr().err
    assert code == int(ExitCode.INTERRUPTED)
    assert len(stderr.strip().splitlines()) == 1
    assert "interrupted" in stderr


def test_a_keyboard_interrupt_outside_click_exits_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def raw_app(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main, "app", raw_app)

    code = _exit_code_of([])

    assert code == int(ExitCode.INTERRUPTED)
    assert "interrupted" in capsys.readouterr().err


def test_exit_130_from_a_command_becomes_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    def exit_130() -> None:
        raise typer.Exit(130)

    monkeypatch.setattr(cli_main, "app", _app_whose_command(exit_130))

    assert _exit_code_of([]) == int(ExitCode.INTERRUPTED)


@pytest.mark.parametrize(
    "exit_code",
    [
        ExitCode.OK,
        ExitCode.POLICY_FAILED,
        ExitCode.INDETERMINATE,
        ExitCode.INVALID_USAGE,
        ExitCode.TARGET_UNAVAILABLE,
        ExitCode.BUDGET_EXHAUSTED,
    ],
)
def test_a_command_exit_code_passes_through_unchanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], exit_code: ExitCode
) -> None:
    def exit_with_code() -> None:
        raise typer.Exit(int(exit_code))

    monkeypatch.setattr(cli_main, "app", _app_whose_command(exit_with_code))

    assert _exit_code_of([]) == int(exit_code)
    assert capsys.readouterr().err == ""


def test_the_real_app_exits_zero_for_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert _exit_code_of(["--version"]) == int(ExitCode.OK)
    assert capsys.readouterr().out.startswith("guardana ")


def test_the_real_app_keeps_invalid_usage_for_an_unknown_option() -> None:
    assert _exit_code_of(["scan", "--no-such-option"]) == int(ExitCode.INVALID_USAGE)


def test_the_console_script_points_at_main() -> None:
    (script,) = entry_points(group="console_scripts", name="guardana")

    assert script.value == "guardana.cli.main:main"
    assert script.load() is cli_main.main
