"""A `--reporter` URL is refused without ever printing the password it carries."""

from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_PASSWORD = "SYNTHETIC-" + "REPORTER-PASSWORD"


def _refusal(tmp_path: Path, colon: str) -> tuple[int, str]:
    reporter = f"server://https://user:{_PASSWORD}@collector.example.com{colon}443"
    result = runner.invoke(app, ["scan", str(tmp_path), "--reporter", reporter])
    return result.exit_code, result.output


def test_control_userinfo_is_refused_without_the_password(tmp_path: Path) -> None:
    code, said = _refusal(tmp_path, ":")

    assert (code, _PASSWORD in said, "userinfo" in said) == (ExitCode.INVALID_USAGE, False, True)


def test_a_fullwidth_colon_is_refused_without_the_password(tmp_path: Path) -> None:
    code, said = _refusal(tmp_path, "\N{FULLWIDTH COLON}")
    leaked = _PASSWORD in said

    assert (code, leaked) == (ExitCode.INVALID_USAGE, False), said.replace(_PASSWORD, "<pw>")


def test_no_part_of_a_password_holding_a_query_mark_is_printed(tmp_path: Path) -> None:
    head = "SYNTHETIC[" + "HEAD"
    reporter = f"server://https://ops:{head}?{_PASSWORD}@collector.example.com"
    result = runner.invoke(app, ["scan", str(tmp_path), "--reporter", reporter])

    assert result.exit_code == ExitCode.INVALID_USAGE
    assert head not in result.output, result.output
    assert _PASSWORD not in result.output
