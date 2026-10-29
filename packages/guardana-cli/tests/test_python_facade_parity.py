"""The Python facade and the CLI write the same run, for every outcome a run can have.

Each case runs the documented command, saves the run with `--format json --output`, runs
the same target through `guardana.core.verify.Verifier`, and compares the two documents
whole — every channel, the gate, the manifest — after removing only the run id and the
clock. The facade is handed the source and deployment the command reads from the
environment, and the canary token is fixed, so neither needs normalising away.
"""

import json
import os
import pickle
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._run_meta import detect_deployment, detect_source
from guardana.cli.main import app
from guardana.core.budget import Budgets
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Profile, default_profile
from guardana.core.report.baseline import read_baseline
from guardana.core.target import ChatTransport, EndpointTarget
from guardana.core.testing import EchoingTransport, RefusingTransport, ScriptedTransport
from guardana.core.usage import UsageMeter
from guardana.core.verify import Verification, Verifier
from typer.testing import CliRunner

runner = CliRunner()

_BUILTINS = PluginTrust(mode=PluginMode.BUILTINS)
_PER_RUN = ("run_id", "created_at", "started_at", "completed_at")


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


def _comparable(document: dict[str, Any]) -> dict[str, Any]:
    run = {key: value for key, value in document["run"].items() if key not in _PER_RUN}
    run["usage"] = {key: v for key, v in run["usage"].items() if key != "wall_time_seconds"}
    return {**document, "run": run}


def _as_the_cli() -> dict[str, Any]:
    """The facade is told where the run came from; the command reads it from the environment."""
    return {"source": detect_source(), "deployment": detect_deployment()}


def _cli(tmp_path: Path, *args: str) -> tuple[int, dict[str, Any]]:
    out = tmp_path / "cli.json"
    result = runner.invoke(app, [*args, "--format", "json", "--output", str(out)])
    assert out.exists(), result.output
    document: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return result.exit_code, document


def _same(code: int, cli: dict[str, Any], verification: Verification) -> None:
    assert verification.exit_code == code
    assert _comparable(verification.document()) == _comparable(cli)


# Files


def _tree(tmp_path: Path, files: dict[str, bytes]) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    for name, content in files.items():
        (root / name).write_bytes(content)
    return root


_CASES: dict[str, tuple[dict[str, bytes], int]] = {
    "pass": ({"app.py": b"print('hello')\n"}, 0),
    "fail": ({"model.pkl": pickle.dumps(_Evil())}, 1),
    "unverified": (
        {"nb.ipynb": b'{"cells": [{"cell_type": "code", "source": "def (\\n"}]}'},
        0,
    ),
    "indeterminate": ({"model.tflite": b"TFL3" + b"\x00" * 16}, 2),
    "unread": ({"model.onnx": b"\xff" * 11}, 2),
}


@pytest.mark.parametrize("case", _CASES)
def test_a_scan_writes_the_same_run_from_python_and_from_the_cli(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files, code = _CASES[case]
    root = _tree(tmp_path, files)
    monkeypatch.chdir(tmp_path)

    cli_code, cli = _cli(tmp_path, "scan", "tree")
    verification = Verifier(trust=_BUILTINS).scan(
        Path("tree"), relative_to=tmp_path, **_as_the_cli()
    )

    assert cli_code == code
    _same(code, cli, verification)
    assert root.exists()


def test_a_baseline_waives_the_same_findings_from_python_and_from_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _tree(tmp_path, {"model.pkl": pickle.dumps(_Evil())})
    monkeypatch.chdir(tmp_path)
    baseline = tmp_path / "baseline.yaml"
    assert runner.invoke(app, ["scan", "tree", "--write-baseline", str(baseline)]).exit_code == 0

    cli_code, cli = _cli(tmp_path, "scan", "tree", "--baseline", str(baseline))
    verification = Verifier(trust=_BUILTINS).scan(
        Path("tree"), relative_to=tmp_path, baseline=read_baseline(baseline), **_as_the_cli()
    )

    assert cli_code == 0
    assert verification.result.waived
    _same(0, cli, verification)


def test_a_check_that_could_not_run_is_an_error_in_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _tree(tmp_path, {"app.py": b"print('hello')\n"})
    locked = root / "locked"
    locked.mkdir()
    (locked / "model.pkl").write_bytes(pickle.dumps(_Evil()))
    locked.chmod(0)
    monkeypatch.chdir(tmp_path)
    try:
        cli_code, cli = _cli(tmp_path, "scan", "tree")
        verification = Verifier(trust=_BUILTINS).scan(
            Path("tree"), relative_to=tmp_path, **_as_the_cli()
        )
    finally:
        locked.chmod(0o755)

    assert cli_code == 2
    assert verification.result.errors
    _same(2, cli, verification)


# Endpoints


def _probe_profile(budgets: Budgets | None = None) -> Profile:
    profile = default_profile()
    return profile if budgets is None else replace(profile, budgets=budgets)


def _endpoint(transport: ChatTransport, profile: Profile) -> EndpointTarget:
    return EndpointTarget(
        "http://fake", "m", transport=transport, meter=UsageMeter(profile.budgets)
    )


_PROBES: dict[str, tuple[Callable[[], ChatTransport], tuple[str, ...], Budgets | None, int]] = {
    "pass": (RefusingTransport, (), None, 0),
    "fail": (EchoingTransport, (), None, 1),
    "indeterminate": (lambda: ScriptedTransport(""), (), None, 2),
    "budget stop": (RefusingTransport, ("--max-requests", "2"), Budgets(max_requests=2), 6),
}


@pytest.mark.parametrize("case", _PROBES)
def test_a_probe_writes_the_same_run_from_python_and_from_the_cli(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport, flags, budgets, code = _PROBES[case]
    monkeypatch.setattr(endpoint_module, "transport_factory", transport)
    monkeypatch.setattr("guardana.core.probe.secrets.token_hex", lambda n: "c" * 2 * n)
    profile = _probe_profile(budgets)

    cli_code, cli = _cli(
        tmp_path, "probe", "--url", "http://fake", "--model", "m", "--concurrency", "1", *flags
    )
    verification = Verifier(trust=_BUILTINS, profile=profile, concurrency=1).run(
        _endpoint(transport(), profile), **_as_the_cli()
    )

    assert cli_code == code
    _same(code, cli, verification)


def test_a_failed_run_is_returned_as_data_never_raised(tmp_path: Path) -> None:
    profile = _probe_profile()

    verification = Verifier(trust=_BUILTINS, profile=profile, concurrency=1).run(
        _endpoint(EchoingTransport(), profile)
    )

    assert not verification.passed
    assert verification.result.findings
    assert verification.manifest.result_summary.gate == verification.gate
