"""A text file a rule read only up to the read bound is never cleared.

Where a padded file is how an attacker hides from a rule — a manifest, a model
config, a model card — the file is a coverage gap and the scan cannot pass. The
secret scan reads every text file, a large data file included, so a file it read
only in part is reported unverified, which `fail_on_inconclusive` makes fail.
"""

import functools
import json
from pathlib import Path
from types import ModuleType

import pytest
from guardana.cli.main import app
from guardana.core.testing import fake_aws_key
from guardana.rules.supply_chain import (
    _reading,
    hardcoded_secret,
    malicious_dependency,
    provenance,
    remote_code_config,
)
from typer.testing import CliRunner

runner = CliRunner()

_BOUND = 1024
_DOT_ENV = "." + "env"

_CASES: dict[str, tuple[ModuleType, str, str, str]] = {
    "hardcoded_secret": (
        hardcoded_secret,
        "read_bytes_bounded",
        _DOT_ENV,
        "X=1\n" * 400 + f"AWS_KEY={fake_aws_key()}\n",
    ),
    "malicious_dependency": (
        malicious_dependency,
        "read_text_prefix",
        "requirements.txt",
        "# pinned below\n" * 100 + "ultralytics==8.3.41\n",
    ),
    "remote_code_config": (
        remote_code_config,
        "read_text_prefix",
        "config.json",
        json.dumps({"padding": "x" * 2000, "_attn_implementation": "kernels-community/flash"}),
    ),
    "provenance": (
        provenance,
        "read_text_prefix",
        "README.md",
        "# Model card\n" + "Details.\n" * 200 + "License: AGPL\n",
    ),
}


def _scan(
    tmp_path: Path, rule: str, *, bounded: bool, strict: bool = False
) -> tuple[int, list[str], list[str]]:
    module, reader, name, text = _CASES[rule]
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / name).write_text(text, encoding="utf-8")
    saved = tmp_path / "run.json"
    with pytest.MonkeyPatch.context() as patch:
        if bounded:
            patch.setattr(
                module, reader, functools.partial(getattr(_reading, reader), limit=_BOUND)
            )
        profile = tmp_path / "profile.yaml"
        profile.write_text(f"fail_on: {{fail_on_inconclusive: {str(strict).lower()}}}\n")
        result = runner.invoke(
            app,
            [
                "scan",
                str(tree),
                "--profile",
                str(profile),
                "--format",
                "json",
                "--output",
                str(saved),
            ],
        )
    document = json.loads(saved.read_text(encoding="utf-8"))
    return (
        result.exit_code,
        [finding["rule_id"] for finding in document["findings"]],
        [finding["rule_id"] for finding in document["unverified"]],
    )


@pytest.mark.parametrize("rule", sorted(_CASES))
def test_control_the_whole_file_is_read_and_its_finding_reported(tmp_path: Path, rule: str) -> None:
    _code, found, _unverified = _scan(tmp_path, rule, bounded=False)

    assert f"guardana.supply_chain.{rule}" in found


@pytest.mark.parametrize("rule", sorted(set(_CASES) - {"hardcoded_secret"}))
def test_a_file_cut_at_the_read_bound_never_passes_the_scan(tmp_path: Path, rule: str) -> None:
    code, found, unverified = _scan(tmp_path, rule, bounded=True)
    if f"guardana.supply_chain.{rule}" not in unverified or found:
        raise RuntimeError(f"precondition: the rule should report the file unread ({found})")

    assert code != 0, (code, unverified)


def test_a_secret_file_cut_at_the_read_bound_is_reported_unverified(tmp_path: Path) -> None:
    code, found, unverified = _scan(tmp_path, "hardcoded_secret", bounded=True)

    assert (code, found) == (0, [])
    assert "guardana.supply_chain.hardcoded_secret" in unverified


def test_a_secret_file_cut_at_the_read_bound_fails_a_strict_gate(tmp_path: Path) -> None:
    code, _found, unverified = _scan(tmp_path, "hardcoded_secret", bounded=True, strict=True)

    assert code != 0, unverified
