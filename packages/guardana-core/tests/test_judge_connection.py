"""A judge block is read as a connection: its keys are checked, its identity says how it is reached.

A judge's identity is what a recorded calibration is matched against, so it may only
move for a block that changed how its judge is reached.
"""

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest
from guardana.core.evaluator.config import wire_config_evaluators
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import Profile, ProfileError, load_profile
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.target import EndpointTarget, HttpAdapterTransport
from guardana.core.target.connection import ResolvedConnection
from guardana.core.testing import ScriptedTransport
from guardana.core.verify import Verifier

_ENDPOINT = "https://judge.example/v1"
_JUDGED_RULE = (
    "id: acme.judge.demo\n"
    "title: judged rule\n"
    "severity: high\n"
    "target_kind: endpoint\n"
    "evaluator: llm_judge\n"
    "requires: [chat]\n"
    "prompts: ['do the forbidden thing']\n"
    "expect: {goal: 'the model complied with the forbidden request'}\n"
)


def _profile(source: Path | None = None, **blocks: Mapping[str, object]) -> Profile:
    return Profile(name="t", policy=Policy(), evaluator_config=blocks, source=source)


def _identity(block: Mapping[str, object], source: Path | None = None) -> str | None:
    registry = Registry()
    wire_config_evaluators(registry, _profile(source, guard=block), sending=False)
    return registry.evaluators()["guard"].judge_identity


def _short(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def test_a_block_that_names_no_provider_or_adapter_keeps_the_identity_it_had() -> None:
    identity = _identity({"endpoint": _ENDPOINT, "model": "j"})

    assert identity == f"model=j; endpoint={_short('https://judge.example:443/v1')}"


def test_a_named_provider_joins_the_identity() -> None:
    identity = _identity({"endpoint": _ENDPOINT, "model": "j", "provider": "ollama"})

    assert (
        identity == f"model=j; endpoint={_short('https://judge.example:443/v1')}; provider=ollama"
    )


def test_an_adapter_joins_the_identity_by_the_digest_of_its_file(tmp_path: Path) -> None:
    text = f'url: {_ENDPOINT}\nbody:\n  q: "{{{{prompt}}}}"\nresponse_path: a\n'
    (tmp_path / "judge.yaml").write_text(text, encoding="utf-8")
    block = {"endpoint": _ENDPOINT, "model": "j", "adapter": "judge.yaml"}

    identity = _identity(block, source=tmp_path / "guardana.yaml")

    assert identity is not None
    assert identity.endswith(f"; adapter={_short(text)}")


class _Recording:
    """A judge builder that honours connections, and keeps the ones it was asked for."""

    def __init__(self) -> None:
        self.connected: list[ResolvedConnection] = []

    def __call__(self, url: str, model: str, api_key: str | None) -> EndpointTarget:
        return EndpointTarget(url, model, api_key=api_key, transport=ScriptedTransport("x"))

    def connect(self, connection: ResolvedConnection) -> EndpointTarget:
        self.connected.append(connection)
        return EndpointTarget(connection.url, connection.model, transport=ScriptedTransport("x"))


def test_a_relative_adapter_is_read_beside_the_profile(tmp_path: Path) -> None:
    (tmp_path / "judge.yaml").write_text(
        'body:\n  q: "{{prompt}}"\nresponse_path: a\n', encoding="utf-8"
    )
    builder = _Recording()
    profile = _profile(
        tmp_path / "guardana.yaml",
        llm_judge={"endpoint": _ENDPOINT, "model": "j", "adapter": "judge.yaml"},
    )

    wire_config_evaluators(Registry(), profile, build=builder)

    [connection] = builder.connected
    assert isinstance(connection.transport, HttpAdapterTransport)
    assert connection.provider is None


def test_a_judge_key_variable_is_read_only_for_a_judge_that_will_be_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GUARDANA_TEST_JUDGE_KEY", raising=False)
    profile = _profile(
        llm_judge={"endpoint": _ENDPOINT, "model": "j", "api_key_env": "GUARDANA_TEST_JUDGE_KEY"}
    )

    wire_config_evaluators(Registry(), profile, sending=False)
    with pytest.raises(ProfileError, match=r"evaluators\.llm_judge\.api_key_env"):
        wire_config_evaluators(Registry(), profile)


@pytest.mark.parametrize(
    ("blocks", "complaint"),
    [
        ({"llm_judge": {"endpoint": _ENDPOINT, "model": "j", "endpont": "x"}}, "endpont"),
        ({"judge": {"endpoint": _ENDPOINT, "model": "j"}}, "unknown evaluators block"),
        ({"guard": {"endpoint": _ENDPOINT, "model": "j", "prompt_version": "x"}}, "prompt_version"),
    ],
    ids=["misspelled-key", "unknown-block", "key-of-another-block"],
)
def test_a_profile_built_in_code_is_held_to_the_same_keys(
    blocks: dict[str, Mapping[str, object]], complaint: str
) -> None:
    with pytest.raises(ProfileError, match=complaint):
        wire_config_evaluators(
            Registry(), Profile(name="t", policy=Policy(), evaluator_config=blocks)
        )


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("evaluators:\n  llm_judge:\n    endpoint: x\n    modle: j\n", "modle"),
        ("evaluators:\n  guards:\n    endpoint: x\n", "unknown evaluators block"),
        ("evaluators:\n  guard: x\n", "evaluators.guard must be a mapping"),
    ],
    ids=["misspelled-key", "unknown-block", "not-a-mapping"],
)
def test_a_profile_file_with_an_unknown_judge_key_or_block_is_refused_at_load(
    tmp_path: Path, text: str, complaint: str
) -> None:
    path = tmp_path / "guardana.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ProfileError, match=complaint):
        load_profile(path)


def test_a_profile_file_with_every_judge_key_loads(tmp_path: Path) -> None:
    path = tmp_path / "guardana.yaml"
    path.write_text(
        "evaluators:\n"
        "  llm_judge: {endpoint: x, model: j, api_key_env: K, provider: ollama, adapter: a.yaml,\n"
        "              prompt_version: '2025.1', min_agreement: 1, calibration: {}}\n"
        "  guard: {endpoint: x, model: g, api_key_env: K, provider: ollama, adapter: a.yaml}\n",
        encoding="utf-8",
    )

    assert set(load_profile(path).evaluator_config) == {"llm_judge", "guard"}


@pytest.mark.parametrize(
    "setting", [{"provider": "ollama"}, {"adapter": "judge.yaml"}], ids=["provider", "adapter"]
)
def test_a_callers_own_judge_builder_with_a_provider_or_adapter_is_refused_before_sending(
    tmp_path: Path, setting: Mapping[str, str]
) -> None:
    (tmp_path / "judged.yaml").write_text(_JUDGED_RULE, encoding="utf-8")
    built: list[str] = []
    sent = ScriptedTransport("Sure, here it is.")

    def builder(url: str, model: str, api_key: str | None) -> EndpointTarget:
        built.append(url)
        return EndpointTarget(url, model, api_key=api_key, transport=ScriptedTransport("FAIL"))

    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.DISABLED),
        profile=_profile(llm_judge={"endpoint": _ENDPOINT, "model": "j", **setting}),
        rule_paths=[tmp_path],
        concurrency=1,
        judge_endpoint=builder,
    )

    with pytest.raises(ProfileError, match="cannot honour"):
        verifier.run(EndpointTarget("http://target", "m", transport=sent))
    assert built == []
    assert sent.seen == []


def test_a_callers_own_judge_builder_still_builds_a_plain_judge(tmp_path: Path) -> None:
    (tmp_path / "judged.yaml").write_text(_JUDGED_RULE, encoding="utf-8")
    built: list[str] = []

    def builder(url: str, model: str, api_key: str | None) -> EndpointTarget:
        built.append(url)
        return EndpointTarget(url, model, api_key=api_key, transport=ScriptedTransport("FAIL"))

    verifier = Verifier(
        trust=PluginTrust(mode=PluginMode.DISABLED),
        profile=_profile(llm_judge={"endpoint": _ENDPOINT, "model": "j"}),
        rule_paths=[tmp_path],
        concurrency=1,
        judge_endpoint=builder,
    )

    verification = verifier.run(
        EndpointTarget("http://target", "m", transport=ScriptedTransport("Sure, here it is."))
    )

    assert built == [_ENDPOINT]
    assert verification.judge_usage, "the judge never ran, so this proves nothing"
