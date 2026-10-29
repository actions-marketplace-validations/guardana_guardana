"""An adapter file's `declines:`, `retry_statuses:` and `metadata_paths:` are checked as read.

Each refusal is one that would otherwise let a broken request, a credential failure or a
rate limit read as a guard's verdict, so it is refused before anything is sent.
"""

from pathlib import Path

import pytest
from guardana.core.evaluator.config import wire_config_evaluators
from guardana.core.profile import Profile, ProfileError
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.target import DeclaredDecline, DeclineReading
from guardana.core.target.adapter import DEFAULT_RETRY_STATUSES, AdapterConfig
from guardana.core.target.connection import (
    Connection,
    ConnectionConfigError,
    load_adapter,
    resolve_connection,
)

_URL = "https://api.example.com/chat"
_BODY = 'body:\n  message: "{{prompt}}"\nresponse_path: data.reply\n'


def _adapter(tmp_path: Path, extra: str) -> Path:
    path = tmp_path / "adapter.yaml"
    path.write_text(_BODY + extra, encoding="utf-8")
    return path


def _load(tmp_path: Path, extra: str) -> AdapterConfig:
    return load_adapter(_adapter(tmp_path, extra), url=_URL, environ={}).config


def test_the_three_keys_are_read_as_written(tmp_path: Path) -> None:
    config = _load(
        tmp_path,
        "declines:\n"
        "  - name: content_filter\n"
        "    status: [400, 422]\n"
        "    path: error.code\n"
        "    equals: content_policy\n"
        "    as: refusal\n"
        "  - name: input_rejected\n"
        "    status: 413\n"
        "    as: ungraded\n"
        "retry_statuses: [429, 502, 503]\n"
        "metadata_paths:\n"
        "  guard_category: data.moderation.category\n",
    )

    assert config.declines == (
        DeclaredDecline(
            name="content_filter",
            statuses=frozenset({400, 422}),
            reading=DeclineReading.REFUSAL,
            path="error.code",
            equals="content_policy",
        ),
        DeclaredDecline(
            name="input_rejected", statuses=frozenset({413}), reading=DeclineReading.UNGRADED
        ),
    )
    assert config.retry_statuses == frozenset({429, 502, 503})
    assert config.metadata_paths == {"guard_category": "data.moderation.category"}


def test_an_adapter_without_the_keys_keeps_its_defaults(tmp_path: Path) -> None:
    config = _load(tmp_path, "")

    assert config.declines == ()
    assert config.retry_statuses == DEFAULT_RETRY_STATUSES == frozenset({429, 503})
    assert config.metadata_paths == {}


def test_an_empty_retry_list_retries_nothing(tmp_path: Path) -> None:
    assert _load(tmp_path, "retry_statuses: []\n").retry_statuses == frozenset()


def _decline(status: str, rest: str = "    path: error.code\n    equals: blocked\n") -> str:
    return f"declines:\n  - name: guard\n    status: {status}\n    as: ungraded\n{rest}"


@pytest.mark.parametrize(
    ("extra", "refusal"),
    [
        pytest.param(_decline("302"), "outside 200-299 and 400-499", id="a-redirect-status"),
        pytest.param(_decline("500"), "outside 200-299 and 400-499", id="a-server-error"),
        pytest.param(_decline("100"), "outside 200-299 and 400-499", id="an-informational"),
        *(
            pytest.param(
                "retry_statuses: []\n" + _decline(str(status)),
                "never a decline",
                id=f"status-{status}",
            )
            for status in (401, 403, 404, 407, 408, 425, 429)
        ),
        pytest.param(_decline("429"), "also in retry_statuses", id="a-retried-status"),
        pytest.param(
            "retry_statuses: [408]\n" + _decline("[400, 408]"),
            "also in retry_statuses",
            id="a-retried-status-in-a-list",
        ),
        pytest.param(
            _decline("400", "    path: error.code\n    equals: x\n    when: always\n"),
            "unknown key",
            id="an-unknown-entry-key",
        ),
        pytest.param("decline: []\n", "unknown key", id="an-unknown-top-level-key"),
        pytest.param(
            _decline("400") + _decline("422").removeprefix("declines:\n"),
            "used twice",
            id="a-duplicate-name",
        ),
        pytest.param(_decline("400", "    path: error.code\n"), "together", id="path-alone"),
        pytest.param(_decline("400", "    equals: blocked\n"), "together", id="equals-alone"),
        pytest.param(
            "declines:\n  - name: guard\n    status: 400\n    as: refusal\n",
            "'as: refusal' needs 'path'",
            id="a-refusal-by-status-alone",
        ),
        pytest.param(_decline("200", ""), "a 2xx status needs", id="a-2xx-by-status-alone"),
        pytest.param(
            "declines:\n  - name: Guard\n    status: 413\n    as: ungraded\n",
            "must match",
            id="a-name-out-of-pattern",
        ),
        pytest.param(
            "declines:\n  - status: 413\n    as: ungraded\n", "'name' is required", id="no-name"
        ),
        pytest.param(
            "declines:\n  - name: guard\n    as: ungraded\n", "'status' is required", id="no-status"
        ),
        pytest.param(
            "declines:\n  - name: guard\n    status: 413\n",
            "refusal or ungraded",
            id="no-reading",
        ),
        pytest.param(
            "declines:\n  - name: guard\n    status: 413\n    as: blocked\n",
            "refusal or ungraded",
            id="an-unknown-reading",
        ),
        pytest.param(
            "declines:\n  - name: guard\n    status: true\n    as: ungraded\n",
            "HTTP status",
            id="a-boolean-status",
        ),
        pytest.param(
            "declines:\n  - name: guard\n    status: []\n    as: ungraded\n",
            "names no status",
            id="no-status-in-the-list",
        ),
        pytest.param(
            _decline("400", "    path: error.code\n    equals: [a]\n"),
            "string, number or boolean",
            id="a-list-to-equal",
        ),
        pytest.param("declines: {name: guard}\n", "must be a list", id="declines-not-a-list"),
        pytest.param("retry_statuses: [400]\n", "cannot be retried", id="retrying-a-400"),
        pytest.param("retry_statuses: [200]\n", "cannot be retried", id="retrying-a-200"),
        pytest.param("retry_statuses: 429\n", "must be a list", id="retry-not-a-list"),
        pytest.param(
            "metadata_paths:\n"
            + "".join(f"  name_{index}: meta.v{index}\n" for index in range(17)),
            "at most 16",
            id="seventeen-metadata-names",
        ),
        pytest.param(
            "metadata_paths:\n  Guard-Category: meta.c\n", "must match", id="a-metadata-name"
        ),
        pytest.param("metadata_paths:\n  category: ''\n", "non-empty", id="an-empty-path"),
        pytest.param("metadata_paths: [a]\n", "map a name", id="metadata-not-a-mapping"),
    ],
)
def test_an_adapter_key_it_cannot_honour_is_refused_as_read(
    tmp_path: Path, extra: str, refusal: str
) -> None:
    with pytest.raises(ConnectionConfigError, match=refusal) as refused:
        _load(tmp_path, extra)

    assert str(tmp_path / "adapter.yaml") in str(refused.value)


def test_sixteen_metadata_names_are_accepted(tmp_path: Path) -> None:
    extra = "metadata_paths:\n" + "".join(f"  name_{i}: meta.v{i}\n" for i in range(16))

    assert len(_load(tmp_path, extra).metadata_paths) == 16


def test_an_adapter_built_in_python_is_held_to_the_same_refusals() -> None:
    with pytest.raises(ValueError, match="never a decline"):
        AdapterConfig(
            url=_URL,
            body={"m": "{{prompt}}"},
            response_path="reply",
            declines=(
                DeclaredDecline(
                    name="guard", statuses=frozenset({401}), reading=DeclineReading.UNGRADED
                ),
            ),
        )


@pytest.mark.parametrize("key", ["declines", "metadata_paths"])
def test_a_judge_adapter_refuses_the_keys_only_a_target_reads(tmp_path: Path, key: str) -> None:
    extra = (
        "declines:\n  - name: guard\n    status: 413\n    as: ungraded\n"
        if key == "declines"
        else "metadata_paths:\n  request_id: meta.id\n"
    )
    path = _adapter(tmp_path, extra)

    with pytest.raises(ConnectionConfigError, match=f"drop {key}:"):
        load_adapter(path, url=_URL, environ={}, for_judge=True)
    with pytest.raises(ConnectionConfigError, match=f"drop {key}:"):
        resolve_connection(Connection(_URL, "j", adapter=path), sending=False, for_judge=True)
    assert load_adapter(path, url=_URL, environ={}).config.url == _URL


def test_a_judge_adapter_may_set_its_retried_statuses(tmp_path: Path) -> None:
    path = _adapter(tmp_path, "retry_statuses: [429, 502]\n")

    loaded = load_adapter(path, url=_URL, environ={}, for_judge=True)

    assert loaded.config.retry_statuses == frozenset({429, 502})


def test_a_profile_judge_block_whose_adapter_declares_declines_is_refused(
    tmp_path: Path,
) -> None:
    (tmp_path / "judge.yaml").write_text(
        _BODY + "declines:\n  - name: guard\n    status: 413\n    as: ungraded\n",
        encoding="utf-8",
    )
    profile = Profile(
        name="t",
        policy=Policy(),
        evaluator_config={
            "llm_judge": {"endpoint": _URL, "model": "j", "adapter": "judge.yaml"},
        },
        source=tmp_path / "guardana.yaml",
    )

    with pytest.raises(ProfileError, match=r"evaluators\.llm_judge\.adapter reaches a judge"):
        wire_config_evaluators(Registry(), profile, sending=False)
