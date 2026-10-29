"""The registry a probe pass runs from reports what the discovering registry could not load.

A refusal read as an ordinary failure, or dropped outright, changes what the gate and the
hint say about a pack the user installed.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from _fake_distribution import EXPLODING_MODULE, MARKING_MODULE, FakeSite
from guardana.core.entrypoints import EVALUATOR_GROUP, RULE_GROUP
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.probe import _sub_registry
from guardana.core.registry import Registry
from guardana.core.report import CheckError


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSite]:
    (tmp_path / "site").mkdir()
    fake = FakeSite(tmp_path / "site", monkeypatch)
    yield fake
    fake.forget_imports()


def test_a_probe_pass_keeps_the_refusals_apart_from_the_failures(site: FakeSite) -> None:
    site.distribution("acme-rules", (RULE_GROUP, "acme", site.module(MARKING_MODULE).name))
    parent = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    parent.record_load_error(CheckError(source="broken.yaml", stage="load", reason="bad"))

    sub = _sub_registry(list(parent.rules()[:1]), parent)

    assert [ep.distribution for ep in sub.refused] == ["acme-rules"]
    assert sub.refused == parent.refused
    assert sub.load_failures == parent.load_failures
    assert [error.source for error in sub.load_failures] == ["broken.yaml"]
    assert sub.load_errors == parent.load_errors
    assert len(sub.rules()) == 1


def test_a_probe_pass_keeps_which_entry_point_each_failure_belongs_to(site: FakeSite) -> None:
    calm = site.module(MARKING_MODULE)
    boom = site.module(EXPLODING_MODULE)
    site.distribution(
        "Acme_Rules", (RULE_GROUP, "acme", calm.name), (EVALUATOR_GROUP, "acme", boom.name)
    )
    parent = Registry.discover(PluginTrust(mode=PluginMode.ALL))

    sub = _sub_registry(list(parent.rules()[:1]), parent)

    assert [(ep.group, ep.module) for ep, _ in sub.failed if ep.distribution == "Acme_Rules"] == [
        (EVALUATOR_GROUP, boom.name)
    ]
    assert sub.failed == parent.failed
    assert all(any(error is f for f in sub.load_failures) for _, error in sub.failed)
