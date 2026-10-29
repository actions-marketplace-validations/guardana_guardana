"""A team states its plugin trust once, in `guardana.yaml`, and a typo there fails loudly.

A trust that silently fell back to a default would load code the author believes
they excluded, or refuse a pack they believe they admitted.
"""

from pathlib import Path

import pytest
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import PRESET_NAMES, ProfileError, default_profile, load_profile, preset


def _load(tmp_path: Path, body: str) -> PluginTrust | None:
    path = tmp_path / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return load_profile(path).plugins


@pytest.mark.parametrize("mode", ["all", "builtins", "disabled"])
def test_every_mode_without_names_is_accepted(tmp_path: Path, mode: str) -> None:
    assert _load(tmp_path, f"plugins:\n  mode: {mode}\n") == PluginTrust(mode=PluginMode(mode))


def test_an_allowlist_carries_the_names_as_written(tmp_path: Path) -> None:
    trust = _load(tmp_path, "plugins:\n  mode: allowlist\n  allow: [acme-rules, Other_Pack]\n")

    assert trust == PluginTrust(
        mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-rules", "Other_Pack"})
    )
    assert trust.allows("other-pack")


def test_a_profile_that_does_not_mention_plugins_states_no_trust(tmp_path: Path) -> None:
    assert _load(tmp_path, "name: t\n") is None


def test_presets_and_the_default_profile_state_no_trust() -> None:
    assert default_profile().plugins is None
    for name in PRESET_NAMES:
        assert preset(name).plugins is None, name


@pytest.mark.parametrize(
    ("body", "complaint"),
    [
        ("plugins:\n  mode: some\n", "plugins.mode"),
        ("plugins:\n  mode: 3\n", "plugins.mode"),
        ("plugins: {}\n", "plugins.mode"),
        ("plugins:\n  allow: [acme-rules]\n", "plugins.mode"),
        ("plugins: builtins\n", "'plugins' must be a mapping"),
        ("plugins:\n  mode: all\n  trust: everyone\n", "unknown plugins key"),
        ("plugins:\n  mode: builtins\n  allow: [acme-rules]\n", "plugins.allow"),
        ("plugins:\n  mode: all\n  allow: []\n", "plugins.allow"),
        ("plugins:\n  mode: allowlist\n", "plugins.allow"),
        ("plugins:\n  mode: allowlist\n  allow: []\n", "plugins.allow"),
        ("plugins:\n  mode: allowlist\n  allow: acme-rules\n", "plugins.allow"),
        ("plugins:\n  mode: allowlist\n  allow: ['  ']\n", "plugins.allow"),
    ],
    ids=[
        "unknown mode",
        "non-string mode",
        "no mode",
        "names without a mode",
        "not a mapping",
        "unknown sub-key",
        "names beside builtins",
        "names beside all",
        "allowlist without names",
        "allowlist with an empty list",
        "names as a string",
        "a blank name",
    ],
)
def test_a_trust_that_is_not_exactly_what_was_written_is_refused(
    tmp_path: Path, body: str, complaint: str
) -> None:
    with pytest.raises(ProfileError, match=complaint) as raised:
        _load(tmp_path, body)

    assert str(tmp_path / "guardana.yaml") in str(raised.value)
