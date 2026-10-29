"""Every double the testing kit exports is named in the extension guide.

Eleven of the sixteen exports were documented nowhere: a third party reading the
guide would not know `GullibleAgentTransport` exists and would write a worse one.
"""

from pathlib import Path

from guardana.core import testing
from guardana.core.testing import secrets


def _extending() -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "docs" / "extending.md"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError("docs/extending.md not found")


def test_every_testing_export_is_named_in_the_extension_guide() -> None:
    guide = _extending()
    missing = [name for name in testing.__all__ if f"`{name}`" not in guide]

    assert not missing, (
        f"exported by guardana.core.testing and absent from docs/extending.md: {missing}"
    )


def test_every_fake_credential_is_exported_and_counted_by_fake_secrets() -> None:
    """A builder the kit keeps to itself is one a pack author cannot find or assert on."""
    built = sorted(
        name
        for name, value in vars(secrets).items()
        if name.startswith("fake_") and callable(value)
    )
    exported = sorted(name for name in testing.__all__ if name.startswith("fake_"))
    single = [getattr(secrets, name)() for name in built if name != "fake_secrets"]

    assert built == exported
    assert sorted(secrets.fake_secrets()) == sorted(single)
