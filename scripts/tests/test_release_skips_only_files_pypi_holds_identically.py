"""A release that skips a file already on PyPI first proves PyPI holds the same bytes."""

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]


def _publish_steps() -> list[dict[str, object]]:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8"))
    steps: list[dict[str, object]] = workflow["jobs"]["publish"]["steps"]
    return steps


def test_control_the_publish_step_skips_existing_files() -> None:
    (publish,) = [s for s in _publish_steps() if s.get("name") == "Publish to PyPI"]
    with_block = publish["with"]
    assert isinstance(with_block, dict)

    assert with_block["skip-existing"] is True


def test_a_skipped_file_is_compared_with_the_published_digest() -> None:
    steps = _publish_steps()
    (publish,) = [i for i, s in enumerate(steps) if s.get("name") == "Publish to PyPI"]
    before = " ".join(str(step.get("run", "")) for step in steps[:publish])

    assert "check_pypi_digests.py dist/" in before
