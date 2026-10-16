"""The reference pack reaches PyPI only as the bytes the release workflow built and attested."""

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]


def _jobs() -> dict[str, dict[str, object]]:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8"))
    jobs: dict[str, dict[str, object]] = workflow["jobs"]
    return jobs


def _steps(job: str) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = _jobs()[job]["steps"]  # type: ignore[assignment]
    return steps


def _scripts(job: str) -> str:
    return "\n".join(str(step.get("run", "")) for step in _steps(job))


def test_control_the_built_pack_is_attested_and_kept_for_the_publish_job() -> None:
    steps = _steps("reference-pack")
    (attest,) = [s for s in steps if "attest" in str(s.get("uses", ""))]
    (kept,) = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]

    assert "dist-reference/*.whl" in str(attest["with"])
    assert "dist-reference/*.whl" in str(kept["with"])


def test_the_published_pack_is_the_attested_build_not_a_release_asset() -> None:
    steps = _steps("publish-reference-pack")
    (publish,) = [i for i, s in enumerate(steps) if "pypi-publish" in str(s.get("uses", ""))]
    before = steps[:publish]
    runs = "\n".join(str(step.get("run", "")) for step in before)

    assert any("download-artifact" in str(step.get("uses", "")) for step in before)
    assert "gh release download" not in runs
    assert "check_pypi_digests.py" in runs


def test_a_release_asset_with_other_bytes_stops_the_attach_step() -> None:
    (attach,) = [s for s in _steps("reference-pack") if "Attach" in str(s.get("name", ""))]

    assert "cmp -s" in str(attach["run"])
