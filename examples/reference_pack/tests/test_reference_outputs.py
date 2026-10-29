"""Both outputs keep the output contract, checked by Guardana's own kit over real engine runs."""

import re
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.output import DeliveryStatus, ReporterRequest
from guardana.core.testing import sample_verifications
from guardana.testing import OutputContractError, assert_renderer_conforms, assert_reporter_conforms
from guardana_reference_pack import provide_file_reporter, provide_summary
from guardana_reference_pack.file_reporter import LocatorRefusedError, prepare
from guardana_reference_pack.summary import escape, render


@pytest.fixture
def locators(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A directory, a regular file where a directory belongs, and a path that does not exist."""
    accepting = tmp_path / "summaries"
    accepting.mkdir()
    refusing = tmp_path / "not-a-directory"
    refusing.write_text("", encoding="utf-8")
    return accepting, refusing, tmp_path / "absent"


def test_the_summary_keeps_the_output_contract() -> None:
    assert_renderer_conforms(provide_summary(), name="reference-summary")


def test_the_file_reporter_keeps_the_output_contract(locators: tuple[Path, Path, Path]) -> None:
    accepting, refusing, absent = locators

    assert_reporter_conforms(
        provide_file_reporter(),
        delivered=str(accepting),
        rejected=str(refusing),
        unreachable=str(absent),
        name="reference-file",
    )

    written = [p.name for p in accepting.iterdir()]
    assert len(written) == len(sample_verifications())
    assert all(re.fullmatch(r"guardana-[0-9a-f-]+\.md", name) for name in written), written
    assert not absent.exists()


def test_the_check_refuses_a_reporter_that_misreports_a_refusal(
    locators: tuple[Path, Path, Path],
) -> None:
    accepting, _refusing, absent = locators

    with pytest.raises(OutputContractError, match="the rejected locator yielded delivered"):
        assert_reporter_conforms(
            provide_file_reporter(),
            delivered=str(accepting),
            rejected=str(accepting),
            unreachable=str(absent),
        )


def test_a_delivered_summary_is_the_run_rendered_and_leaves_no_temporary_file(
    tmp_path: Path,
) -> None:
    sample = sample_verifications()[0]

    delivery = prepare(ReporterRequest(locator=str(tmp_path))).deliver(sample)

    assert delivery.status is DeliveryStatus.DELIVERED
    assert [p.name for p in tmp_path.iterdir()] == [f"guardana-{sample.manifest.run_id}.md"]
    written = (tmp_path / f"guardana-{sample.manifest.run_id}.md").read_text(encoding="utf-8")
    assert written == render(sample)


def test_a_run_id_that_cannot_name_a_file_is_not_sent(tmp_path: Path) -> None:
    sample = sample_verifications()[0]
    escaping = replace(sample, manifest=replace(sample.manifest, run_id="../outside"))

    delivery = prepare(ReporterRequest(locator=str(tmp_path))).deliver(escaping)

    assert delivery.status is DeliveryStatus.NOT_SENT
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("locator", ["", "  ", "summaries\x00"])
def test_prepare_refuses_a_locator_that_names_no_directory(locator: str) -> None:
    with pytest.raises(LocatorRefusedError):
        prepare(ReporterRequest(locator=locator))


def test_the_summary_states_the_verdict_of_every_sample() -> None:
    for sample in sample_verifications():
        text = render(sample)

        assert text.startswith(f"# Guardana run {escape(sample.manifest.run_id)}\n")
        assert f"| Gate | **{sample.gate}** |" in text
        assert f"| Exit code | {sample.exit_code} |" in text


def test_text_from_the_run_cannot_open_markup_or_a_table_cell() -> None:
    assert escape("a|b\n<script>[x](y)") == "a\\|b \\<script\\>\\[x\\](y)"
    assert escape("tab\there\x1b[31m") == "tab here \\[31m"
