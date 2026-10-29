"""A safetensors file nobody could read is not scanned, and the run says which file it was."""

from pathlib import Path

from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.rules.supply_chain.model_format import _scan_safetensors

_RULE_ID = "guardana.supply_chain.model_format"


def test_a_file_that_cannot_be_opened_is_reported_as_not_scanned(tmp_path: Path) -> None:
    ctx = RuleContext()
    path = tmp_path / "gone.safetensors"

    (finding,) = _scan_safetensors(path, ctx)

    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"
    assert "not scanned" in finding.title
    (gap,) = ctx.shortfalls()
    assert (gap.kind, gap.name) == (ShortfallKind.UNEXAMINED_COMPONENT, str(path))
    assert gap.detail.startswith(f"{_RULE_ID} could not read it: ")


def test_a_malformed_header_is_not_scanned_rather_than_a_structural_verdict(
    tmp_path: Path,
) -> None:
    ctx = RuleContext()
    path = tmp_path / "bad.safetensors"
    path.write_bytes(b"\x01\x00")

    (finding,) = _scan_safetensors(path, ctx)

    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"
    assert finding.title == "safetensors file not scanned"
    (gap,) = ctx.shortfalls()
    assert (gap.kind, gap.name) == (ShortfallKind.UNEXAMINED_COMPONENT, str(path))
    assert gap.detail.startswith(f"{_RULE_ID} could not read it: ")


def test_a_well_formed_file_reports_no_shortfall(tmp_path: Path) -> None:
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    path = tmp_path / "ok.safetensors"
    path.write_bytes(len(header).to_bytes(8, "little") + header + b"\x00" * 4)
    ctx = RuleContext()

    assert list(_scan_safetensors(path, ctx)) == []
    assert ctx.shortfalls() == ()
