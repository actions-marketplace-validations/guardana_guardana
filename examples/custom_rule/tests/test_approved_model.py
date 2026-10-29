from pathlib import Path

from acme_rules.approved_model import ApprovedModelRule
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.core.testing import build_gguf


def _findings(tmp_path: Path) -> list[str]:
    rule = ApprovedModelRule()
    return [f.evidence.summary for f in rule.run(ArtifactTarget(tmp_path), RuleContext())]


def test_an_approved_model_is_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "model.gguf").write_bytes(
        build_gguf({"general.organization": "acme-ml", "general.name": "acme-7b"})
    )
    assert _findings(tmp_path) == []


def test_a_third_party_model_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "model.gguf").write_bytes(
        build_gguf({"general.organization": "somebody-else", "general.name": "mystery-7b"})
    )
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert "mystery-7b" in findings[0]


def test_a_model_without_provenance_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "model.gguf").write_bytes(build_gguf({"general.architecture": "llama"}))
    assert len(_findings(tmp_path)) == 1


def test_an_unreadable_model_is_flagged_rather_than_skipped(tmp_path: Path) -> None:
    (tmp_path / "model.gguf").write_bytes(b"GGUF\x03\x00\x00\x00 truncated")
    findings = _findings(tmp_path)
    assert len(findings) == 1
    assert "unreadable" in findings[0]


def test_an_unreadable_model_is_named_as_coverage_the_run_did_not_get(tmp_path: Path) -> None:
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF\x03\x00\x00\x00 truncated")
    ctx = RuleContext()

    [finding] = list(ApprovedModelRule().run(ArtifactTarget(tmp_path), ctx))

    assert finding.verdict is not None
    assert finding.verdict.outcome == "inconclusive"
    [gap] = ctx.shortfalls()
    assert gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
    assert gap.name == str(model)
    assert "acme.supply_chain.approved_model could not read it" in gap.detail
    assert str(model) in ctx.examined_paths()


def test_a_readable_model_is_examined_without_a_shortfall(tmp_path: Path) -> None:
    (tmp_path / "model.gguf").write_bytes(build_gguf({"general.organization": "acme-ml"}))
    ctx = RuleContext()

    assert list(ApprovedModelRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.shortfalls() == ()
    assert str(tmp_path / "model.gguf") in ctx.examined_paths()
