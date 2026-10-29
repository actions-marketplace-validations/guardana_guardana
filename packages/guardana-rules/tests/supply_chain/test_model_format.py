import json
from pathlib import Path

from guardana.core.report import Finding, ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain._reading import MAX_SCAN_BYTES
from guardana.rules.supply_chain.model_format import ModelFormatRule


def _unverified(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.verdict is not None and f.verdict.outcome == "inconclusive"]


def _unread(ctx: RuleContext) -> list[str]:
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.model_format could not read it: ")
    ]


def test_safetensors_wellformed_not_flagged(tmp_path: Path) -> None:
    header = json.dumps({"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    blob = len(header).to_bytes(8, "little") + header + b"\x00\x00\x00\x00"
    (tmp_path / "w.safetensors").write_bytes(blob)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_a_safetensors_header_longer_than_the_file_is_not_scanned_and_named(
    tmp_path: Path,
) -> None:
    blob = (10_000).to_bytes(8, "little") + b"{}"
    path = tmp_path / "bad.safetensors"
    path.write_bytes(blob)
    ctx = RuleContext()

    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.title for f in findings] == ["safetensors file not scanned"]
    assert _unverified(findings) == findings
    assert _unread(ctx) == [str(path)]
    assert str(path) in ctx.examined_paths()


def test_safetensors_large_valid_header_not_flagged(tmp_path: Path) -> None:
    # A model with tens of thousands of tensors has a JSON header well over
    # the 1 MiB content-scan bound (~1.5 MiB here). The safetensors detector
    # must read its own declared header length, not the 1 MiB-truncated
    # content-scan buffer, so a big-but-valid header must never be flagged.
    num_tensors = 20_000
    tensors = {
        f"t{i}": {"dtype": "F32", "shape": [1], "data_offsets": [i * 4, (i + 1) * 4]}
        for i in range(num_tensors)
    }
    header = json.dumps(tensors).encode()
    content_scan_bound = 1_048_576
    assert len(header) > content_scan_bound  # sanity: header exceeds the content-scan bound
    data = len(header).to_bytes(8, "little") + header + b"\x00" * (num_tensors * 4)
    (tmp_path / "big.safetensors").write_bytes(data)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_pmml_doctype_entity_flagged(tmp_path: Path) -> None:
    payload = (
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    )
    (tmp_path / "model.pmml").write_bytes(payload)
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_clean_pmml_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "model.pmml").write_bytes(b'<?xml version="1.0"?><PMML version="4.4"></PMML>')
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_xml_suffix_routed_to_xxe_detector(tmp_path: Path) -> None:
    (tmp_path / "model.xml").write_bytes(b"<!DOCTYPE r><r/>")
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"


def test_utf16_xxe_caught_by_defused_parser(tmp_path: Path) -> None:
    # UTF-16 bytes defeat the ASCII byte-regex prefilter, so this must be
    # caught by the defusedxml belt-and-braces path (forbid_dtd=True).
    payload = (
        '<?xml version="1.0" encoding="utf-16"?>'
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    )
    (tmp_path / "model.pmml").write_bytes(payload.encode("utf-16"))
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert "defused" in findings[0].evidence.summary


def test_binary_garbage_xml_suffix_ignored(tmp_path: Path) -> None:
    (tmp_path / "junk.xml").write_bytes(b"\x00\x01\x02 not xml at all \xff")
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_safetensors_absurd_header_length_is_bounded(tmp_path: Path) -> None:
    # declared header length is astronomically large (2**60) while the file
    # itself is tiny; the cap + file-size check must reject this as
    # malformed without attempting to allocate/read anywhere near 2**60
    # bytes (i.e. it must return promptly).
    blob = (2**60).to_bytes(8, "little") + b"{}"
    (tmp_path / "absurd.safetensors").write_bytes(blob)
    ctx = RuleContext()
    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), ctx))
    assert len(findings) == 1
    assert _unverified(findings) == findings
    assert _unread(ctx) == [str(tmp_path / "absurd.safetensors")]


_XXE = b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'


def test_an_xml_model_padded_past_the_read_bound_is_unverified_not_clean(tmp_path: Path) -> None:
    """A comment longer than the bound pushes the DOCTYPE out of the part that is read."""
    path = tmp_path / "model.pmml"
    path.write_bytes(b"<!--" + b"x" * MAX_SCAN_BYTES + b"-->" + _XXE)
    ctx = RuleContext()

    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.title for f in findings] == ["XML model file not scanned"]
    assert _unverified(findings) == findings
    assert _unread(ctx) == [str(path)]
    assert str(path) in ctx.examined_paths()


def test_an_xml_document_past_the_read_bound_is_unverified_and_no_model_component(
    tmp_path: Path,
) -> None:
    """Only PMML is a model the inventory lists; any other XML stays a finding alone."""
    (tmp_path / "data.xml").write_bytes(b"<!--" + b"x" * MAX_SCAN_BYTES + b"-->")
    ctx = RuleContext()

    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.title for f in findings] == ["XML model file not scanned"]
    assert ctx.shortfalls() == ()


def test_a_truncated_xml_model_reports_what_it_saw_and_what_it_did_not(tmp_path: Path) -> None:
    (tmp_path / "model.pmml").write_bytes(_XXE + b"<!--" + b"x" * MAX_SCAN_BYTES + b"-->")

    findings = list(ModelFormatRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity.name for f in findings] == ["HIGH", "LOW"]
    assert [f.title for f in _unverified(findings)] == ["XML model file not scanned"]
