"""Every renderer words a coverage shortfall so it is true for every kind.

Most kinds are not a demand anybody wrote: a target with no file in it, a model no rule
read, a recording cut short. A line calling each of them "demanded" sends the reader
looking for a requirement that does not exist, so the wording names the kind and the
detail and claims nothing else.
"""

import json
import re
import xml.etree.ElementTree as ET

import pytest
from guardana.core.report import CoverageShortfall, ScanResult, ShortfallKind
from guardana.report import get_renderer


def _normalised(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _result(kind: ShortfallKind) -> ScanResult:
    gap = CoverageShortfall(kind=kind, name="models/a.bin", detail="no rule read this file")
    return ScanResult((), ("acme.check",), (), coverage_shortfall=(gap,))


@pytest.mark.parametrize("kind", list(ShortfallKind))
def test_the_human_report_names_the_kind_and_detail_without_claiming_a_demand(
    kind: ShortfallKind,
) -> None:
    rendered = _normalised(get_renderer("human").render(_result(kind)))

    assert f"coverage missing ({kind.value}): models/a.bin" in rendered
    assert "no rule read this file" in rendered
    assert "1 piece(s) of coverage were missing" in rendered
    assert "demanded" not in rendered.replace(kind.value, "")


@pytest.mark.parametrize("kind", list(ShortfallKind))
def test_sarif_names_the_kind_and_detail_without_claiming_a_demand(kind: ShortfallKind) -> None:
    run = json.loads(get_renderer("sarif").render(_result(kind)))["runs"][0]
    [note] = [
        n
        for n in run["invocations"][0]["toolExecutionNotifications"]
        if n["descriptor"]["id"] == f"guardana.coverage_shortfall.{kind.value}"
    ]
    text = _normalised(note["message"]["text"])

    assert text == f"coverage missing ({kind.value}): models/a.bin: no rule read this file"


@pytest.mark.parametrize("kind", list(ShortfallKind))
def test_junit_names_the_kind_and_detail_without_claiming_a_demand(kind: ShortfallKind) -> None:
    root = ET.fromstring(get_renderer("junit").render(_result(kind)))  # noqa: S314
    [case] = [c for c in root.iter("testcase") if c.get("name") == "models/a.bin"]
    error = case.find("error")

    assert error is not None
    assert _normalised(error.get("message", "")) == f"coverage missing ({kind.value})"
    assert _normalised(error.text or "") == "no rule read this file"
    assert case.get("classname") == f"guardana.coverage.{kind.value}"
