"""A low-confidence "lead" verdict for genuinely probabilistic static signals.

A slopsquat import or an unsigned/unpinned model is a lead worth a look, not a
proven compromise. Attaching a low confidence lets a policy's `min_confidence`
treat it as a lead — while unambiguous detections (a malicious pickle opcode)
stay verdict-free and at effective certainty, never diluted by a made-up number.
"""

from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.report import CoverageShortfall, ShortfallKind

LEAD_CONFIDENCE = 0.4
_LEAD_EVALUATOR_ID = "heuristic.lead"
_UNSCANNED_EVALUATOR_ID = "heuristic.unscanned"


def lead_verdict(rationale: str) -> Verdict:
    """Build a flagged-but-low-confidence verdict for a probabilistic static lead."""
    return Verdict("fail", LEAD_CONFIDENCE, rationale, _LEAD_EVALUATOR_ID)


def unscanned_verdict(rationale: str) -> Verdict:
    """Build the verdict for an artifact this build could not read.

    Not a lead, and not a finding of any size. A lead says "this looks wrong and I
    am not certain"; this says "I did not look, so nothing here is evidence either
    way". Grading it as a low-confidence failure put an answer where there is none:
    severity asks how bad a problem is, and an artifact nobody read is not a problem
    of a size — which is how a profile failing on `medium` promoted a model store
    holding a hundred members it could not parse.
    """
    return Verdict("inconclusive", 0.0, rationale, _UNSCANNED_EVALUATOR_ID)


def unread_component(rule_id: str, path: Path, reason: str) -> CoverageShortfall:
    """Name a model or notebook a rule could not read as coverage the run did not get.

    Reported beside the inconclusive finding, never instead of it: the finding is what
    the collector envelope carries, and the shortfall is what makes the run
    `indeterminate` under every policy rather than only under `fail_on_inconclusive`.
    """
    return CoverageShortfall(
        kind=ShortfallKind.UNEXAMINED_COMPONENT,
        name=str(path),
        detail=f"{rule_id} could not read it: {reason}",
    )
