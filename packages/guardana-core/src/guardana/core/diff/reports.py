"""Comparing two *saved* runs, which know things a bare result does not.

A `ScanResult` cannot say what kind of target it came from or when it was made.
A saved run can, and both are refusals waiting to happen: comparing a file scan
against a live-model probe is meaningless, and a pair handed over in the wrong
order turns a regression into a clean bill of health without anyone noticing.
"""

from collections.abc import Mapping
from dataclasses import replace

from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.diff.compare import Grader, RunContext, compare
from guardana.core.diff.errors import IncomparableRunsError
from guardana.core.diff.model import RunDiff
from guardana.core.fingerprint import DigestKind
from guardana.core.manifest import RunManifest
from guardana.core.manifest.records import EvaluatorRecord
from guardana.core.report import RunReport

_GRADED = frozenset({AssessmentStatus.MEASURED, AssessmentStatus.INCONCLUSIVE})


def compare_reports(before: RunReport, after: RunReport) -> RunDiff:
    """Compare two saved runs, refusing pairs that cannot honestly be compared.

    Adds two refusals to the ones `compare` already makes: a different kind of
    target, and a pair whose timestamps say they were handed over the wrong way
    round. A note is added — not a refusal — when the tool version differs, since
    a fleet has to be able to upgrade.
    """
    if before.manifest.target.kind != after.manifest.target.kind:
        raise IncomparableRunsError(
            f"the runs examined different kinds of target "
            f"({before.manifest.target.kind} and {after.manifest.target.kind}) — "
            f"there is nothing to compare between them"
        )
    _refuse_if_out_of_order(before, after)
    diff = compare(
        before.result,
        after.result,
        before_context=_context(before),
        after_context=_context(after),
    )
    notes = (
        _target_note(before, after)
        + _subject_note(before, after)
        + _configuration_note(before, after)
        + _version_note(before, after)
        + _coverage_note(before, after)
        + _migration_note(before, after)
        + _shared_execution_note(before, after)
        + diff.notes
    )
    # `replace`, never a fresh `RunDiff`: rebuilding field by field drops whatever
    # channel is added next, which is why `ScanResult` grew `merged`.
    return replace(diff, notes=notes)


def _context(report: RunReport) -> RunContext:
    """Describe one side of the comparison: what it examined, with which rules, from which build."""
    return RunContext(
        root=report.manifest.target.ref,
        rules={rule.id: rule.digest for rule in report.manifest.rules},
        tool_version=report.manifest.guardana.version,
        grading=_grading(report),
        fixtures=None if report.manifest.fixtures is None else report.manifest.fixtures.digest,
        markers=None if report.manifest.fixtures is None else report.manifest.fixtures.markers,
    )


def _grading(report: RunReport) -> dict[str, dict[str, Grader]]:
    """Map each rule to the assessors its graded trials name, with what the run recorded of each.

    Read from the assessments because a rule record does not say which evaluator its
    verdicts came from, and an assessment names the one that produced it. A trial
    nobody graded — not run, or a reply redaction altered — names no grader.
    """
    recorded = {evaluator.id: evaluator for evaluator in report.manifest.evaluators}
    grading: dict[str, dict[str, Grader]] = {}
    for assessment in report.result.assessments:
        if _names_a_grader(assessment):
            grading.setdefault(assessment.rule_id, {})[assessment.assessor] = _grader(
                assessment.assessor, recorded
            )
    return grading


def _names_a_grader(assessment: Assessment) -> bool:
    return assessment.status in _GRADED and assessment.reason is not UnmeasuredReason.REPLY_ALTERED


def _grader(assessor: str, recorded: Mapping[str, EvaluatorRecord]) -> Grader:
    """Find the evaluator record an assessor names: exactly, or before its `@version`."""
    record = recorded.get(assessor) or recorded.get(assessor.partition("@")[0])
    if record is None:
        return Grader()
    return Grader(version=record.version, digest=record.digest, judge=record.judge)


def _shared_execution_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say when both runs graded the same recorded replies, naming the recording's digest.

    Nothing more: the two may still differ in tool version, rules, coverage and skips,
    and each of those has its own note.
    """
    digest = _shared_execution(before.manifest, after.manifest)
    if digest is None:
        return ()
    return (
        f"both runs graded the same recorded replies ({digest}), so a difference between "
        f"them is not the system answering differently",
    )


def _shared_execution(first: RunManifest, second: RunManifest) -> str | None:
    """Return the digest two runs' recorded replies share, or None when nothing links them.

    A probe's kept exchanges link to the run that graded them; two graded runs link
    through the recording they both read.
    """
    for kept, graded in ((first, second), (second, first)):
        document = _whole_document(graded)
        if kept.exchanges is not None and kept.exchanges.digest == document:
            return document
    if first.recording is None or second.recording is None:
        return None
    document = _whole_document(first)
    return document if document is not None and document == _whole_document(second) else None


def _whole_document(manifest: RunManifest) -> str | None:
    """Return the digest of the document a run read, only when it covers every byte of it."""
    document = manifest.target.document
    if document is None or document.kind is not DigestKind.CONTENT:
        return None
    return document.digest


def _coverage_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say when the two runs could check different things, and name what moved.

    A run with a narrower reach reports fewer findings, and subtracting two lists
    cannot tell that from a fix. The rule list alone never could: it says nothing
    about a rule whose corpus was trimmed, an evaluator that stopped being
    installed, a target that lost a capability, or a server that answered with an
    older protocol revision. The fingerprint covers all of those in one value.

    A run that recorded no fingerprint is *unknown*, never "the same": saying
    nothing changed about coverage nobody measured is the shape of false green this
    project refuses everywhere else.
    """
    first, second = before.manifest.coverage, after.manifest.coverage
    if first.digest is None or second.digest is None:
        return (
            "one of the runs records no coverage fingerprint, so whether the two verified "
            "the same amount is unknown rather than settled — re-run the older side to compare "
            "reach as well as findings",
        )
    if first.digest == second.digest:
        return ()
    return (
        f"the two runs did not have the same reach{_coverage_detail(before, after)} — "
        f"a difference in findings may be a difference in what could be checked",
    )


def _coverage_detail(before: RunReport, after: RunReport) -> str:
    """Name the catalogues and protocols that moved, so the note is actionable.

    Silent about the rest of the fingerprint on purpose: a differing digest whose
    catalogues and protocols match means the rules, their trial counts, the
    evaluators or the target's capabilities moved, and `diff` already reports those
    per rule. Restating them here in the aggregate would be the same finding twice.
    """
    parts = []
    catalogues = _changed_catalogues(before, after)
    if catalogues:
        parts.append(f"framework catalogue(s) {', '.join(catalogues)} differ")
    if before.manifest.coverage.protocols != after.manifest.coverage.protocols:
        parts.append(
            f"negotiated protocols went from {before.manifest.coverage.protocols or 'none'} "
            f"to {after.manifest.coverage.protocols or 'none'}"
        )
    return f" ({'; '.join(parts)})" if parts else ""


def _changed_catalogues(before: RunReport, after: RunReport) -> list[str]:
    # A framework can hold two records, its built-in catalogue and what packages added.
    first = _catalogue_digests(before)
    second = _catalogue_digests(after)
    return sorted(name for name in first | second if first.get(name) != second.get(name))


def _catalogue_digests(report: RunReport) -> dict[str, frozenset[str]]:
    digests: dict[str, set[str]] = {}
    for catalogue in report.manifest.coverage.taxonomies:
        digests.setdefault(catalogue.framework, set()).add(catalogue.digest)
    return {framework: frozenset(found) for framework, found in digests.items()}


def _migration_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say so when one side was migrated, rather than letting its gaps read as facts.

    A migrated run carries explicit unknowns where an older schema recorded
    nothing — no usage, no gate verdict. Comparing against it is still worth
    doing; reading its blanks as measurements is not.
    """
    migrated = [
        label
        for label, report in (("first", before), ("second", after))
        if report.manifest.migrated_from is not None
    ]
    if not migrated:
        return ()
    return (
        f"the {' and '.join(migrated)} run(s) were migrated from an older saved-run schema, "
        f"so what that schema did not record is unknown rather than zero",
    )


def _refuse_if_out_of_order(before: RunReport, after: RunReport) -> None:
    """Refuse a pair given newest-first, rather than reporting its regressions as fixes.

    Only when both runs recorded a time; a run without one is not evidence of
    anything, and inventing an order for it would be worse than not checking.
    """
    started_before, started_after = before.manifest.started_at, after.manifest.started_at
    if started_before is None or started_after is None:
        return
    if started_before > started_after:
        raise IncomparableRunsError(
            f"the run given first ({started_before.isoformat()}) is newer than the one given "
            f"second ({started_after.isoformat()}) — pass them oldest first, or a regression "
            f"reads as a fix"
        )


def _version_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    if before.manifest.guardana.version == after.manifest.guardana.version:
        return ()
    return (
        f"the runs were made by different Guardana versions "
        f"({before.manifest.guardana.version} and {after.manifest.guardana.version}); "
        f"a rule's behaviour may have changed with it, not only the system under test",
    )


def _target_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    if before.manifest.target.ref == after.manifest.target.ref:
        return ()
    return (
        f"the runs examined different targets ({before.manifest.target.ref} and "
        f"{after.manifest.target.ref}) — intended when comparing two models, worth "
        f"a second look otherwise",
    )


CONFIGURATION_LABELS = {
    "profile_digest": "the profile",
    "system_prompt_digest": "the system prompt",
    "tool_manifest_digest": "the tool manifest",
    "retriever_digest": "the retriever",
    "dataset_digest": "the dataset",
    "adapter_digest": "the adapter file",
    "provider": "the provider wire",
    "plugins": "the plugin trust",
}
"""What each recorded setting is called in a note; every field but the profile's name."""


def _configuration_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say which recorded settings differ, so a change is not read as the system changing.

    A setting one side did not record is unknown, never different.
    """
    first, second = before.manifest.configuration, after.manifest.configuration
    changed = [
        label
        for name, label in CONFIGURATION_LABELS.items()
        if (was := getattr(first, name)) is not None
        and (now := getattr(second, name)) is not None
        and was != now
    ]
    if not changed:
        return ()
    return (
        f"the runs were configured differently ({', '.join(changed)} changed) — a "
        f"difference may come from that rather than from the system",
    )


def _subject_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say when the two runs' recipes declared a different kind of subject.

    Only when both record a recipe: a run started without one declared nothing, which is
    unknown rather than different.
    """
    first, second = before.manifest.recipe, after.manifest.recipe
    if first is None or second is None or first.kind == second.kind:
        return ()
    return (
        f"the runs' recipes declared different subjects ({first.kind} and {second.kind}) — "
        f"a model harness answers without the application's prompt, tools and data, so a "
        f"difference may be that rather than the system changing",
    )
