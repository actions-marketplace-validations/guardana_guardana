"""Assemble the manifest a saved run carries, from what the run and its caller know.

The engine supplies what it measured; the caller supplies the circumstances — when the
run started, where it came from, which deployment it verifies — because those are not
the engine's to guess. Shared by every command and by `guardana.core.verify`, so a run
saved from Python and one saved by the CLI describe themselves the same way.
"""

import uuid
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from guardana.core import __version__, judge_error
from guardana.core.assessment import Assessment
from guardana.core.calibration.corpus import bundled_corpus
from guardana.core.calibration.store import (
    CalibrationStoreError,
    RecordedCalibration,
    corpus_digest,
    load_calibrations,
)
from guardana.core.evaluator.base import Evaluator
from guardana.core.fingerprint import DocumentDigest
from guardana.core.gate import GateOutcome
from guardana.core.manifest.coverage import (
    CoverageRecord,
    TaxonomyCatalogRecord,
    coverage_digest,
)
from guardana.core.manifest.fingerprint import digest_of
from guardana.core.manifest.identity import DeploymentRef, RunSource, TargetIdentity, ToolInfo
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import (
    CalibrationRecord,
    EvaluatorRecord,
    ExchangesRecord,
    RecordingRecord,
    RuleRecord,
    SuiteSummary,
    TrialSummary,
)
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings, PrivacyRecord
from guardana.core.manifest.summary import summarize
from guardana.core.manifest.usage import JudgeUsage, RunUsage
from guardana.core.origin import Origin
from guardana.core.pack.lock import catalogue_digest
from guardana.core.profile import Profile
from guardana.core.profile.digest import profile_digest
from guardana.core.registry import Registry
from guardana.core.report import CoverageShortfall, ScanResult
from guardana.core.rule import Rule
from guardana.core.target import REQUEST_TIMEOUT_SECONDS, Target, TargetKind, TraceReader
from guardana.core.target.recorded import RecordedTarget
from guardana.core.taxonomy import catalogs, extensions
from guardana.core.trials import reduce_rule
from guardana.core.usage import TargetUsage


def target_identity(target: Target, ref: str) -> TargetIdentity:
    """Describe what was examined, and say what the fingerprint was computed from.

    The fingerprint covers the *declared* identity of the target — its reference
    and kind — which is what the engine can honestly attest to without asking the
    target to identify itself. `fingerprint_inputs` records exactly that, so no
    consumer reads the digest as covering model weights it never saw. What a real
    endpoint supports, and how it identifies itself, is `guardana target inspect`.

    A trace also records the digest of the document it was read from, beside the
    fingerprint rather than in it, so the fingerprint keeps identifying the target.
    """
    inputs = ("kind", "ref")
    return TargetIdentity(
        kind=target.kind,
        ref=ref,
        fingerprint=digest_of(str(target.kind), ref),
        fingerprint_inputs=inputs,
        capabilities=tuple(sorted(str(c) for c in target.capabilities())),
        document=_document_of(target),
    )


def _document_of(target: Target) -> DocumentDigest | None:
    """Return the digest of the document a target read: a trace, or a grade's recording."""
    if isinstance(target, TraceReader):
        return target.trace.provenance.document
    if isinstance(target, RecordedTarget):
        return target.document
    return None


def _run_usage(
    spent: TargetUsage | None,
    started_at: datetime,
    completed_at: datetime,
    judge: Mapping[str, JudgeUsage] | None = None,
) -> RunUsage:
    """Turn what the targets and the judges metered into the run's usage block.

    Wall time is measured here rather than in the engine, which does not consult a
    clock. Everything else is passed through untouched: `spent is None` means no
    target counted, and `judge is None` that no judge did, and each stays an explicit
    unknown instead of becoming a zero somewhere between the meter and the file.
    """
    elapsed = (completed_at - started_at).total_seconds()
    if spent is None:
        return RunUsage(wall_time_seconds=elapsed, judge=judge)
    return RunUsage(
        requests=spent.requests,
        input_tokens=spent.input_tokens,
        output_tokens=spent.output_tokens,
        requests_missing_token_counts=spent.requests_missing_token_counts,
        wall_time_seconds=elapsed,
        judge=judge,
    )


def _evaluator_records(
    rules: Sequence[Rule],
    calibrations: Mapping[str, RecordedCalibration] | None = None,
    evaluators: Mapping[str, Evaluator] | None = None,
) -> tuple[EvaluatorRecord, ...]:
    """Record the evaluators the rules that ran declared they would grade with.

    Declared, not "every evaluator installed": an evaluator nobody used graded
    nothing, and listing it would pad the coverage fingerprint with checking that
    never happened. A rule grading entirely in Python declares none, and that is
    the honest answer for it.

    No digest. An `Evaluator` has no declaration to hash — it is Python — and
    inventing one from its class name would claim to detect a change it cannot see.
    The tool version recorded beside it is what covers the code.

    A calibration is attached when this run was pointed at one. An evaluator with no
    recorded measurement carries `None`, which is what every run said for every
    evaluator until `calibrate --record` existed — honest then and honest now, but
    now distinguishable from "measured, and here is how honest it was".

    The judge identity is the one the registered evaluator states, so a judge swapped
    under the same id is recorded as a different grader; None when it states none.
    """
    declared = {
        evaluator_id
        for rule in rules
        for evaluator_id, _expectation in rule.declared_expectations()
        if evaluator_id
    }
    measured = calibrations or {}
    registered = evaluators or {}
    return tuple(
        EvaluatorRecord(
            id=evaluator_id,
            calibration=(measured[evaluator_id].as_record() if evaluator_id in measured else None),
            judge=_stated_judge(registered.get(evaluator_id)),
            deterministic=_declared_deterministic(registered.get(evaluator_id)),
        )
        for evaluator_id in sorted(declared)
    )


def _declared_deterministic(evaluator: Evaluator | None) -> bool:
    """Return whether a registered evaluator declares itself deterministic; False for none."""
    return evaluator is not None and evaluator.deterministic is True


def _stated_judge(evaluator: Evaluator | None) -> str | None:
    """Return the judge identity an evaluator states, or None when it states none."""
    identity = None if evaluator is None else evaluator.judge_identity
    return identity if isinstance(identity, str) and identity.strip() else None


@dataclass(frozen=True, slots=True)
class ProfileCalibrations:
    """Every calibration a profile names, the file each came from, and what failed to load."""

    measured: dict[str, RecordedCalibration]
    sources: dict[str, Path]
    problems: tuple[str, ...]


def read_profile_calibrations(profile: Profile) -> ProfileCalibrations:
    """Read every calibration file this profile points at, collecting each problem.

    The run and the profile checks share this, so a check cannot call valid what a
    run refuses. Every file is read even after one fails, so a check reports all of
    them at once rather than one per attempt.

    Two files measuring one evaluator are a problem too: whichever came last would
    decide which measurement corrects the run, and nothing would say so. One file
    listed twice is still one measurement.
    """
    measured: dict[str, RecordedCalibration] = {}
    source: dict[str, Path] = {}
    problems: list[str] = []
    read: set[Path] = set()
    for raw_path in profile.calibration_paths:
        path = Path(raw_path)
        if not path.exists():
            problems.append(
                f"{path} does not exist, so the calibrations it names cannot be recorded"
            )
            continue
        resolved = path.resolve()
        if resolved in read:
            continue
        read.add(resolved)
        try:
            loaded = load_calibrations(path)
        except CalibrationStoreError as exc:
            problems.append(str(exc))
            continue
        for evaluator_id, calibration in loaded.items():
            if evaluator_id in source:
                problems.append(
                    f"{evaluator_id} is calibrated in both {source[evaluator_id]} and {path}; "
                    f"keep one measurement per evaluator, so the run says which it used"
                )
                continue
            source[evaluator_id] = path
            measured[evaluator_id] = calibration
    return ProfileCalibrations(measured, source, tuple(problems))


def load_profile_calibrations(profile: Profile) -> dict[str, RecordedCalibration]:
    """Read every calibration file this profile points at, refusing one it cannot parse.

    Refusing rather than skipping. A calibration file that silently failed to load
    would leave every evaluator recorded as unmeasured, which reads as "nobody
    checked this judge" — the opposite of what the operator configured and asked to
    have in their evidence.
    """
    calibrations = read_profile_calibrations(profile)
    if calibrations.problems:
        raise CalibrationStoreError(calibrations.problems[0])
    return calibrations.measured


def _coverage(
    rules: Sequence[RuleRecord],
    evaluators: Sequence[EvaluatorRecord],
    capabilities: Sequence[str],
    protocols: Mapping[str, str],
    shortfall: Sequence[CoverageShortfall],
) -> CoverageRecord:
    """Describe what this run was able to check, and pin the catalogues it mapped against."""
    builtin = catalogs()
    taxonomies = (
        *(
            TaxonomyCatalogRecord(
                framework=catalog.framework,
                digest=catalog.digest,
                entries=len(catalog.refs),
                version=catalog.version,
            )
            for catalog in builtin
        ),
        *_installed_catalogues(),
    )
    return CoverageRecord(
        digest=coverage_digest(rules, evaluators, capabilities, taxonomies, protocols),
        taxonomies=taxonomies,
        protocols=dict(protocols),
        # Carried into the document rather than left on the in-memory result: the
        # verdict this run reached is `indeterminate` because of these, and evidence
        # that states a conclusion without its cause is evidence nobody can act on.
        shortfall=tuple(shortfall),
    )


def _installed_catalogues() -> tuple[TaxonomyCatalogRecord, ...]:
    """Pin the references packages registered, per framework, by the digest `pack lock` takes."""
    return tuple(
        TaxonomyCatalogRecord(framework=framework, digest=catalogue_digest(refs), entries=len(refs))
        for framework, refs in sorted(extensions().items())
    )


@dataclass(frozen=True, slots=True)
class ConnectionFacts:
    """How a run reached its endpoint: the built-in wire, and digests of the operator's files.

    `system_prompt_digest` covers the operator's prompt, never a planted canary, so two runs
    of one configuration record the same digest.
    """

    provider: str | None = None
    adapter_digest: str | None = None
    system_prompt_digest: str | None = None


def build_run_manifest(  # noqa: PLR0913 — a manifest is assembled from independent facts
    registry: Registry,
    profile: Profile,
    result: ScanResult,
    *,
    target_kind: TargetKind,
    target_ref: str,
    gate: GateOutcome,
    started_at: datetime,
    identity: TargetIdentity | None = None,
    concurrency: int = 1,
    deployment: DeploymentRef | None = None,
    source: RunSource | None = None,
    calibrations: Mapping[str, RecordedCalibration] | None = None,
    judge_usage: Mapping[str, JudgeUsage] | None = None,
    exchanges: ExchangesRecord | None = None,
    recording: RecordingRecord | None = None,
    run_id: str | None = None,
    connection: ConnectionFacts | None = None,
    target: Target | None = None,
) -> RunManifest:
    """Describe the run that produced `result`, digesting the rules that actually ran.

    Only the rules that ran are digested. A rule that was skipped or errored did
    not test anything, and listing it as part of the plan would let a later
    comparison treat a check that never happened as coverage it had. The one
    exception is a suite the run cut off: its record carries the declined summary
    over every case it planned, and it stays out of `rules_run`, the coverage
    digest and the evaluator records.

    `calibrations` are the records the run itself was handed; given, they are used as
    they are, so the run and its record correct with the same measurements. Left out,
    the profile's are read here.

    `judge_usage` is what the judges built from the profile spent, read once by the
    caller after every pass; `None` records that nobody counted judge calls. `source`
    and `deployment` are the caller's knowledge — the engine reads no environment — and
    default to a local run of an undeclared deployment. Calibrations left out are read
    from the profile's files, raising `CalibrationStoreError` on one that cannot be read.

    `exchanges` are what a probe kept in its sidecar and `recording` the recording a graded
    run answered from; both are the caller's to state, and None when there is neither.
    `run_id` is given by a caller that wrote it into the sidecar before the manifest
    existed; left out, a fresh one is drawn. `target` is what the rules ran against: each
    rule's declared requests are then priced for it, as the plan prices them, and left
    out they are the rule's target-free declaration.
    """
    now = datetime.now(UTC)
    ran = tuple(rule for rule in registry.rules() if rule.meta.id in result.rules_run)
    # A rule's `version` is recorded beside its id and digest: a replacement can copy
    # those two exactly, and the version is what tells it apart.
    recorded: dict[str, list[Assessment]] = {}
    for assessment in result.assessments:
        recorded.setdefault(assessment.rule_id, []).append(assessment)
    reported = {f.rule_id for f in (*result.findings, *result.unverified, *result.waived)}
    if calibrations is None:
        calibrations = load_profile_calibrations(profile)
    grading = _Grading(
        evaluators=registry.evaluators(),
        calibrations={key: value.as_record() for key, value in calibrations.items()},
        starter_digest=corpus_digest(bundled_corpus()),
    )
    rules = tuple(
        _rule_record(
            rule,
            registry.origin_of(rule.meta.id),
            _trial_summary(rule, recorded.get(rule.meta.id, []), result, reported, grading),
            result.suites.get(rule.meta.id),
            declared=_declared(rule, target),
        )
        for rule in ran
    )
    evaluators = _evaluator_records(ran, calibrations, grading.evaluators)
    identified = (
        identity
        if identity is not None
        else TargetIdentity(kind=target_kind, ref=target_ref, fingerprint_inputs=())
    )
    return RunManifest(
        run_id=run_id if run_id is not None else str(uuid.uuid4()),
        created_at=now,
        started_at=started_at,
        completed_at=now,
        source=source if source is not None else RunSource(),
        deployment=deployment if deployment is not None else DeploymentRef(),
        guardana=ToolInfo(version=__version__),
        target=identified,
        configuration=ConfigurationRef(
            profile_name=profile.name,
            profile_digest=profile_digest(profile),
            plugins=registry.trust,
            provider=None if connection is None else connection.provider,
            adapter_digest=None if connection is None else connection.adapter_digest,
            system_prompt_digest=None if connection is None else connection.system_prompt_digest,
        ),
        # The ceilings are recorded whether or not the run hit them. Without them a
        # run that exits `6` says it stopped and never says what it hit, which
        # leaves the one number an operator needs — was the budget too small, or is
        # the target now more expensive — unanswerable from the evidence.
        execution=ExecutionSettings(
            concurrency=concurrency,
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            max_requests=profile.budgets.max_requests,
            max_input_tokens=profile.budgets.max_input_tokens,
            max_output_tokens=profile.budgets.max_output_tokens,
            max_duration_seconds=profile.budgets.max_duration_seconds,
            max_requests_per_minute=profile.budgets.max_requests_per_minute,
            # Only an endpoint run makes attempts at a sampled reply; a file scan or a
            # trace given a profile that says `trials: 5` asked for nothing it could do.
            trials=profile.trials if target_kind is TargetKind.ENDPOINT else 1,
        ),
        usage=_run_usage(result.usage, started_at, now, judge_usage),
        rules=rules + _unfinished_suites(registry, result, target),
        evaluators=evaluators,
        coverage=_coverage(
            rules, evaluators, identified.capabilities, result.protocols, result.coverage_shortfall
        ),
        result_summary=summarize(result, gate),
        # Recorded, so a reader knows what was applied to the evidence they are
        # looking at rather than assuming the default of whatever build they run.
        privacy=PrivacyRecord(
            evidence_mode=profile.privacy.mode,
            redaction_policy_digest=profile.privacy.digest,
        ),
        exchanges=exchanges,
        recording=recording,
    )


def _declared(rule: Rule, target: Target | None) -> int | None:
    """Return the requests `rule` declares, priced for `target` when the run names it."""
    return rule.estimated_requests if target is None else rule.estimated_requests_for(target)


def _unfinished_suites(
    registry: Registry, result: ScanResult, target: Target | None
) -> tuple[RuleRecord, ...]:
    """Record each suite that concluded without finishing, so its unsent cases stay counted.

    `run.rules` is the only place a saved run keeps a suite summary; leaving a cut-off
    suite out would lose the cases it planned and never sent.
    """
    return tuple(
        _rule_record(
            rule,
            registry.origin_of(rule.meta.id),
            None,
            result.suites[rule.meta.id],
            declared=_declared(rule, target),
        )
        for rule in registry.rules()
        if rule.meta.id in result.suites and rule.meta.id not in result.rules_run
    )


def _rule_record(
    rule: Rule,
    origin: Origin,
    trial_summary: TrialSummary | None,
    suite: SuiteSummary | None = None,
    *,
    declared: int | None,
) -> RuleRecord:
    """Describe one rule that ran, including which distribution supplied it.

    An unattributed origin stays `None` rather than becoming `"unknown"`: a
    placeholder in an evidence field teaches readers to treat the field as
    decoration.
    """
    return RuleRecord(
        id=rule.meta.id,
        digest=rule.digest(),
        version=origin.version,
        origin=origin.distribution or origin.source,
        maturity=str(rule.meta.maturity),
        declared_requests=declared,
        trial_summary=trial_summary,
        suite=suite,
    )


@dataclass(frozen=True, slots=True)
class _Grading:
    """What a rule's rate is corrected with: the graders, their calibrations, the starter."""

    evaluators: Mapping[str, Evaluator]
    calibrations: Mapping[str, CalibrationRecord]
    starter_digest: str


def _trial_summary(
    rule: Rule,
    recorded: Sequence[Assessment],
    result: ScanResult,
    reported: Set[str],
    grading: _Grading,
) -> TrialSummary | None:
    """Reduce a repeating rule's recorded trials over its cases; None for a rule that cannot.

    K comes from the rule object that ran, carried on the result, rather than from the
    registry's copy: a planted copy is what sent the requests. A rule that reported a
    finding never gets a bound, whatever its recorded trials say: a clean summary beside
    a finding would be the report contradicting itself in the reassuring direction.

    Every summary carries its correction, decided after the bound so a suppressed bound
    is never corrected. `None` there is what a migrated document says, never a build.

    A suite gets none: its trials are summarised as a pass rate in its own summary, and
    an attack success rate over the same trials would state the opposite quantity.
    """
    if rule.meta.id in result.suites or not any(a.trial is not None for a in recorded):
        return None
    rule_id = rule.meta.id
    trials = reduce_rule(
        rule_id,
        recorded,
        result.trials_per_case.get(rule_id, 1),
        one_case=rule.grades_one_case,
    )
    summary = TrialSummary.from_trials(trials)
    if summary.bound is not None and rule_id in reported:
        summary = replace(summary, bound=None)
    graded_by = judge_error.grading_of(
        rule_id, rule.deterministic, {a.assessor for a in recorded}, grading.evaluators
    )
    return replace(
        summary,
        correction=judge_error.correct(
            summary,
            graded_by,
            grading.evaluators,
            grading.calibrations,
            starter_digest=grading.starter_digest,
        ),
    )
