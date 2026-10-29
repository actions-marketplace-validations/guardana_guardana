"""Rebuild a manifest from a saved run's `run` block, refusing what it cannot parse."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.gate import GateOutcome
from guardana.core.manifest.coverage import CoverageRecord, TaxonomyCatalogRecord
from guardana.core.manifest.identity import (
    DeploymentRef,
    RunSource,
    SourceKind,
    TargetIdentity,
    ToolInfo,
)
from guardana.core.manifest.model import RunManifest
from guardana.core.manifest.records import (
    CalibrationRecord,
    CorrectionStatus,
    EvaluatorRecord,
    ExchangesRecord,
    FixturesRecord,
    JudgeCorrection,
    RecipeRecord,
    RecordingOriginRecord,
    RecordingRecord,
    ResultSummary,
    RuleRecord,
    SubjectSource,
    SuiteCorrection,
    SuiteOutcome,
    SuiteSummary,
    TrialSummary,
)
from guardana.core.manifest.settings import ConfigurationRef, EvidenceMode, ExecutionSettings
from guardana.core.manifest.settings import PrivacyRecord as _PrivacyRecord
from guardana.core.manifest.usage import JUDGE_BLOCKS, JudgeUsage, RunUsage
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.report.skipped import SkippedRule, SkipReason
from guardana.core.report.stop import StopReason
from guardana.core.subject import SubjectKind
from guardana.core.target import TargetKind
from guardana.core.trials import check_trials

_DIGEST_KINDS = frozenset(str(kind) for kind in DigestKind)


class ManifestLoadError(Exception):
    """A run block that cannot be read as one. Always raised, never defaulted around."""


def _mapping(raw: object, what: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ManifestLoadError(f"{what} must be an object")
    return raw


def _text(raw: Mapping[str, Any], key: str, what: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ManifestLoadError(f"{what}.{key} must be a string")
    return value


def _optional_text(raw: Mapping[str, Any], key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) else None


def _optional_int(raw: Mapping[str, Any], key: str) -> int | None:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _optional_number(raw: Mapping[str, Any], key: str) -> float | None:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _timestamp(raw: object, what: str) -> datetime | None:
    if raw is None:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"{what} is not an RFC 3339 timestamp") from exc


def _target_kind(raw: object) -> TargetKind:
    try:
        return TargetKind(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"unknown target type {raw!r}") from exc


def _gate(raw: object) -> GateOutcome | None:
    """Read the recorded verdict, or None when the document does not carry one.

    Never computed here. A migrated version-1 run has no verdict, and deriving
    one would apply this build's thresholds to another build's result — the
    re-derivation that storing the gate as a field exists to prevent.
    """
    if raw is None:
        return None
    try:
        return GateOutcome(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"unknown gate outcome {raw!r}") from exc


def _stop_reason(raw: object) -> StopReason | None:
    if raw is None:
        return None
    try:
        return StopReason(str(raw))
    except ValueError as exc:
        raise ManifestLoadError(f"unknown stop reason {raw!r}") from exc


def _source(raw: object) -> RunSource:
    block = raw if isinstance(raw, dict) else {}
    kind = block.get("kind")
    try:
        resolved = SourceKind(str(kind)) if kind is not None else SourceKind.LOCAL
    except ValueError as exc:
        raise ManifestLoadError(f"unknown source kind {kind!r}") from exc
    return RunSource(
        kind=resolved,
        provider=_optional_text(block, "provider"),
        run_url=_optional_text(block, "run_url"),
    )


def _tool(raw: object) -> ToolInfo:
    block = _mapping(raw, "run.guardana")
    versions = block.get("distribution_versions")
    return ToolInfo(
        version=_text(block, "version", "run.guardana"),
        commit=_optional_text(block, "commit"),
        distribution_versions=(
            {str(k): str(v) for k, v in versions.items()} if isinstance(versions, dict) else {}
        ),
    )


def _target(raw: object) -> TargetIdentity:
    block = _mapping(raw, "run.target")
    inputs = block.get("fingerprint_inputs")
    capabilities = block.get("capabilities")
    return TargetIdentity(
        kind=_target_kind(block.get("type")),
        ref=_text(block, "ref", "run.target"),
        fingerprint=_optional_text(block, "fingerprint"),
        fingerprint_inputs=tuple(str(v) for v in inputs) if isinstance(inputs, list) else (),
        capabilities=tuple(str(v) for v in capabilities) if isinstance(capabilities, list) else (),
        document=_document(block),
    )


def _document(target: Mapping[str, Any]) -> DocumentDigest | None:
    """Read the digest of the document the run read, refusing one absent or malformed.

    The key is required, null included: a digest read back as absent when the writer
    recorded one would drop the only link from the run to the bytes it graded.
    """
    what = "run.target.document"
    raw = _present(target, "document", "run.target")
    if raw is None:
        return None
    block = _mapping(raw, what)
    unknown = sorted(set(block) - {"digest", "kind", "bytes"})
    if unknown:
        raise ManifestLoadError(f"{what} carries {unknown}, which no writer records")
    digest = _present(block, "digest", what)
    kind = _present(block, "kind", what)
    size = _present(block, "bytes", what)
    if not isinstance(digest, str):
        raise ManifestLoadError(f"{what}.digest must be a string")
    if not isinstance(kind, str) or kind not in _DIGEST_KINDS:
        raise ManifestLoadError(f"{what}.kind {kind!r} is not one of {sorted(_DIGEST_KINDS)}")
    if isinstance(size, bool) or not isinstance(size, int):
        raise ManifestLoadError(f"{what}.bytes must be an integer")
    try:
        return DocumentDigest(digest=digest, kind=DigestKind(kind), bytes=size)
    except (TypeError, ValueError) as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


def _deployment(raw: object) -> DeploymentRef:
    """Read which deployment this run verified, leaving anything unrecorded null.

    An absent block and an absent field are the same answer — "not known" — which
    is what `DeploymentRef` already documents every null to mean. A laptop run has
    no commit sha, and a reader must be able to tell that from a commit of zeroes.

    Written since the manifest existed and read since 0.19.0: `manifest_to_dict`
    serialized all eight fields and nothing rebuilt them, so `run inspect --format
    json` re-rendered a run against production as a run against nothing, and any
    consumer holding a loaded manifest lost the AI system, the environment and the
    model digest the evidence was about.
    """
    block = raw if isinstance(raw, dict) else {}
    return DeploymentRef(
        ai_system=_optional_text(block, "ai_system"),
        environment=_optional_text(block, "environment"),
        deployment_id=_optional_text(block, "deployment_id"),
        commit_sha=_optional_text(block, "commit_sha"),
        image_digest=_optional_text(block, "image_digest"),
        model_digest=_optional_text(block, "model_digest"),
        model_name=_optional_text(block, "model_name"),
        model_revision=_optional_text(block, "model_revision"),
    )


def _configuration(raw: object) -> ConfigurationRef:
    block = _mapping(raw, "run.configuration")
    return ConfigurationRef(
        profile_name=_text(block, "profile_name", "run.configuration"),
        profile_digest=_optional_text(block, "profile_digest"),
        system_prompt_digest=_optional_text(block, "system_prompt_digest"),
        tool_manifest_digest=_optional_text(block, "tool_manifest_digest"),
        retriever_digest=_optional_text(block, "retriever_digest"),
        dataset_digest=_optional_text(block, "dataset_digest"),
        adapter_digest=_optional_text(block, "adapter_digest"),
        provider=_nullable_text(block, "provider", "run.configuration"),
        plugins=_plugins(block),
    )


_PLUGIN_MODES = frozenset(str(mode) for mode in PluginMode)


def _plugins(block: dict[str, Any]) -> PluginTrust | None:
    """Read the plugin trust a run recorded; the key is required, null means unknown."""
    if "plugins" not in block:
        raise ManifestLoadError("run.configuration.plugins is missing")
    raw = block["plugins"]
    if raw is None:
        return None
    if (
        not isinstance(raw, dict)
        or set(raw) != {"mode", "allowed"}
        or raw["mode"] not in _PLUGIN_MODES
        or not isinstance(raw["allowed"], list)
        or not all(isinstance(name, str) for name in raw["allowed"])
    ):
        raise ManifestLoadError(
            f"run.configuration.plugins must be null or an object with a mode of "
            f"{sorted(_PLUGIN_MODES)} and a list of allowed distributions"
        )
    return PluginTrust(mode=PluginMode(raw["mode"]), allowed=frozenset(raw["allowed"]))


def _execution(raw: object) -> ExecutionSettings:
    block = raw if isinstance(raw, dict) else {}
    return ExecutionSettings(
        concurrency=_optional_int(block, "concurrency"),
        timeout_seconds=_optional_int(block, "timeout_seconds"),
        seed=_optional_int(block, "seed"),
        temperature=_optional_number(block, "temperature"),
        max_requests=_optional_int(block, "max_requests"),
        max_input_tokens=_optional_int(block, "max_input_tokens"),
        max_output_tokens=_optional_int(block, "max_output_tokens"),
        max_duration_seconds=_optional_number(block, "max_duration_seconds"),
        max_requests_per_minute=_optional_int(block, "max_requests_per_minute"),
        trials=_execution_trials(block.get("trials")),
    )


def _execution_trials(raw: object) -> int:
    """Read the trials per case the operator asked for, refusing a value that is not one.

    Absent reads as one attempt, which is what every run before trials existed made.
    """
    if raw is None:
        return 1
    try:
        return check_trials(raw)
    except ValueError as exc:
        raise ManifestLoadError(f"run.execution.trials: {exc}") from exc


def _usage(raw: object) -> RunUsage:
    block = raw if isinstance(raw, dict) else {}
    return RunUsage(
        requests=_optional_int(block, "requests"),
        input_tokens=_optional_int(block, "input_tokens"),
        output_tokens=_optional_int(block, "output_tokens"),
        requests_missing_token_counts=_optional_int(block, "requests_missing_token_counts"),
        estimated_cost=_optional_number(block, "estimated_cost"),
        wall_time_seconds=_optional_number(block, "wall_time_seconds"),
        judge=_judge_usage(block),
    )


def _judge_usage(usage: Mapping[str, Any]) -> dict[str, JudgeUsage] | None:
    """Read what each configured judge spent, refusing a block absent or malformed.

    Every key is required, null included: judge calls read back as uncounted when the
    writer counted them would hide a bill, and read back as zero would invent one.
    """
    what = "run.usage.judge"
    raw = _present(usage, "judge", "run.usage")
    if raw is None:
        return None
    block = _mapping(raw, what)
    if not block:
        raise ManifestLoadError(f"{what} is empty; null says nobody counted judge calls")
    unknown = sorted(set(block) - set(JUDGE_BLOCKS))
    if unknown:
        raise ManifestLoadError(f"{what} names {unknown}, which no judge block meters")
    out: dict[str, JudgeUsage] = {}
    for name in JUDGE_BLOCKS:
        if name not in block:
            continue
        entry = _mapping(block[name], f"{what}.{name}")
        where = f"{what}.{name}"
        exhausted = _present(entry, "budget_exhausted", where)
        if not isinstance(exhausted, bool):
            raise ManifestLoadError(f"{where}.budget_exhausted must be true or false")
        try:
            out[name] = JudgeUsage(
                requests=_whole(entry, "requests", where),
                input_tokens=_nullable_count(entry, "input_tokens", where),
                output_tokens=_nullable_count(entry, "output_tokens", where),
                requests_missing_token_counts=_whole(entry, "requests_missing_token_counts", where),
                budget_exhausted=exhausted,
            )
        except ValueError as exc:
            raise ManifestLoadError(f"{where}: {exc}") from exc
    return out


def _rules(raw: object) -> tuple[RuleRecord, ...]:
    if not isinstance(raw, list):
        return ()
    records = []
    for entry in raw:
        block = _mapping(entry, "run.rules[]")
        records.append(
            RuleRecord(
                id=_text(block, "id", "run.rules[]"),
                digest=_text(block, "digest", "run.rules[]"),
                version=_optional_text(block, "version"),
                origin=_optional_text(block, "origin"),
                maturity=_optional_text(block, "maturity"),
                declared_requests=_optional_int(block, "declared_requests"),
                trial_summary=_trial_summary(block),
                suite=_suite(block),
            )
        )
    return tuple(records)


_TRIAL_COUNTS = ("trials_per_case", "cases", "cases_failed", "cases_incomplete")
_TRIAL_RATES = ("bound", "mean_success_rate")


def _trial_summary(rule: Mapping[str, Any]) -> TrialSummary | None:
    """Read what a rule's trials added up to, refusing a summary that is absent or malformed.

    Refused rather than read as null: a summary is where a clean result states its
    bound, and one quietly dropped would turn a stated bound into an unrepeated rule.
    """
    what = "run.rules[].trial_summary"
    if "trial_summary" not in rule:
        raise ManifestLoadError(f"{what} is missing; null says the rule made one attempt")
    raw = rule["trial_summary"]
    if raw is None:
        return None
    block = _mapping(raw, what)
    counts: dict[str, int] = {}
    for key in _TRIAL_COUNTS:
        value = block.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ManifestLoadError(f"{what}.{key} must be a whole number")
        counts[key] = value
    rates: dict[str, float | None] = {}
    for key in _TRIAL_RATES:
        if key not in block:
            raise ManifestLoadError(f"{what}.{key} is missing; null says it is unknown")
        value = block[key]
        if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)):
            raise ManifestLoadError(f"{what}.{key} must be a number or null")
        rates[key] = None if value is None else float(value)
    if "correction" not in block:
        raise ManifestLoadError(
            f"{what}.correction is missing; null says the run was saved before corrections"
        )
    try:
        return TrialSummary(
            trials_per_case=counts["trials_per_case"],
            cases=counts["cases"],
            cases_failed=counts["cases_failed"],
            cases_incomplete=counts["cases_incomplete"],
            bound=rates["bound"],
            mean_success_rate=rates["mean_success_rate"],
            correction=_correction(block["correction"]),
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


_CORRECTION_TEXT = ("assessor", "reason", "dataset_digest")
_CORRECTION_NUMBERS = ("rate", "low", "high", "sensitivity", "specificity")


def _correction(raw: object) -> JudgeCorrection | None:
    """Read whether a rule's rate was corrected for its judge's error, refusing a guess.

    Every key is required, null included: a corrected block missing its interval must not
    read back as one that stated none.
    """
    what = "run.rules[].trial_summary.correction"
    if raw is None:
        return None
    block = _mapping(raw, what)
    raw_status = block.get("status")
    try:
        status = CorrectionStatus(raw_status if isinstance(raw_status, str) else "")
    except ValueError as exc:
        raise ManifestLoadError(
            f"{what}.status {raw_status!r} is not one of {[str(s) for s in CorrectionStatus]}"
        ) from exc
    texts = {key: _nullable_text(block, key, what) for key in _CORRECTION_TEXT}
    numbers = {key: _nullable_number(block, key, what) for key in _CORRECTION_NUMBERS}
    try:
        return JudgeCorrection(
            status=status,
            assessor=texts["assessor"],
            reason=texts["reason"],
            rate=numbers["rate"],
            low=numbers["low"],
            high=numbers["high"],
            sensitivity=numbers["sensitivity"],
            specificity=numbers["specificity"],
            dataset_digest=texts["dataset_digest"],
            positives=_nullable_count(block, "positives", what),
            negatives=_nullable_count(block, "negatives", what),
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


_SUITE_COUNTS = ("trials_per_case", "cases", "measured", "ungraded", "min_sample")
_SUITE_SHARES = ("worst", "best", "low", "high")


def _suite(rule: Mapping[str, Any]) -> SuiteSummary | None:
    """Read what a suite measured and concluded, refusing a summary absent or malformed.

    Every key is required, null included: a stored pass is what a pipeline reads, and a
    block missing the numbers behind it must not read back as one that stated none.
    """
    what = "run.rules[].suite"
    if "suite" not in rule:
        raise ManifestLoadError(f"{what} is missing; null says the rule is not a suite")
    raw = rule["suite"]
    if raw is None:
        return None
    block = _mapping(raw, what)
    raw_outcome = _present(block, "outcome", what)
    try:
        outcome = SuiteOutcome(raw_outcome if isinstance(raw_outcome, str) else "")
    except ValueError as exc:
        raise ManifestLoadError(
            f"{what}.outcome {raw_outcome!r} is not one of {[str(o) for o in SuiteOutcome]}"
        ) from exc
    counts = {key: _whole(block, key, what) for key in _SUITE_COUNTS}
    shares = {key: _nullable_number(block, key, what) for key in _SUITE_SHARES}
    dataset = _text(block, "dataset", what)
    dataset_digest = _text(block, "dataset_digest", what)
    min_pass_rate = _nullable_number(block, "min_pass_rate", what)
    if min_pass_rate is None:
        raise ManifestLoadError(f"{what}.min_pass_rate must be a number")
    sample_size = _nullable_count(block, "sample_size", what)
    sample_seed = _nullable_count(block, "sample_seed", what)
    reason = _nullable_text(block, "reason", what)
    correction = _suite_correction(_present(block, "correction", what))
    try:
        return SuiteSummary(
            dataset=dataset,
            dataset_digest=dataset_digest,
            trials_per_case=counts["trials_per_case"],
            cases=counts["cases"],
            measured=counts["measured"],
            ungraded=counts["ungraded"],
            min_pass_rate=min_pass_rate,
            min_sample=counts["min_sample"],
            outcome=outcome,
            correction=correction,
            worst=shares["worst"],
            best=shares["best"],
            low=shares["low"],
            high=shares["high"],
            sample_size=sample_size,
            sample_seed=sample_seed,
            reason=reason,
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


def _suite_correction(raw: object) -> SuiteCorrection:
    """Read whether a suite's pass rate was corrected for its judge's error, refusing a guess.

    Never null: a suite records how it was graded from the first version that has one.
    """
    what = "run.rules[].suite.correction"
    block = _mapping(raw, what)
    raw_status = block.get("status")
    try:
        status = CorrectionStatus(raw_status if isinstance(raw_status, str) else "")
    except ValueError as exc:
        raise ManifestLoadError(
            f"{what}.status {raw_status!r} is not one of {[str(s) for s in CorrectionStatus]}"
        ) from exc
    texts = {key: _nullable_text(block, key, what) for key in _CORRECTION_TEXT}
    numbers = {
        key: _nullable_number(block, key, what)
        for key in (*_SUITE_SHARES, "sensitivity", "specificity")
    }
    try:
        return SuiteCorrection(
            status=status,
            assessor=texts["assessor"],
            reason=texts["reason"],
            worst=numbers["worst"],
            best=numbers["best"],
            low=numbers["low"],
            high=numbers["high"],
            sensitivity=numbers["sensitivity"],
            specificity=numbers["specificity"],
            dataset_digest=texts["dataset_digest"],
            positives=_nullable_count(block, "positives", what),
            negatives=_nullable_count(block, "negatives", what),
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


def _whole(block: Mapping[str, Any], key: str, what: str) -> int:
    value = _present(block, key, what)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestLoadError(f"{what}.{key} must be a whole number")
    return value


def _present(block: Mapping[str, Any], key: str, what: str) -> object:
    if key not in block:
        raise ManifestLoadError(f"{what}.{key} is missing; null says it is unknown")
    return block[key]


def _nullable_text(block: Mapping[str, Any], key: str, what: str) -> str | None:
    value = _present(block, key, what)
    if value is not None and not isinstance(value, str):
        raise ManifestLoadError(f"{what}.{key} must be a string or null")
    return value


def _nullable_number(block: Mapping[str, Any], key: str, what: str) -> float | None:
    value = _present(block, key, what)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ManifestLoadError(f"{what}.{key} must be a number or null")
    return float(value)


def _nullable_count(block: Mapping[str, Any], key: str, what: str) -> int | None:
    value = _present(block, key, what)
    if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
        raise ManifestLoadError(f"{what}.{key} must be a whole number or null")
    return value


def _nullable_flag(block: Mapping[str, Any], key: str, what: str) -> bool | None:
    value = _present(block, key, what)
    if value is not None and not isinstance(value, bool):
        raise ManifestLoadError(f"{what}.{key} must be true, false or null")
    return value


def _coverage(raw: object) -> CoverageRecord:
    """Read the coverage fingerprint, leaving it unknown when the document has none.

    An absent block is `None` rather than an empty one: a document written before
    coverage was recorded did not measure the same coverage, it measured none, and
    `diff` has to be able to tell those apart before it says "coverage is unchanged".
    """
    block = raw if isinstance(raw, dict) else {}
    protocols = block.get("protocols")
    return CoverageRecord(
        digest=_optional_text(block, "digest"),
        taxonomies=_taxonomy_catalogs(block.get("taxonomies")),
        protocols=(
            {str(k): str(v) for k, v in protocols.items()} if isinstance(protocols, dict) else {}
        ),
        shortfall=_shortfall(block.get("shortfall")),
    )


def _shortfall(raw: object) -> tuple[CoverageShortfall, ...]:
    """Read the demanded coverage a run did not get, refusing a kind nobody can place.

    Closed like the skip reasons, and for a sharper reason: this channel is the only
    one that makes a run indeterminate with no policy in front of it, so a kind read
    leniently would be a refusal somebody could smuggle past by writing a word this
    build has never seen.
    """
    if not isinstance(raw, list):
        return ()
    out: list[CoverageShortfall] = []
    for entry in raw:
        block = _mapping(entry, "run.coverage.shortfall[]")
        try:
            kind = ShortfallKind(_text(block, "kind", "run.coverage.shortfall[]"))
        except ValueError as exc:
            raise ManifestLoadError(
                f"unknown coverage shortfall kind {block.get('kind')!r}"
            ) from exc
        out.append(
            CoverageShortfall(
                kind=kind,
                name=_text(block, "name", "run.coverage.shortfall[]"),
                detail=_optional_text(block, "detail") or "",
            )
        )
    return tuple(out)


def _taxonomy_catalogs(raw: object) -> tuple[TaxonomyCatalogRecord, ...]:
    if not isinstance(raw, list):
        return ()
    records = []
    for entry in raw:
        block = _mapping(entry, "run.coverage.taxonomies[]")
        records.append(
            TaxonomyCatalogRecord(
                framework=_text(block, "framework", "run.coverage.taxonomies[]"),
                digest=_text(block, "digest", "run.coverage.taxonomies[]"),
                entries=_optional_int(block, "entries") or 0,
                version=_optional_text(block, "version"),
            )
        )
    return tuple(records)


def _evaluators(raw: object) -> tuple[EvaluatorRecord, ...]:
    """Rebuild the evaluators, calibration included.

    The calibration was written by the serializer and dropped here, so a saved run
    carried the measurement to a machine reading the JSON and to nobody reading it
    through `run inspect` or comparing it with `diff`. A field written and never read
    back is not a half-feature: it is a document whose two halves disagree about what
    the run recorded.
    """
    if not isinstance(raw, list):
        return ()
    return tuple(
        EvaluatorRecord(
            id=_text(_mapping(entry, "run.evaluators[]"), "id", "run.evaluators[]"),
            version=_optional_text(entry, "version"),
            digest=_optional_text(entry, "digest"),
            calibration=_calibration(entry),
            judge=_nullable_text(entry, "judge", "run.evaluators[]"),
            deterministic=_flag(entry, "deterministic", "run.evaluators[]"),
        )
        for entry in raw
    )


def _flag(block: Mapping[str, Any], key: str, what: str) -> bool:
    value = _present(block, key, what)
    if not isinstance(value, bool):
        raise ManifestLoadError(f"{what}.{key} must be true or false")
    return value


_EXCHANGES_KEYS = frozenset({"digest", "count", "altered"})


def _exchanges(run: Mapping[str, Any]) -> ExchangesRecord | None:
    """Read the exchanges a probe kept, refusing a block absent or malformed.

    The key is required, null included: a sidecar digest read back as absent would drop
    the only link from a probe to the run that regraded its replies.
    """
    what = "run.exchanges"
    raw = _present(run, "exchanges", "run")
    if raw is None:
        return None
    block = _closed(raw, _EXCHANGES_KEYS, what)
    try:
        return ExchangesRecord(
            digest=_text(block, "digest", what),
            count=_whole(block, "count", what),
            altered=_whole(block, "altered", what),
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


_RECORDING_KEYS = frozenset({"name", "version", "subject", "verbatim", "origin"})
_ORIGIN_KEYS = frozenset({"run_id", "target", "started_at", "stopped_by", "gate"})


def _recording(run: Mapping[str, Any]) -> RecordingRecord | None:
    """Read the recording a graded run answered from, refusing a block absent or malformed.

    The key is required, null included: a graded run read back as a live one would hide
    that nothing was sent to the system it names.
    """
    what = "run.recording"
    raw = _present(run, "recording", "run")
    if raw is None:
        return None
    block = _closed(raw, _RECORDING_KEYS, what)
    verbatim = _present(block, "verbatim", what)
    if not isinstance(verbatim, bool):
        raise ManifestLoadError(f"{what}.verbatim must be true or false")
    origin = _present(block, "origin", what)
    return RecordingRecord(
        name=_text(block, "name", what),
        version=_text(block, "version", what),
        subject=_nullable_text(block, "subject", what),
        verbatim=verbatim,
        origin=None if origin is None else _origin(origin),
    )


def _origin(raw: object) -> RecordingOriginRecord:
    what = "run.recording.origin"
    block = _closed(raw, _ORIGIN_KEYS, what)
    return RecordingOriginRecord(
        run_id=_text(block, "run_id", what),
        target=_text(block, "target", what),
        started_at=_nullable_text(block, "started_at", what),
        stopped_by=_nullable_text(block, "stopped_by", what),
        gate=_nullable_text(block, "gate", what),
    )


_RECIPE_KEYS = frozenset({"name", "digest", "lock_digest", "kind", "source", "unpinned"})


def _recipe(run: Mapping[str, Any]) -> RecipeRecord | None:
    """Read the recipe a run was started from, refusing a block absent or malformed.

    The key is required, null included: a recipe run read back as one started without a
    recipe would drop what the team declared answered it.
    """
    what = "run.recipe"
    raw = _present(run, "recipe", "run")
    if raw is None:
        return None
    block = _closed(raw, _RECIPE_KEYS, what)
    unpinned = _present(block, "unpinned", what)
    if not isinstance(unpinned, list) or not all(isinstance(v, str) for v in unpinned):
        raise ManifestLoadError(f"{what}.unpinned must be a list of `rule:` and `evaluator:` ids")
    try:
        kind = SubjectKind(_text(block, "kind", what))
        source = SubjectSource(_text(block, "source", what))
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: unknown kind or source: {exc}") from exc
    try:
        return RecipeRecord(
            name=_text(block, "name", what),
            digest=_text(block, "digest", what),
            lock_digest=_nullable_text(block, "lock_digest", what),
            kind=kind,
            source=source,
            unpinned=tuple(unpinned),
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


_FIXTURES_KEYS = frozenset({"name", "digest", "data", "tenants", "counts", "markers"})
_FIXTURES_DATA_KEYS = frozenset({"declared"})
_FIXTURES_COUNT_KEYS = frozenset({"documents", "records", "tools"})


def _fixtures(run: Mapping[str, Any]) -> FixturesRecord | None:
    """Read the fixtures file a run was given, refusing a block absent or malformed.

    The key is required, null included: a run given fixtures read back as one given none
    would let `diff` compare it with a run that seeded nothing.
    """
    what = "run.fixtures"
    raw = _present(run, "fixtures", "run")
    if raw is None:
        return None
    block = _closed(raw, _FIXTURES_KEYS, what)
    data = _closed(block["data"], _FIXTURES_DATA_KEYS, f"{what}.data")
    counts = _closed(block["counts"], _FIXTURES_COUNT_KEYS, f"{what}.counts")
    tenants = block["tenants"]
    if not isinstance(tenants, list) or not all(isinstance(name, str) for name in tenants):
        raise ManifestLoadError(f"{what}.tenants must be a list of tenant names")
    try:
        return FixturesRecord(
            name=_text(block, "name", what),
            digest=_text(block, "digest", what),
            data=_text(data, "declared", f"{what}.data"),
            tenants=tuple(tenants),
            documents=_whole(counts, "documents", f"{what}.counts"),
            records=_whole(counts, "records", f"{what}.counts"),
            tools=_whole(counts, "tools", f"{what}.counts"),
            markers=_whole(block, "markers", what),
        )
    except (TypeError, ValueError) as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


def _closed(raw: object, keys: frozenset[str], what: str) -> dict[str, Any]:
    """Return `raw` as an object holding exactly `keys`, refusing one missing or unknown."""
    block = _mapping(raw, what)
    unknown = sorted(set(block) - keys)
    if unknown:
        raise ManifestLoadError(f"{what} carries {unknown}, which no writer records")
    missing = sorted(keys - set(block))
    if missing:
        raise ManifestLoadError(f"{what} is missing {missing}; null says a value is unknown")
    return block


def _calibration(entry: object) -> CalibrationRecord | None:
    """Read one evaluator's calibration, or None when it was never measured.

    Absent and null are the same answer and both are honest — every run written
    before 0.18 said null for every evaluator. What must not happen is a recorded
    measurement reading back as an unmeasured one, so the per-class fields a
    correction reads are required keys, null meaning the calibration did not record them.
    """
    what = "run.evaluators[].calibration"
    raw = entry.get("calibration") if isinstance(entry, dict) else None
    if raw is None:
        return None
    block = _mapping(raw, what)
    try:
        return CalibrationRecord(
            dataset_digest=_optional_text(block, "dataset_digest"),
            measured_at=_timestamp(block.get("measured_at"), f"{what}.measured_at"),
            brier=_optional_number(block, "brier"),
            ece=_optional_number(block, "ece"),
            assessor=_nullable_text(block, "assessor", what),
            judge_identity=_nullable_text(block, "judge_identity", what),
            starter_corpus=_nullable_flag(block, "starter_corpus", what),
            positives=_nullable_count(block, "positives", what),
            negatives=_nullable_count(block, "negatives", what),
            positives_inconclusive=_nullable_count(block, "positives_inconclusive", what),
            negatives_inconclusive=_nullable_count(block, "negatives_inconclusive", what),
            sensitivity=_nullable_number(block, "sensitivity", what),
            specificity=_nullable_number(block, "specificity", what),
        )
    except ValueError as exc:
        raise ManifestLoadError(f"{what}: {exc}") from exc


def _skipped(raw: object) -> tuple[SkippedRule, ...]:
    """Rebuild the skips, refusing a reason this build has never heard of.

    Closed like `Severity`: a reason nobody can place cannot be gated on, and
    guessing at one would invent the very distinction this type exists to keep.
    """
    if not isinstance(raw, list):
        return ()
    out: list[SkippedRule] = []
    for entry in raw:
        block = _mapping(entry, "run.result_summary.rules_skipped[]")
        missing = block.get("missing")
        try:
            reason = SkipReason(_text(block, "reason", "run.result_summary.rules_skipped[]"))
        except ValueError as exc:
            raise ManifestLoadError(f"unknown skip reason {block.get('reason')!r}") from exc
        out.append(
            SkippedRule(
                rule_id=_text(block, "rule_id", "run.result_summary.rules_skipped[]"),
                reason=reason,
                missing=tuple(str(v) for v in missing) if isinstance(missing, list) else (),
                detail=_optional_text(block, "detail") or "",
            )
        )
    return tuple(out)


def _result_summary(raw: object) -> ResultSummary:
    block = _mapping(raw, "run.result_summary")
    rules_run = block.get("rules_run")
    rules_skipped = block.get("rules_skipped")
    return ResultSummary(
        findings=_optional_int(block, "findings") or 0,
        unverified=_optional_int(block, "unverified") or 0,
        waived=_optional_int(block, "waived") or 0,
        errors=_optional_int(block, "errors") or 0,
        observations=_optional_int(block, "observations") or 0,
        rules_run=tuple(str(v) for v in rules_run) if isinstance(rules_run, list) else (),
        rules_skipped=_skipped(rules_skipped),
        max_severity=_optional_text(block, "max_severity"),
        gate=_gate(block.get("gate")),
        stopped_by=_stop_reason(block.get("stopped_by")),
        assessments=_optional_int(block, "assessments") or 0,
        measured=_optional_int(block, "measured") or 0,
    )


def _privacy(raw: object) -> _PrivacyRecord:
    block = raw if isinstance(raw, dict) else {}
    mode = block.get("evidence_mode")
    try:
        resolved = EvidenceMode(str(mode)) if mode is not None else EvidenceMode.FULL
    except ValueError as exc:
        raise ManifestLoadError(f"unknown evidence mode {mode!r}") from exc
    return _PrivacyRecord(
        evidence_mode=resolved,
        redaction_policy_digest=_optional_text(block, "redaction_policy_digest"),
    )


def manifest_from_dict(raw: object, *, migrated_from: int | None = None) -> RunManifest:
    """Rebuild a manifest from the `run` block of a saved run."""
    block = _mapping(raw, "run")
    return RunManifest(
        run_id=_text(block, "run_id", "run"),
        created_at=_timestamp(block.get("created_at"), "run.created_at"),
        started_at=_timestamp(block.get("started_at"), "run.started_at"),
        completed_at=_timestamp(block.get("completed_at"), "run.completed_at"),
        source=_source(block.get("source")),
        guardana=_tool(block.get("guardana")),
        target=_target(block.get("target")),
        deployment=_deployment(block.get("deployment")),
        configuration=_configuration(block.get("configuration")),
        execution=_execution(block.get("execution")),
        usage=_usage(block.get("usage")),
        rules=_rules(block.get("rules")),
        evaluators=_evaluators(block.get("evaluators")),
        coverage=_coverage(block.get("coverage")),
        result_summary=_result_summary(block.get("result_summary")),
        privacy=_privacy(block.get("privacy")),
        exchanges=_exchanges(block),
        recording=_recording(block),
        recipe=_recipe(block),
        fixtures=_fixtures(block),
        migrated_from=(
            migrated_from if migrated_from is not None else _optional_int(block, "migrated_from")
        ),
    )
