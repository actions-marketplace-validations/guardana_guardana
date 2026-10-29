"""What only a command knows about a run: where it ran, and which deployment it verifies.

The manifest itself is built by `guardana.core.manifest.build`; this module reads the
environment for the circumstances the engine never consults, and turns an unreadable
calibration file into the exit code for invalid usage.
"""

import os
from collections.abc import Mapping
from datetime import datetime

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.calibration.store import (
    CalibrationStoreError,
    RecordedCalibration,
)
from guardana.core.evaluator.config import calibrations_for_another_prompt_version
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    DeploymentRef,
    RunManifest,
    RunSource,
    SourceKind,
    TargetIdentity,
)
from guardana.core.manifest.build import (
    _evaluator_records,
    _Grading,
    _trial_summary,
    build_run_manifest,
    load_profile_calibrations,
    target_identity,
)
from guardana.core.manifest.usage import JudgeUsage
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.target import TargetKind

_CI_PROVIDERS = (
    ("GITHUB_ACTIONS", "github"),
    ("GITLAB_CI", "gitlab"),
    ("JENKINS_URL", "jenkins"),
    ("TF_BUILD", "azure"),
)


def detect_source() -> RunSource:
    """Work out whether this run came from a laptop or a pipeline.

    Read from the environment rather than asked of the user, because the answer
    that matters is the one nobody had to remember to pass. A laptop run and a
    gate that was supposed to hold are different evidence, and a dashboard that
    cannot tell them apart reports an experiment as a deployment check.
    """
    for variable, provider in _CI_PROVIDERS:
        if os.environ.get(variable):
            return RunSource(kind=SourceKind.CI, provider=provider, run_url=_ci_run_url(provider))
    if os.environ.get("CI"):
        return RunSource(kind=SourceKind.CI, provider="other")
    return RunSource(kind=SourceKind.LOCAL, provider="local")


def _ci_run_url(provider: str) -> str | None:
    if provider == "github":
        server = os.environ.get("GITHUB_SERVER_URL")
        repository = os.environ.get("GITHUB_REPOSITORY")
        run_id = os.environ.get("GITHUB_RUN_ID")
        if server and repository and run_id:
            return f"{server}/{repository}/actions/runs/{run_id}"
    return os.environ.get("CI_PIPELINE_URL") or os.environ.get("BUILD_URL")


AI_SYSTEM_VARIABLE = "GUARDANA_AI_SYSTEM"
ENVIRONMENT_VARIABLE = "GUARDANA_ENVIRONMENT"
DEPLOYMENT_ID_VARIABLE = "GUARDANA_DEPLOYMENT_ID"

_COMMIT_VARIABLES = ("GITHUB_SHA", "CI_COMMIT_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION")
_IMAGE_VARIABLES = ("GUARDANA_IMAGE_DIGEST",)


def _first(*variables: str) -> str | None:
    for variable in variables:
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return None


def _folded(value: str | None) -> str | None:
    """Fold a *name* the way the collector will, so both records of a run agree.

    The collector normalizes the AI system and the environment so `Production` and
    `production` group as one. If the saved run kept the raw spelling, one run would
    be filed under two names in two places — and `guardana diff` compares saved
    runs, so the disagreement would surface as a change nobody made.
    """
    if value is None:
        return None
    folded = value.strip().lower()
    return folded or None


def detect_deployment(
    ai_system: str | None = None,
    environment: str | None = None,
    deployment_id: str | None = None,
) -> DeploymentRef:
    """Describe which deployment of which AI system this run verifies.

    Two different kinds of fact, gathered two different ways.

    **What CI states is read**, because the answer that matters is the one nobody
    had to remember to pass — the same reasoning as `detect_source`. A commit is a
    fact the pipeline already holds.

    **What only a human knows is declared, never guessed.** A branch name is not an
    environment and a repository name is not an AI system: a monorepo has several
    systems, and one repository deployed twice is one system in two environments. A
    guessed value is one a team would build a dashboard on, which is the same
    mistake as an invented cost — and this project already refuses that one.

    A flag wins over the environment variable, so a pipeline can set the repository
    default once and one job can still say it is production. The two *names* are
    folded exactly as the collector folds them, so the saved run and the collector
    never disagree about which environment a run was.
    """
    return DeploymentRef(
        ai_system=_folded(ai_system or _first(AI_SYSTEM_VARIABLE)),
        environment=_folded(environment or _first(ENVIRONMENT_VARIABLE)),
        deployment_id=deployment_id or _first(DEPLOYMENT_ID_VARIABLE),
        commit_sha=_first(*_COMMIT_VARIABLES),
        image_digest=_first(*_IMAGE_VARIABLES),
    )


def calibrations_or_exit(profile: Profile) -> dict[str, RecordedCalibration]:
    """Read the calibrations, or refuse in words with a code from the exit table.

    A configuration file this build cannot parse is `INVALID_USAGE`, like a profile
    or a contract that will not load. Letting `CalibrationStoreError` propagate exited
    `1` with a stack trace — and `1` means *policy failed*, so a pipeline reading exit
    codes would report a security regression when the only thing wrong was a broken
    JSON file. A wrong verdict is worse than a crash.

    A judge calibration measured under another prompt version than the one in force is
    named on stderr, since it no longer applies and the run would not otherwise say why.
    """
    try:
        calibrations = load_profile_calibrations(profile)
    except CalibrationStoreError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc
    for stale in calibrations_for_another_prompt_version(profile, calibrations):
        typer.echo(f"warning: {stale}", err=True)
    return calibrations


def _source(kind: SourceKind | None) -> RunSource:
    """Describe where this run came from, letting a command state what only it knows.

    Detection reads the environment, which answers "laptop or pipeline" and cannot
    answer "is this a live system or a recording somebody exported". A trace analysis
    is `imported_trace` whether it runs on a laptop or in CI, and the provider stays
    whatever the environment said — so a dashboard can still tell which pipeline read
    the file.
    """
    detected = detect_source()
    if kind is None:
        return detected
    return RunSource(kind=kind, provider=detected.provider, run_url=detected.run_url)


def build_manifest(  # noqa: PLR0913 — a manifest is assembled from independent facts
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
    source_kind: SourceKind | None = None,
    calibrations: Mapping[str, RecordedCalibration] | None = None,
    judge_usage: Mapping[str, JudgeUsage] | None = None,
) -> RunManifest:
    """Build the manifest with where this command ran, read from the environment.

    The calibrations default to the profile's, refused in words when one cannot be read.
    """
    return build_run_manifest(
        registry,
        profile,
        result,
        target_kind=target_kind,
        target_ref=target_ref,
        gate=gate,
        started_at=started_at,
        identity=identity,
        concurrency=concurrency,
        deployment=deployment,
        source=_source(source_kind),
        calibrations=calibrations_or_exit(profile) if calibrations is None else calibrations,
        judge_usage=judge_usage,
    )


__all__ = [
    "_Grading",
    "_evaluator_records",
    "_trial_summary",
    "build_manifest",
    "calibrations_or_exit",
    "detect_deployment",
    "detect_source",
    "target_identity",
]
