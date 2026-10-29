"""Two runs that graded the same recorded replies say so, naming the recording's digest.

Only a digest of a whole document links two runs: a probe's kept exchanges and the
regrade that read them, or two regrades of one recording. A prefix digest never
proves the same document, and equal documents without a recording are not replies
somebody kept.
"""

from datetime import UTC, datetime

from guardana.core.diff import compare_reports
from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.gate import GateOutcome
from guardana.core.manifest import RunManifest, TargetIdentity, ToolInfo
from guardana.core.manifest.records import ExchangesRecord, RecordingRecord, ResultSummary
from guardana.core.manifest.settings import ConfigurationRef, ExecutionSettings
from guardana.core.manifest.usage import RunUsage
from guardana.core.report import RunReport, ScanResult
from guardana.core.target import TargetKind

_RULE = "acme.prompt.judged"
_KEPT = "sha256:" + "ab" * 32
_OTHER = "sha256:" + "cd" * 32
_FIRST = datetime(2026, 8, 1, tzinfo=UTC)
_SECOND = datetime(2026, 8, 2, tzinfo=UTC)
_RECORDING = RecordingRecord(name="support", version="1", subject=None, verbatim=True, origin=None)


def _report(
    *,
    when: datetime,
    exchanges: str | None = None,
    document: DocumentDigest | None = None,
    recorded: bool = False,
) -> RunReport:
    return RunReport(
        manifest=RunManifest(
            run_id="r",
            created_at=when,
            started_at=when,
            completed_at=when,
            guardana=ToolInfo(version="0.35.0"),
            target=TargetIdentity(kind=TargetKind.ENDPOINT, ref="http://x#m", document=document),
            configuration=ConfigurationRef(profile_name="default"),
            execution=ExecutionSettings(concurrency=1, timeout_seconds=30),
            usage=RunUsage(),
            result_summary=ResultSummary(
                findings=0,
                unverified=0,
                waived=0,
                errors=0,
                observations=0,
                rules_run=(_RULE,),
                rules_skipped=(),
                max_severity=None,
                gate=GateOutcome.PASS,
            ),
            exchanges=(
                None if exchanges is None else ExchangesRecord(digest=exchanges, count=3, altered=0)
            ),
            recording=_RECORDING if recorded else None,
        ),
        result=ScanResult(findings=(), rules_run=(_RULE,), rules_skipped=()),
    )


def _whole(digest: str) -> DocumentDigest:
    return DocumentDigest(digest=digest, kind=DigestKind.CONTENT, bytes=512)


def _prefix(digest: str) -> DocumentDigest:
    return DocumentDigest(digest=digest, kind=DigestKind.CONTENT_PREFIX, bytes=512)


def _shared(before: RunReport, after: RunReport) -> list[str]:
    return [n for n in compare_reports(before, after).notes if "recorded replies" in n]


def test_a_probe_and_the_regrade_of_its_kept_exchanges_share_an_execution() -> None:
    probe = _report(when=_FIRST, exchanges=_KEPT)
    regrade = _report(when=_SECOND, document=_whole(_KEPT), recorded=True)

    assert _shared(probe, regrade) == [
        f"both runs graded the same recorded replies ({_KEPT}), so a difference between "
        f"them is not the system answering differently"
    ]


def test_two_regrades_of_one_recording_share_an_execution() -> None:
    first = _report(when=_FIRST, document=_whole(_KEPT), recorded=True)
    second = _report(when=_SECOND, document=_whole(_KEPT), recorded=True)

    assert len(_shared(first, second)) == 1


def test_a_regrade_of_other_exchanges_shares_nothing() -> None:
    probe = _report(when=_FIRST, exchanges=_KEPT)
    regrade = _report(when=_SECOND, document=_whole(_OTHER), recorded=True)

    assert _shared(probe, regrade) == []


def test_two_regrades_of_different_recordings_share_nothing() -> None:
    first = _report(when=_FIRST, document=_whole(_KEPT), recorded=True)
    second = _report(when=_SECOND, document=_whole(_OTHER), recorded=True)

    assert _shared(first, second) == []


def test_a_prefix_digest_never_proves_the_same_exchanges() -> None:
    probe = _report(when=_FIRST, exchanges=_KEPT)
    regrade = _report(when=_SECOND, document=_prefix(_KEPT), recorded=True)

    assert _shared(probe, regrade) == []


def test_a_prefix_digest_never_proves_the_same_recording() -> None:
    first = _report(when=_FIRST, document=_prefix(_KEPT), recorded=True)
    second = _report(when=_SECOND, document=_prefix(_KEPT), recorded=True)

    assert _shared(first, second) == []


def test_equal_documents_without_a_recording_are_not_recorded_replies() -> None:
    first = _report(when=_FIRST, document=_whole(_KEPT))
    second = _report(when=_SECOND, document=_whole(_KEPT))

    assert _shared(first, second) == []
