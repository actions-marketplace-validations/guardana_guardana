import time
from collections.abc import Callable
from dataclasses import dataclass, replace

from guardana.core.diff import IncomparableRunsError, compare, gate_diff
from guardana.core.gate import GateOutcome, StopReason, exit_code_for, gate_outcome
from guardana.core.profile.model import Policy
from guardana.core.report import ScanResult
from guardana.core.runner import gate, target_failures
from guardana.core.target import EndpointError


class TargetStoppedError(EndpointError):
    """A cycle its target stopped part-way: nothing in it was sampled.

    Carries the cycle's partial `result`; the message is what the target did, as the
    run recorded it.
    """

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        super().__init__("; ".join(target_failures(result)) or "the target stopped the cycle")


# A monitored endpoint blips: a rate-limit, a 502, a dropped connection. A 24/7
# loop must survive those. A programming bug (anything else) must not be
# swallowed — it propagates so the operator sees it.
_TRANSIENT = (OSError, EndpointError)

_PASSED = exit_code_for(GateOutcome.PASS)
_INDETERMINATE = exit_code_for(GateOutcome.INDETERMINATE)
_FAILED = exit_code_for(GateOutcome.FAIL)
_WORST_LAST = (
    _PASSED,
    _INDETERMINATE,
    exit_code_for(GateOutcome.INDETERMINATE, StopReason.INTERRUPTED),
    exit_code_for(GateOutcome.INDETERMINATE, StopReason.BUDGET_EXHAUSTED),
    _FAILED,
)
"""How the result codes rank across cycles, best first.

A policy failure outranks a stop: each cycle is a complete run of its own, so a
failure one cycle proved stays proven whatever cut a later cycle short.
"""


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    """How often to sample, and (in tests/CI) when to stop."""

    interval_seconds: float
    max_cycles: int | None = None


@dataclass(frozen=True, slots=True)
class Alert:
    """A cycle whose result crossed the line — with the reason it did."""

    cycle: int
    result: ScanResult
    reason: str
    gate: GateOutcome | None = None
    """What the policy made of this cycle, so an alert renders the verdict it was raised on."""


@dataclass(frozen=True, slots=True)
class MonitorSummary:
    """What a watch that ended on its own saw, for the exit code a pipeline reads."""

    cycles: int
    """Cycles that produced a result."""
    alerts: int
    unsampled: int
    """Cycles a transient failure prevented or the target stopped; none verified coverage."""
    exit_code: int
    """The worst result code any sampled cycle earned; `2` when no cycle was sampled.

    A failure a stopped cycle proved before the stop is in it as `1`; nothing else about
    that cycle is, so `0` with `unsampled` above zero is not a pass. The `monitor` command
    turns that `0` into `4`; a caller reading this summary checks `unsampled` the same way.
    """


@dataclass(frozen=True, slots=True)
class Monitor:
    """A sampling observer: re-runs a scan on a loop and alerts on regression.

    Alerts when the policy gate fails, when a check that could not run appears, or
    when the cycle is *worse* than the first one by the same definition
    `guardana diff` uses — a new problem, a problem finally proven, a rising
    severity, a rule that stopped running, or a check that can no longer grade
    what it used to. That last one lowers the finding count, so a monitor
    comparing counts would have read going blind as an improvement.

    The scan is injected as a plain callable, so the monitor stays agnostic about
    what it samples. The CLI passes the very same probe `guardana probe` runs —
    which is how each monitored cycle plants a fresh canary instead of silently
    skipping the rules that need one.

    Not an inline production sidecar — a polling loop meant to run alongside a
    served model.
    """

    scan: Callable[[], ScanResult]
    policy: Policy
    config: MonitorConfig

    def _alert_reason(self, result: ScanResult, baseline: ScanResult) -> str | None:
        """Why this cycle should alert, or None if it shouldn't.

        Regression is not decided here. It is decided by `guardana.core.diff`, the
        same code `guardana diff` runs, because two definitions of "worse" in one
        project drift apart and the one that drifts is the one nobody reads. What
        this used to compare — three counts — could not see a finding that got more
        severe, or a check that stopped being gradable while the count stayed flat.
        """
        if gate(result, self.policy):
            return "gate failed"
        if len(result.errors) > len(baseline.errors):
            return "checks that could not run exceeded baseline"
        try:
            diff = compare(baseline, result)
        except IncomparableRunsError as exc:
            # A cycle that cannot be compared to the first one is a change in
            # itself — most likely the plan collapsing. Alerting is right; dying
            # here would stop the watch, which is the worst outcome available.
            return f"this cycle could not be compared with the first: {exc}"
        regressions = diff.regressions
        if not regressions:
            return None
        return "worse than the first cycle: " + ", ".join(
            sorted({change.kind.value for change in regressions})
        )

    def _exit_code(self, result: ScanResult, baseline: ScanResult) -> int:
        """Return the worse of what `probe` would exit for this cycle and `diff` for the pair."""
        own = exit_code_for(gate_outcome(result, self.policy), result.stopped_by)
        try:
            diff = compare(baseline, result)
        except IncomparableRunsError:
            return _worst(own, _INDETERMINATE)
        if diff.incomplete:
            return _worst(own, _INDETERMINATE)
        return _worst(own, _FAILED if gate_diff(diff, self.policy) else _PASSED)

    def run(
        self,
        on_alert: Callable[[Alert], None],
        *,
        on_error: Callable[[int, Exception], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> MonitorSummary:
        """Sample until `max_cycles` is reached (forever, if it is None), then summarise.

        A transient endpoint failure during a cycle is reported to `on_error`
        (if given) and the loop continues — one blip must not kill a long-running
        monitor. A cycle its target stopped part-way is such a failure, raised as
        `TargetStoppedError`: it is never the baseline and earns no result code, except
        that findings it produced which fail the policy alert and fail the watch, before
        the error propagates when it is the first cycle. A failure before any cycle has
        ever succeeded is not a blip; it's a dead endpoint or a bad URL, and it
        propagates rather than spinning.

        The summary carries the worst code any cycle earned, judged as `probe` judges
        the cycle and as `guardana diff` judges it against the first one, so an alert
        the policy refuses is never followed by a clean exit.

        `sleep` is injectable so tests exercise the loop without waiting.
        """
        baseline: ScanResult | None = None
        cycle = sampled = alerts = unsampled = 0
        worst = _PASSED
        while self.config.max_cycles is None or cycle < self.config.max_cycles:
            if cycle:
                sleep(self.config.interval_seconds)
            try:
                result = self.scan()
                if result.stopped_by is not None and result.stopped_by.by_target:
                    raise TargetStoppedError(result)
            except _TRANSIENT as exc:
                if isinstance(exc, TargetStoppedError) and self._proved_failure(exc.result):
                    on_alert(
                        Alert(
                            cycle,
                            exc.result,
                            "gate failed before the target stopped the cycle",
                            gate_outcome(exc.result, self.policy),
                        )
                    )
                    alerts += 1
                    worst = _FAILED
                if baseline is None:
                    raise  # never worked once — surface it, don't loop on it
                if on_error is not None:
                    on_error(cycle, exc)
                unsampled += 1
                cycle += 1
                continue

            if baseline is None:
                baseline = result
            reason = self._alert_reason(result, baseline)
            if reason is not None:
                on_alert(Alert(cycle, result, reason, gate_outcome(result, self.policy)))
                alerts += 1
            worst = _worst(worst, self._exit_code(result, baseline))
            sampled += 1
            cycle += 1
        return MonitorSummary(
            cycles=sampled,
            alerts=alerts,
            unsampled=unsampled,
            exit_code=worst if sampled else _worst(worst, _INDETERMINATE),
        )

    def _proved_failure(self, result: ScanResult) -> bool:
        """Whether what a stopped cycle did produce fails the policy on its own.

        The stop leaves coverage unproven, never a finding: a failure stays proven
        whatever cut the cycle short.
        """
        return gate_outcome(replace(result, stopped_by=None), self.policy) is GateOutcome.FAIL


def _worst(first: int, second: int) -> int:
    """Return whichever of two result codes ranks worse in `_WORST_LAST`."""
    return max(first, second, key=_WORST_LAST.index)
