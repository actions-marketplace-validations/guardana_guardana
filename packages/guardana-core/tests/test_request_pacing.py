"""A request rate is a budget: every meter the profile reaches waits for its slot.

Measured on a fake clock and a fake sleep, never on wall time: a count of the slots
claimed means the same thing on a laptop and on a loaded runner.
"""

import json
import threading
from pathlib import Path

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.evaluator.config import wire_config_evaluators
from guardana.core.profile import Profile
from guardana.core.profile.model import Policy
from guardana.core.recording import Recording
from guardana.core.registry import Registry
from guardana.core.target import (
    ArtifactTarget,
    Capability,
    ChatMessage,
    EndpointTarget,
    Target,
    TargetKind,
)
from guardana.core.target.recorded import RecordedTarget
from guardana.core.testing import ScriptedTransport
from guardana.core.usage import UsageMeter


class _Clock:
    """A clock that moves only when the meter sleeps on it."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _meter(budgets: Budgets, clock: _Clock) -> UsageMeter:
    return UsageMeter(budgets, clock=clock, sleep=clock.sleep)


def test_requests_are_sent_no_closer_than_the_rate_allows() -> None:
    clock = _Clock()
    meter = _meter(Budgets(max_requests_per_minute=30), clock)

    for _ in range(4):
        meter.reserve()

    assert clock.slept == [2.0, 2.0, 2.0]
    assert clock.now == 6.0


def test_an_idle_meter_does_not_bank_a_burst() -> None:
    clock = _Clock()
    meter = _meter(Budgets(max_requests_per_minute=30), clock)
    meter.reserve()
    clock.now += 10.0

    meter.reserve()
    meter.reserve()

    assert clock.slept == [2.0], "the request after an idle spell goes at once, the next waits"


def test_without_a_rate_no_request_waits() -> None:
    clock = _Clock()
    meter = _meter(Budgets(max_requests=100), clock)

    for _ in range(5):
        meter.reserve()

    assert clock.slept == []


def test_concurrent_requests_each_claim_their_own_slot() -> None:
    claimed: list[float] = []
    lock = threading.Lock()

    def sleep(seconds: float) -> None:
        with lock:
            claimed.append(seconds)

    meter = UsageMeter(Budgets(max_requests_per_minute=60), clock=lambda: 100.0, sleep=sleep)
    start = threading.Barrier(8)

    def send() -> None:
        start.wait()
        meter.reserve()

    threads = [threading.Thread(target=send) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(claimed) == [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0], (
        "eight requests at one instant leave one at once and seven a second apart"
    )


def test_a_rate_that_would_wait_past_the_duration_ceiling_stops_before_sleeping() -> None:
    clock = _Clock()
    meter = _meter(Budgets(max_requests_per_minute=1, max_duration_seconds=90.0), clock)
    meter.reserve()
    meter.reserve()

    with pytest.raises(BudgetExhausted, match="time budget"):
        meter.reserve()

    assert clock.slept == [60.0], "the third slot lies past the ceiling, so nothing waits for it"
    assert clock.now == 60.0


def test_a_refused_slot_is_not_claimed() -> None:
    clock = _Clock()
    meter = _meter(Budgets(max_requests_per_minute=1, max_duration_seconds=90.0), clock)
    meter.reserve()
    meter.reserve()
    with pytest.raises(BudgetExhausted):
        meter.reserve()

    meter.apply(Budgets(max_requests_per_minute=1))
    meter.reserve()

    assert clock.slept == [60.0, 60.0]


def test_a_rate_is_a_ceiling() -> None:
    assert not Budgets(max_requests_per_minute=10).is_unbounded


def test_a_retry_waits_for_its_own_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    replies: list[object] = [
        _rate_limited(),
        _Answer({"choices": [{"message": {"content": "hi"}}]}),
    ]

    def fake_open(request: object, timeout: float) -> object:
        outcome = replies.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr("guardana.core.target.endpoint.open_unredirected", fake_open)
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", lambda seconds: None)
    clock = _Clock()
    target = EndpointTarget(
        "http://model.test", "m", meter=_meter(Budgets(max_requests_per_minute=20), clock)
    )

    assert target.chat([ChatMessage(role="user", content="hello")]) == "hi"
    assert clock.slept == [3.0], "the retry is a request, and it waits for the next slot"
    assert target.usage().requests == 2


def test_each_judge_paces_itself_on_its_own_meter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDANA_TEST_JUDGE_KEY", "judge-key")
    clock = _Clock()
    profile = Profile(
        name="t",
        policy=Policy(),
        evaluator_config={
            "llm_judge": {
                "endpoint": "https://judge.example/v1",
                "model": "j",
                "api_key_env": "GUARDANA_TEST_JUDGE_KEY",
            }
        },
    )

    def build(url: str, model: str, api_key: str | None) -> EndpointTarget:
        return EndpointTarget(
            url,
            model,
            api_key=api_key,
            transport=ScriptedTransport("PASS"),
            meter=UsageMeter(clock=clock, sleep=clock.sleep),
        )

    (judge,) = wire_config_evaluators(
        Registry(), profile, Budgets(max_requests_per_minute=12), build=build
    ).meters
    for _ in range(3):
        judge.ask("grade this")

    assert clock.slept == [5.0, 5.0]


@pytest.mark.parametrize(
    "target",
    [
        ArtifactTarget(Path()),
        RecordedTarget(
            Recording(
                name="r",
                version="1",
                verbatim=True,
                subject=None,
                origin=None,
                exchanges=(),
                digest=None,
            )
        ),
    ],
    ids=["files", "recording"],
)
def test_a_target_that_sends_nothing_accepts_a_rate(target: Target) -> None:
    target.apply_budgets(Budgets(max_requests_per_minute=6))


def test_a_target_that_does_not_meter_itself_refuses_a_rate() -> None:
    class _Unmetered(Target):
        kind = TargetKind.ENDPOINT

        @property
        def ref(self) -> str:
            return "acme://unmetered"

        def capabilities(self) -> set[Capability]:
            return set()

    with pytest.raises(BudgetExhausted):
        _Unmetered().apply_budgets(Budgets(max_requests_per_minute=6))


class _Answer:
    def __init__(self, payload: object) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self, size: int = -1) -> bytes:
        return self._body

    def __enter__(self) -> "_Answer":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _rate_limited() -> Exception:
    from urllib.error import HTTPError  # noqa: PLC0415

    return HTTPError("http://model.test", 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]
