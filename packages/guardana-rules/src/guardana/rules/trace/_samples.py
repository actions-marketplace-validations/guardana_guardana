"""The recorded executions the trace rules sample themselves against.

Each sample is a trace built in code from a producer that records every dimension, so
what a sample leaves out is a fact about the execution rather than an instrumentation
gap. A target is built fresh for each run.
"""

from collections.abc import Callable

from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome
from guardana.core.target import Target, TraceTarget
from guardana.core.trace import Dimension, Provenance, Span, Trace, TraceTruncation

SOURCE = "sample.jsonl"


def target(
    *spans: Span, truncated: TraceTruncation | None = None, unreadable: int = 0
) -> TraceTarget:
    """Build a target over one execution holding `spans`, read whole unless told otherwise."""
    return TraceTarget(
        Trace(
            trace_id="sample",
            spans=spans,
            provenance=Provenance(producer="sample-agent", source=SOURCE, dialect="guardana"),
            instrumented=frozenset(Dimension),
            truncated=truncated,
            unreadable=unreadable,
        )
    )


def sample(
    name: str, outcome: FixtureOutcome, build: Callable[[], Target], note: str = ""
) -> DeclaredFixture:
    """Declare one sample whose trace is built afresh each time the rule is verified."""
    return DeclaredFixture(name, outcome, build, note)
