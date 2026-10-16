import json
from collections.abc import Iterable, Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import ATLAS_T0057, OWASP_ASI03_2026, OWASP_LLM02_2026
from guardana.core.testing import fake_llm_key
from guardana.core.trace import Span, SpanKind, ToolExecution, Trace
from guardana.rules.trace import _samples
from guardana.rules.trace._base import TraceRule

from guardana.rules._secrets import (  # isort: skip — shared with the two scanning rules
    ALLOWLIST,
    REPLY_SECRET_PATTERNS,
    redact,
)


class SecretInToolArgumentRule(TraceRule):
    """A credential travelled out of the conversation inside a tool argument.

    The one check here that works on a plain OpenTelemetry export, because it needs only
    what the conventions carry: tool calls and their arguments. An agent that puts an API
    key into `http_request(headers=…)` or a password into a shell command has moved a
    secret from wherever it was configured into somebody else's log — and in a trace it
    is already *in* a log, which is the point.

    Patterns are the ones the two secret-scanning rules use, so there is one definition
    of what a credential looks like. Precision over recall: no bare-entropy matching, and
    documentation fixtures are allowlisted, because a false positive here teaches people
    to switch the rule off.
    """

    meta = RuleMeta(
        id="guardana.trace.secret_in_tool_argument",
        title="A credential appeared in a recorded tool argument",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_LLM02_2026, OWASP_ASI03_2026, ATLAS_T0057),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_TOOL_CALLS}),
        detection=Detection.HEURISTIC,
    )

    claim = "whether a credential travelled in a tool argument is not established"

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a key in a request header, a plain request, and one beside an unread record."""
        return materialise(
            (
                _samples.sample(
                    "an API key passed to an HTTP tool as a request header",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(_request(header=fake_llm_key())),
                ),
                _samples.sample(
                    "an HTTP tool called with a URL and nothing secret",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(_request()),
                ),
                _samples.sample(
                    "a plain request beside a record the reader could not interpret",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(_request(), unreadable=1),
                    "the unread record may be a tool call carrying a credential",
                ),
            )
        )

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Scan every recorded tool argument, from the execution and from the message part.

        Both places, because they are different records of the same call and a producer may
        emit either: an `execute_tool` span carries the arguments as an attribute, while a
        chat span carries them inside an assistant message's `tool_call` part. A call whose
        arguments neither record holds — matched by call id where both carry one — was not
        examined, and is declined in one aggregated line rather than passed.
        """
        for span in trace.spans:
            for tool_name, arguments in self._arguments(span):
                for label, secret in self._secrets(arguments):
                    yield self.finding(
                        trace,
                        f"a {label} appears in the arguments of {tool_name} in span "
                        f"{span.span_id} ({redact(secret)}) — the credential is now in "
                        f"whatever holds this trace",
                        span=span,
                    )
        unread = _unrecorded_calls(trace)
        if unread:
            yield self.unverified(
                trace,
                f"{len(unread)} tool call(s) record no arguments ({'; '.join(unread)}), so "
                f"{self.claim} for them",
            )

    def _arguments(self, span: Span) -> Iterator[tuple[str, str]]:
        if span.tool is not None and span.tool.arguments:
            yield span.tool.name, span.tool.arguments
        for message in span.messages:
            for part in message.tool_calls():
                if part.arguments:
                    yield part.tool_name or "an unnamed tool", part.arguments

    def _secrets(self, text: str) -> Iterator[tuple[str, str]]:
        """Yield each credential-shaped match, skipping the public example values.

        The allowlist is the same one the file and reply scanners use: quoting AWS's
        canonical example key is citation, not leakage, and a rule that cannot tell the
        difference is a rule people exclude.
        """
        for label, pattern in REPLY_SECRET_PATTERNS:
            for match in pattern.finditer(text):
                found = match.group(0)
                if found not in ALLOWLIST:
                    yield label, found


def _unrecorded_calls(trace: Trace) -> list[str]:
    """Name the tool calls whose arguments no record of the call holds."""
    argued = {
        call
        for span in trace.spans
        for call in (
            *((span.tool.call_id,) if span.tool and span.tool.arguments is not None else ()),
            *(
                part.call_id
                for message in span.messages
                for part in message.tool_calls()
                if part.arguments is not None
            ),
        )
        if call is not None
    }
    unread: list[str] = []
    for span in trace.spans:
        tool = span.tool
        if tool is not None and tool.arguments is None and tool.call_id not in argued:
            unread.append(f"{tool.name} in span {span.span_id}")
        unread.extend(
            f"{part.tool_name or 'an unnamed tool'} in span {span.span_id}"
            for message in span.messages
            for part in message.tool_calls()
            if part.arguments is None and part.call_id not in argued
        )
    return unread


def _request(*, header: str | None = None) -> Span:
    """Build an HTTP tool call, sending `header` as its API key when one is given."""
    arguments: dict[str, object] = {"url": "https://api.invalid/v1/items"}
    if header is not None:
        arguments["headers"] = {"x-api-key": header}
    return Span(
        span_id="s1",
        kind=SpanKind.TOOL_EXECUTION,
        name="http_request",
        tool=ToolExecution(name="http_request", arguments=json.dumps(arguments)),
    )
