"""What every MCP authorization rule shares: one observation, and two ways to speak.

The observation is bought by the target and read here. The two ways to speak are a
finding — *this invariant does not hold* — and an unverified verdict — *this
question could not be asked, and here is why*. There is deliberately no third way,
because "said nothing" has to mean "the invariant held", and a rule that could not
run has to say so rather than fall into that silence.
"""

from abc import abstractmethod
from collections.abc import Iterable, Iterator, Mapping

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext
from guardana.core.severity import Severity
from guardana.core.target import McpAuthorizationView, Target
from guardana.core.target.protocols import AuthorizationInspector

METADATA_NOT_FETCHED = (
    "the server answers an anonymous caller, so its authorization metadata was never fetched"
)
"""Why a rule grading the metadata documents declines on a server open to anyone."""


class McpReporting(Rule):
    """The two ways an MCP rule is allowed to speak, and the evidence both carry.

    Separate from `McpAuthorizationRule` because not every MCP rule grades the
    authorization observation alone — one reads the manifest too — and a second
    copy of these constructors would be a second place for a finding's shape to
    drift.
    """

    claim = "this check could not be made"
    """What this rule would have established, phrased to follow "so …" in a sentence."""

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """Empty: an MCP rule grades what the server revealed in its own code."""
        return {}

    def finding(
        self, view: McpAuthorizationView, summary: str, *, severity: Severity | None = None
    ) -> Finding:
        """Report that the invariant this rule tests does not hold on this server."""
        return Finding(
            rule_id=self.meta.id,
            severity=severity or self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=view.server,
            evidence=Evidence(summary=summary, detail=f"server={view.server}"),
        )

    def unverified(self, view: McpAuthorizationView, why: str) -> Finding:
        """Report that the question could not be asked, which is never a pass."""
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=view.server,
            evidence=Evidence(summary=why, detail=f"server={view.server}"),
            verdict=Verdict("inconclusive", 0.0, why, self.meta.id),
        )

    def unreachable(self, view: McpAuthorizationView) -> Finding | None:
        """Return the verdict to report when the server could not be examined, or None.

        Every rule here calls this first. A server that sent no reply stops the run
        before any rule grades it; this is the server that answered with something no
        observation can be made from — a revision guardana does not speak, a status
        that is neither a session nor a refusal — and the reason is quoted. Silence
        from a rule means *the invariant holds*, so a rule that said nothing here would
        be claiming the invariant holds on a server it never examined.
        """
        error = view.anonymous.error
        if error is None:
            return None
        return self.unverified(view, f"the server could not be examined, so {self.claim}: {error}")


class McpAuthorizationRule(McpReporting):
    """A rule that grades one part of what a server's authorization surface revealed.

    Subclasses implement `examine` and never touch a socket: the requests were made
    by the target, once, and shared with every rule that reads the same section.
    """

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Read the shared observation and grade it. Never a type assertion.

        A target this rule cannot examine yields nothing here, because the runner
        has already skipped the rule by capability — `INSPECT_AUTHORIZATION` is
        declared only by an MCP server reached over HTTP. This check is the belt to
        that braces, and it returns rather than asserting because an `assert`
        vanishes under `python -O`.
        """
        if not isinstance(target, AuthorizationInspector):
            return
        yield from self.examine(target.authorization())

    def metadata_not_fetched(self, view: McpAuthorizationView) -> Finding:
        """Decline on a server open to anyone, where discovery is never attempted.

        Whatever such a server publishes went unread, so silence here would grade a
        document nobody fetched. The rule that reports the open server is a different
        id, and a profile may have excluded it.
        """
        return self.unverified(
            view,
            f"{METADATA_NOT_FETCHED} and {self.claim}; "
            f"guardana.mcp.unauthenticated_access reports the open server",
        )

    @abstractmethod
    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Grade the observation, yielding a finding or an unverified verdict per claim."""


def further_issuers(view: McpAuthorizationView) -> tuple[str, ...]:
    """Return the authorization servers the resource names after the first, in its order.

    Only the first one's metadata is ever fetched, so whatever these advertise was not seen.
    """
    resource = view.protected_resource
    content = None if resource is None else resource.content
    issuers = None if content is None else content.get("authorization_servers")
    if not isinstance(issuers, list):
        return ()
    named = list(dict.fromkeys(entry for entry in issuers if isinstance(entry, str) and entry))
    return tuple(named[1:])
