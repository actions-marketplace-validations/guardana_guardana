from collections.abc import Iterable, Iterator, Mapping

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    Capability,
    McpError,
    RegistryEntry,
    Target,
    TargetKind,
    display_url,
)
from guardana.core.target.protocols import RegistryEntryInspector
from guardana.core.taxonomy import OWASP_ASI04_2026, OWASP_MCP04_2025, OWASP_MCP09_2025
from guardana.rules.mcp import _samples


class McpRegistryEntryRule(Rule):
    """An MCP server that is not the one its registry entry publishes.

    Neither MCP revision defines registry metadata a client can observe, and what a
    server reports about itself is self-reported. What a team can check is whether the
    server it deployed is the one its registry entry publishes, so the entry is the
    operator's input (`--mcp-registry-entry server.json`), never fetched.

    Two halves. Over HTTP, the URL the server answered at must be one of the entry's
    `remotes`: scheme and host compared lowercased, a default port and one trailing `/`
    dropped, the query compared apart from the address, a fragment ignored, and a
    `{variable}` standing for one or more characters other than `/`, `?` and `#` in the
    address, and other than `&` and `#` in the query. An entry without remotes publishes none.
    In either transport, the version the server reports in `serverInfo` (or in
    discovery `_meta`) is compared with the entry's: a different one is a low finding
    worded as what it is, a self-report; none reported leaves the comparison open.
    No request is made beyond the conversation's opening.
    """

    meta = RuleMeta(
        id="guardana.mcp.registry_entry",
        title="MCP server is not the one its registry entry publishes",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP09_2025, OWASP_MCP04_2025, OWASP_ASI04_2026),
        required_capabilities=frozenset({Capability.REGISTRY_ENTRY}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, and over the handshake era the conversation's `initialize`."""
        return 2

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """Empty: this rule compares what the server reported with what the operator gave."""
        return {}

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a server at an unpublished URL, a published one, and one reporting no version."""
        return materialise(
            (
                _samples.sample(
                    "a server at a URL its entry does not publish",
                    FixtureOutcome.FINDING,
                    lambda: _samples.target(
                        _samples.open_server(),
                        registry_entry=_samples.entry(remotes=("https://elsewhere.invalid/mcp",)),
                    ),
                ),
                _samples.sample(
                    "a server at its published URL reporting the published version",
                    FixtureOutcome.CLEAN,
                    lambda: _samples.target(
                        _samples.open_server(), registry_entry=_samples.entry()
                    ),
                ),
                _samples.sample(
                    "a server reporting no version",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _samples.target(
                        _samples.open_server(server_info={"name": "lookup", "version": ""}),
                        registry_entry=_samples.entry(),
                    ),
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Compare the URL the server answered at, then the version it reported, with the entry.

        A target without an entry yields nothing: the runner has already skipped this rule
        by capability, and the check returns rather than asserting because an `assert`
        vanishes under `python -O`.
        """
        if not isinstance(target, RegistryEntryInspector):
            return
        entry = target.registry_entry()
        url = target.server_url()
        if url is not None and not entry.publishes(url):
            yield self._finding(
                target,
                f"the server at {display_url(url)} is not a remote its registry entry "
                f"{entry.name} publishes",
            )
        yield from self._version(target, entry)

    def _version(self, target: Target, entry: RegistryEntry) -> Iterator[Finding]:
        if not isinstance(target, RegistryEntryInspector):
            return
        try:
            reported = target.reported_server()
        except McpError as exc:
            yield self._unverified(
                target,
                f"what the server reports about itself could not be read, so its version "
                f"was not compared with {entry.version}: {exc}",
            )
            return
        if reported is None:
            yield self._unverified(
                target, f"the server reports no version to compare with {entry.version}"
            )
            return
        if reported.version != entry.version:
            yield self._finding(
                target,
                f"the server reports version {reported.version}, and its registry entry "
                f"{entry.name} publishes {entry.version}; the reported version is the "
                f"server's own claim",
                severity=Severity.LOW,
            )

    def _finding(
        self, target: Target, summary: str, *, severity: Severity | None = None
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity or self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target.ref,
            evidence=Evidence(summary=summary, detail=f"server={target.ref}"),
        )

    def _unverified(self, target: Target, why: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target.ref,
            evidence=Evidence(summary=why, detail=f"server={target.ref}"),
            verdict=Verdict("inconclusive", 0.0, why, self.meta.id),
        )
