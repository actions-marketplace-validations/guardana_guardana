"""A server nobody could reach stops the run, and no rule turns that into a verdict.

Silence from a rule here means *the invariant holds*, so a rule that said nothing
about a server it never reached would read as clean. An inconclusive verdict from
each rule was honest and still wrong about the cause: the server failed, not eight
checks, and a run that carried on spent one failure per rule before exiting `2`.
"""

import pytest
from _offline import refuse_name_lookups
from guardana.core.gate import StopReason
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.rule import Rule, RuleContext
from guardana.core.runner import Runner, target_failures
from guardana.core.target import EndpointUnreachable, McpServerTarget
from guardana.rules.mcp import (
    McpAuthorizationDiscoveryRule,
    McpCacheScopeRule,
    McpDiscoveryTargetRule,
    McpIssuerIdentificationRule,
    McpScopeBreadthRule,
    McpSessionBindingRule,
    McpTokenAudienceRule,
    McpUnauthenticatedAccessRule,
)
from mcp_fixtures import ROUTABLE, unreachable

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

EVERY_MCP_RULE: list[Rule] = [
    McpUnauthenticatedAccessRule(),
    McpAuthorizationDiscoveryRule(),
    McpTokenAudienceRule(),
    McpSessionBindingRule(),
    McpScopeBreadthRule(),
    McpDiscoveryTargetRule(),
    McpIssuerIdentificationRule(),
    McpCacheScopeRule(),
]


@pytest.mark.parametrize("rule", EVERY_MCP_RULE, ids=lambda rule: rule.meta.id)
def test_a_rule_meets_a_server_it_never_reached_as_the_servers_failure(rule: Rule) -> None:
    target = McpServerTarget(ROUTABLE, sender=unreachable, discovery_sender=unreachable)

    with pytest.raises(EndpointUnreachable) as raised:
        list(rule.run(target, RuleContext()))

    assert f"the MCP server at {ROUTABLE} did not answer" in str(raised.value)


def test_a_run_against_a_server_nobody_reached_stops_with_no_verdict() -> None:
    registry = Registry()
    for rule in EVERY_MCP_RULE:
        registry.register_rule(rule)
    target = McpServerTarget(ROUTABLE, sender=unreachable, discovery_sender=unreachable)

    result = Runner(registry=registry, profile=Profile("t", Policy()), concurrency=1).run(target)

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert result.findings == ()
    assert result.rules_run == ()
    (said,) = target_failures(result)
    assert f"the MCP server at {ROUTABLE} did not answer" in said
