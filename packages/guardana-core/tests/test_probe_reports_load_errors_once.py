"""A probe reports each plugin that did not load exactly once, whatever it ran.

Every canary pass reads the same registry, so each pass seeds the same load errors;
the probe reports each one once, and still reports them when no rule is left to run.
"""

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry
from guardana.core.report import CheckError
from guardana.core.target import EndpointTarget
from guardana.core.testing import RefusingTransport
from guardana.core.verify import Verifier

_BROKEN = CheckError(source="acme-rules", stage="discovery", reason="ImportError: no module")


def _probe(registry: Registry) -> tuple[CheckError, ...]:
    verification = Verifier(
        trust=PluginTrust(mode=PluginMode.BUILTINS), registry=registry, concurrency=1
    ).run(EndpointTarget("http://x", "m", transport=RefusingTransport()))
    return tuple(e for e in verification.result.errors if e == _BROKEN)


def test_a_load_error_is_reported_once_across_every_canary_pass() -> None:
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    registry.record_load_error(_BROKEN)

    assert _probe(registry) == (_BROKEN,)


def test_a_load_error_survives_a_probe_with_no_rule_to_run() -> None:
    registry = Registry()
    registry.record_load_error(_BROKEN)

    assert _probe(registry) == (_BROKEN,)


def test_two_plugins_that_failed_alike_are_two_errors() -> None:
    registry = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    registry.record_load_error(_BROKEN)
    registry.record_load_error(
        CheckError(source=_BROKEN.source, stage=_BROKEN.stage, reason=_BROKEN.reason)
    )

    assert _probe(registry) == (_BROKEN, _BROKEN)
