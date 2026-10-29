"""The rules and runs behind `sample_verifications`."""

from collections.abc import Iterable
from dataclasses import replace

from guardana.core.budget import Budgets
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, ChatMessage, EndpointTarget, Target, TargetKind
from guardana.core.target.protocols import FileReader
from guardana.core.testing.artifacts import files_target
from guardana.core.testing.transports import ScriptedTransport
from guardana.core.verify import Verification, Verifier

_MARKED = "marked"
"""The file stem the sample artifact rule reports."""

_QUESTIONS = 3
"""How many requests the sample chat rule sends; more than the stopped probe's budget."""


class _MarkedFile(Rule):
    """Report every file named `marked`, so a sample tree passes or fails by its names alone."""

    meta = RuleMeta(
        id="sample.marked_file",
        title="a file is named marked",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Yield one finding per file whose stem is `marked`."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files():
            if path.stem == _MARKED:
                yield Finding(
                    rule_id=self.meta.id,
                    severity=self.meta.severity,
                    title=self.meta.title,
                    taxonomy=(),
                    target_ref=str(path),
                    evidence=Evidence(summary=f"{path.name} is named {_MARKED}"),
                )


class _Questions(Rule):
    """Ask a chat target several questions and report nothing, so only a budget can stop it."""

    meta = RuleMeta(
        id="sample.questions",
        title="the model answers questions",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send each question in turn."""
        if not isinstance(target, EndpointTarget):
            return
        for number in range(_QUESTIONS):
            target.chat([ChatMessage(role="user", content=f"question {number}")])
        yield from ()


def _verifier(*rules: Rule, budgets: Budgets | None = None) -> Verifier:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    profile = default_profile()
    if budgets is not None:
        profile = replace(profile, budgets=budgets)
    return Verifier(trust=PluginTrust(mode=PluginMode.BUILTINS), profile=profile, registry=registry)


def run_samples() -> tuple[Verification, ...]:
    """Run the engine five times and return each run, in the order `sample_verifications` states."""
    scans = _verifier(_MarkedFile())
    return (
        scans.run(files_target({"model/config.json": "{}", "README.md": "a model"})),
        scans.run(files_target({"model/config.json": "{}", f"model/{_MARKED}.bin": b"\x00"})),
        scans.run(files_target({})),
        _verifier(_Questions(), budgets=Budgets(max_requests=1)).run(
            EndpointTarget(
                "http://sample.invalid/v1", "sample", transport=ScriptedTransport("an answer")
            )
        ),
        _verifier().run(files_target({"README.md": "a model"})),
    )
