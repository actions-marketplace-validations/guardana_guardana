"""Guardana's reference pack: one of every extension point, through the supported surface only.

Each provider below is what one entry point in `pyproject.toml` names. The two output
providers import their module inside the function, so a run that selects neither output
imports neither.
"""

from importlib import resources

from guardana.core import Evaluator, Registry, Rule, RuleLoadError, Target, TaxonomyRef
from guardana.core.output import RendererSpec, ReporterSpec

from guardana_reference_pack.controls import CONTROLS
from guardana_reference_pack.evaluator import MarkerEvaluator
from guardana_reference_pack.target import ReferenceRequirementsTarget
from guardana_reference_pack.unpinned import UnpinnedRequirementRule


def provide_rules() -> list[Rule]:
    """Entry point target for `guardana.rules`: the Python rule and every YAML rule."""
    return [UnpinnedRequirementRule(), *_yaml_rules()]


def provide_evaluators() -> list[Evaluator]:
    """Entry point target for `guardana.evaluators`: `reference.marker`."""
    return [MarkerEvaluator()]


def provide_targets() -> list[type[Target]]:
    """Entry point target for `guardana.targets`: `reference-requirements://`."""
    return [ReferenceRequirementsTarget]


def provide_taxonomies() -> list[TaxonomyRef]:
    """Entry point target for `guardana.taxonomies`: the `REFERENCE-CONTROLS` catalogue."""
    return list(CONTROLS)


def provide_summary() -> RendererSpec:
    """Entry point target for `guardana.renderers`: the `reference-summary` format."""
    from guardana_reference_pack import summary  # noqa: PLC0415 — imported only when selected

    return summary.spec()


def provide_file_reporter() -> ReporterSpec:
    """Entry point target for `guardana.reporters`: the `reference-file` reporter."""
    from guardana_reference_pack import file_reporter  # noqa: PLC0415 — imported only when selected

    return file_reporter.spec()


def _yaml_rules() -> tuple[Rule, ...]:
    """Load every YAML rule shipped in `rules/`, raising when any one of them does not load.

    `Registry.load_yaml_rule_dirs` records a broken file instead of raising; raised here,
    the whole provider fails, so a run reports the pack as broken rather than short a rule.
    """
    registry = Registry()
    folder = resources.files(__name__).joinpath("rules")
    for entry in sorted(folder.iterdir(), key=lambda item: item.name):
        if not entry.name.endswith(".yaml"):
            continue
        with resources.as_file(entry) as path:
            loaded = registry.load_yaml_rule_dirs([path])
        if loaded.errors:
            problems = "; ".join(f"{error.source}: {error.reason}" for error in loaded.errors)
            raise RuleLoadError(f"a rule shipped with the reference pack did not load: {problems}")
    if not registry.rules():
        raise RuleLoadError("the reference pack was installed without its YAML rules")
    return registry.rules()
