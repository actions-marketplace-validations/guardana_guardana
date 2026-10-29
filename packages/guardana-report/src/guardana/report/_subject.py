"""What answered a recipe's run and what it was seeded with, in the words every output uses."""

from guardana.core.manifest import RunManifest, SubjectKind

_LABEL = {SubjectKind.APPLICATION: "application", SubjectKind.MODEL_HARNESS: "model harness"}


def subject_line(run: RunManifest | None) -> str | None:
    """Return the line naming what answered, or None for a run no recipe started."""
    if run is None or run.recipe is None:
        return None
    recipe = run.recipe
    line = f"subject: {_LABEL[recipe.kind]}, from a {recipe.source} — recipe {recipe.name}"
    if recipe.kind is SubjectKind.MODEL_HARNESS:
        line += " (a model reached without the application's prompt, tools and data)"
    return line


def fixtures_line(run: RunManifest | None) -> str | None:
    """Return the line naming the fixtures a run was given, or None for a run given none."""
    if run is None or run.fixtures is None:
        return None
    return f"fixtures: {run.fixtures.describe()}"


def suite_name(run: RunManifest | None) -> str:
    """Name a JUnit suite after what answered, so a CI test view shows it beside the result."""
    if run is None or run.recipe is None:
        return "guardana"
    return f"guardana ({_LABEL[run.recipe.kind]})"
