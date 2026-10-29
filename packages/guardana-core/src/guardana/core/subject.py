"""What answered a run, as the team or the recording's producer declared it.

A leaf module, so a recording can carry the kind without importing the run manifest.
"""

from enum import StrEnum


class SubjectKind(StrEnum):
    """What answered a recipe's run, as the team declared it."""

    APPLICATION = "application"
    """The endpoint the team's users reach, with its own prompt, tools and data behind it."""

    MODEL_HARNESS = "model_harness"
    """A model reached without the application's prompt, tools and data."""
