"""Checks over the synthetic data a team seeded into its own application from a fixtures file.

Both ask through the application's own pipeline as a tenant Guardana chose, so the
verdict rests on which tenant was sent as and which markers came back, never on what
the application says about itself. Both need `Capability.SEEDED_DATA`, which only a
target built with `--fixtures` declares.
"""

from guardana.rules.seeded.cross_tenant_answer import CrossTenantAnswerRule
from guardana.rules.seeded.poisoned_document import PoisonedDocumentRule

__all__ = ["CrossTenantAnswerRule", "PoisonedDocumentRule"]
