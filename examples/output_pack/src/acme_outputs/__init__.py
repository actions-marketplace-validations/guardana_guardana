"""Acme's Guardana outputs: the `acme-table` format and the `acme-webhook` reporter.

Each provider imports its module inside the function, so selecting the table never
imports the webhook, and a run that selects neither imports nothing here.
"""

from guardana.core.output import RendererSpec, ReporterSpec


def provide_table() -> RendererSpec:
    """Entry point target for `guardana.renderers`: the run as one CSV table."""
    from acme_outputs import table  # noqa: PLC0415 — imported only when selected

    return table.spec()


def provide_webhook() -> ReporterSpec:
    """Entry point target for `guardana.reporters`: the run's summary as a signed webhook."""
    from acme_outputs import webhook  # noqa: PLC0415 — imported only when selected

    return webhook.spec()
