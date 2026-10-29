"""Real runs, produced by the engine over kit targets, for checking an output against.

An output tested only against a run built by hand sees the fields its author thought
of; these come out of `Verifier`, so they carry what a saved run carries.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardana.core.verify import Verification


def sample_verifications() -> "tuple[Verification, ...]":
    """Run the engine five times and return each run, in this order.

    A passed scan and a failed scan of `files_target` trees, an indeterminate scan of an
    empty tree (an `empty_target` shortfall), a probe of a scripted endpoint stopped by
    `max_requests`, and a scan in which no rule ran. Each call runs afresh, so every
    sample has its own run id; nothing is sent beyond the process.
    """
    # The rule package imports this kit's transports, so the engine is imported on call.
    from guardana.core.testing._sample_runs import run_samples  # noqa: PLC0415

    return run_samples()
