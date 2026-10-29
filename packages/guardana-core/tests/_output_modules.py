"""Module bodies for fake installed outputs, each leaving a marker beside itself when imported.

`NAME` in a body is replaced with the output's name before the module is written. A
recording output appends every `Verification` it is handed to the module's `SEEN`, so a
test reads what crossed the boundary at the seam where it arrived.
"""

_MARK = """\
import sys
from pathlib import Path

from guardana.core.output import Delivery, DeliveryStatus, RendererSpec, ReporterSpec

Path(__file__).with_name(__name__ + ".imported").write_text("imported", encoding="utf-8")
SEEN = []
"""

RECORDING_RENDERER = (
    _MARK
    + """

def _render(verification):
    SEEN.append(verification)
    return "rendered"


def provide():
    return RendererSpec(name="NAME", summary="records what it is handed", render=_render)
"""
)

RECORDING_REPORTER = (
    _MARK
    + """

class _Deliverer:
    destination = "https://hooks.example.invalid"

    def __init__(self, locator):
        self.locator = locator

    def sent_secrets(self):
        return ()

    def deliver(self, verification):
        SEEN.append(verification)
        return Delivery(DeliveryStatus.DELIVERED, attempts=1, http_status=204)


def provide():
    return ReporterSpec(
        name="NAME", summary="records what it is handed", prepare=lambda r: _Deliverer(r.locator)
    )
"""
)

RAISING_PROVIDER = (
    _MARK
    + """

def provide():
    raise ValueError("the provider is broken")
"""
)

EXITING_PROVIDER = (
    _MARK
    + """

def provide():
    sys.exit(0)
"""
)

INTERRUPTED_PROVIDER = (
    _MARK
    + """

def provide():
    raise KeyboardInterrupt
"""
)

WRONG_TYPE_PROVIDER = (
    _MARK
    + """

def provide():
    return 42
"""
)

MISNAMED_PROVIDER = (
    _MARK
    + """

def provide():
    return RendererSpec(name="someone-else", summary="s", render=lambda v: "x")
"""
)

FAILING_IMPORT = """\
from pathlib import Path

Path(__file__).with_name(__name__ + ".imported").write_text("imported", encoding="utf-8")
raise RuntimeError("this module was imported")
"""

EXITING_IMPORT = """\
import sys
from pathlib import Path

Path(__file__).with_name(__name__ + ".imported").write_text("imported", encoding="utf-8")
sys.exit(0)
"""

RAISING_PREPARE = (
    _MARK
    + """

def _prepare(request):
    raise ValueError("ACME_WEBHOOK_URL is not set")


def provide():
    return ReporterSpec(name="NAME", summary="s", prepare=_prepare)
"""
)

EXITING_PREPARE = (
    _MARK
    + """

def _prepare(request):
    sys.exit(0)


def provide():
    return ReporterSpec(name="NAME", summary="s", prepare=_prepare)
"""
)

NO_DELIVERER_PREPARE = (
    _MARK
    + """

def provide():
    return ReporterSpec(name="NAME", summary="s", prepare=lambda request: object())
"""
)

SECRET_DESTINATION_PREPARE = (
    _MARK
    + """

class _Deliverer:
    def __init__(self, locator):
        self.destination = locator

    def sent_secrets(self):
        return (self.destination.rsplit("/", 1)[-1],)

    def deliver(self, verification):
        return Delivery(DeliveryStatus.DELIVERED)


def provide():
    return ReporterSpec(name="NAME", summary="s", prepare=lambda r: _Deliverer(r.locator))
"""
)


UNWITHHELD_DESTINATION_PREPARE = (
    _MARK
    + """

class _Deliverer:
    def __init__(self, locator):
        self.destination = locator

    def sent_secrets(self):
        return ()

    def deliver(self, verification):
        return Delivery(DeliveryStatus.DELIVERED)


def provide():
    return ReporterSpec(name="NAME", summary="s", prepare=lambda r: _Deliverer(r.locator))
"""
)


def body(template: str, name: str) -> str:
    """Return `template` with the output's name written in."""
    return template.replace("NAME", name)
