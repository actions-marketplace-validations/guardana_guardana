"""A saved run over any trace target records the digest of the document it was read from."""

from guardana.cli._run_meta import target_identity
from guardana.core.fingerprint import DigestKind, DocumentDigest
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.trace import Provenance, Trace

_DOCUMENT = DocumentDigest.of(b'{"guardana_trace": 3}\n', DigestKind.CONTENT)


class _InstalledTraceTarget(Target):
    """A third party's trace target: it reads a trace, and is not the built-in class."""

    kind = TargetKind.TRACE

    def __init__(self, document: DocumentDigest | None) -> None:
        provenance = Provenance(
            producer="acme", source="acme://session/1", dialect="acme", document=document
        )
        self._trace = Trace(trace_id="t-1", spans=(), provenance=provenance)

    @property
    def trace(self) -> Trace:
        return self._trace

    @property
    def ref(self) -> str:
        return "acme://session/1"

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_TRACE}


def test_an_installed_trace_target_records_the_document_its_trace_was_read_from() -> None:
    target = _InstalledTraceTarget(_DOCUMENT)

    identity = target_identity(target, target.ref)

    assert identity.document == _DOCUMENT
    assert identity.fingerprint_inputs == ("kind", "ref")


def test_a_trace_read_from_no_document_records_none_rather_than_a_digest() -> None:
    target = _InstalledTraceTarget(None)

    assert target_identity(target, target.ref).document is None
