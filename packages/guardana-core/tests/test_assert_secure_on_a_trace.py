"""`assert_secure` grades a trace a framework translator built, as the testing page shows."""

import pytest
from guardana.adapters.llama_index import llama_index_trace
from guardana.core.gate import GateOutcome
from guardana.core.target import TraceTarget
from guardana.testing import SecurityAssertionError, assert_secure


class _Node:
    def __init__(self, node_id: str, tenant: str) -> None:
        self.node_id = node_id
        self.metadata = {"tenant": tenant}
        self.text = "an invoice"
        self.ref_doc_id = None


class _Scored:
    def __init__(self, node: _Node) -> None:
        self.node = node
        self.node_id = node.node_id
        self.metadata = node.metadata
        self.score = 0.7

    def get_content(self) -> str:
        return self.node.text


def test_a_cross_tenant_retrieval_in_a_translated_trace_fails_the_assertion() -> None:
    trace = llama_index_trace(
        [_Scored(_Node("d1", "acme")), _Scored(_Node("d2", "globex"))],
        query="invoices",
        tenant="acme",
    )

    with pytest.raises(SecurityAssertionError, match="cross_tenant_retrieval") as raised:
        assert_secure(TraceTarget(trace))

    assert raised.value.outcome is GateOutcome.FAIL
