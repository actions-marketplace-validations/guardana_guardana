"""A reference retrieval application the tenancy and poisoning checks run against.

Served with the standard library; its tools are Guardana's stateful doubles. The
example's README says how to run it and what each switch breaks.
"""

from retrieval_pilot.app import (
    NOT_FOUND,
    ORDER_TOOL,
    CredentialsError,
    MalformedRequestError,
    ReferenceApplication,
    Switches,
    make_server,
)
from retrieval_pilot.index import Document, KeywordIndex

__all__ = [
    "NOT_FOUND",
    "ORDER_TOOL",
    "CredentialsError",
    "Document",
    "KeywordIndex",
    "MalformedRequestError",
    "ReferenceApplication",
    "Switches",
    "make_server",
]
