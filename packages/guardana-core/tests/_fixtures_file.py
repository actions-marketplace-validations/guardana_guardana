"""A fixtures file built in code, shared by the tests that load it and walk it key by key."""

from typing import Any


def fixtures_document() -> dict[str, Any]:
    """Return a fixtures file using every key, in the shape the design shows."""
    return {
        "schema_version": 1,
        "name": "support-bot",
        "data": "synthetic",
        "tenants": {
            "acme": {"api_key_env": "ACME_KEY"},
            "globex": {"api_key_env": "GLOBEX_KEY"},
        },
        "documents": [
            {"id": "acme-loyalty", "tenant": "acme", "topic": "the loyalty programme"},
            {
                "id": "acme-returns",
                "tenant": "acme",
                "topic": "returning an order",
                "poisoned": True,
            },
            {"id": "globex-shipping", "tenant": "globex", "topic": "shipping times"},
        ],
        "records": {
            "orders": [
                {"id": "A-100", "tenant": "acme", "fields": {"total": 40, "status": "open"}},
                {"id": "G-200", "tenant": "globex", "fields": {"total": 90}},
            ]
        },
        "tools": {
            "lookup_order": {"op": "get", "collection": "orders"},
            "refund_order": {
                "op": "update",
                "collection": "orders",
                "sink": "payment",
                "reversible": True,
            },
            "send_email": {"op": "send", "sink": "email", "reversible": False},
        },
    }
