"""Resolver wiring for ``{{ENDPOINT_CONTEXT}}`` (Slice 15 / G1).

``resolve_agent_context`` must populate a new ``endpoint_context`` key
when running in ``batch`` mode — it drives the ``{{ENDPOINT_CONTEXT}}``
template variable. The rendered string surfaces cross-identity
visibility: sibling parameters, prior test_attempts, findings, and
access observations for the endpoint(s) the batch targets.
"""
from __future__ import annotations

import pytest

from src.greybox.temporal.activities import (
    ResolveContextInput,
    resolve_agent_context,
)


class _FakeGraphClient:
    """Minimal async context manager stub for GraphClient.

    Routes queries by pattern and returns shapes that mirror what
    SurrealDB would yield. The goal is to exercise
    ``endpoint_full_context`` end-to-end through the resolver without
    needing an in-process SurrealDB.
    """

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def raw_query(self, query, params=None):
        params = params or {}

        # Node-count summary
        if "SELECT count() AS c FROM" in query:
            return [{"c": 0}]

        # Batch mode: parameter lookup — include the endpoint id so the
        # resolver can pick it up and call endpoint_full_context.
        if "FROM parameter" in query and "WHERE id IN $ids" in query:
            ids = params.get("ids", [])
            return [
                {
                    "id": pid,
                    "name": f"name_{pid}",
                    "shape": "free_text",
                    "location": "query",
                    "data_type": "string",
                    "endpoints": [
                        {
                            "id": "endpoint:5",
                            "method": "GET",
                            "path": "/api/x",
                            "full_url": "http://t/api/x",
                        }
                    ],
                }
                for pid in ids
            ]

        # Identity list (for endpoint_full_context identity scope)
        if query.strip() == "SELECT id FROM identity":
            return [{"id": "identity:admin"}, {"id": "identity:user"}]

        # Siblings query: FROM parameter WHERE <-has_param<-endpoint CONTAINS ...
        if "FROM parameter" in query and "has_param" in query:
            return [
                {
                    "id": "parameter:p1",
                    "name": "id",
                    "location": "query",
                    "shape": "numeric_id",
                },
                {
                    "id": "parameter:p2",
                    "name": "slug",
                    "location": "query",
                    "shape": "free_text",
                },
            ]

        # Test attempts against the endpoint's parameters
        if "FROM test_attempt" in query and "tested_against" in query:
            return [
                {
                    "id": "test_attempt:ta1",
                    "vuln_type": "authorization",
                    "verdict": "inconclusive",
                    "agent": "specialist_authz",
                },
            ]

        # Findings exploiting the endpoint
        if "FROM finding" in query and "exploits" in query:
            return [
                {
                    "id": "finding:f1",
                    "vuln_type": "authorization",
                    "severity": "high",
                    "title": "Horizontal escalation on /api/x",
                },
            ]

        # can_access / denied_access
        if "FROM can_access" in query:
            return [{"identity_id": "identity:admin"}]
        if "FROM denied_access" in query:
            return [{"identity_id": "identity:user"}]

        return []


@pytest.fixture(autouse=True)
def _stub_deps(monkeypatch):
    monkeypatch.setattr(
        "src.greybox.graph.client.GraphClient", _FakeGraphClient
    )
    monkeypatch.setattr(
        "src.greybox.services.credentials.load_identities",
        lambda path: [],
    )
    monkeypatch.setattr(
        "src.greybox.services.credentials.build_login_block",
        lambda identity, web_url: "",
    )
    yield


@pytest.mark.asyncio
async def test_batch_mode_populates_endpoint_context_with_finding():
    """``endpoint_context`` surfaces the finding title for the endpoint."""
    result = await resolve_agent_context(
        ResolveContextInput(
            session_id="gb-endpoint-ctx-001",
            credentials_path="/tmp/creds.yaml",
            web_url="http://target.local",
            target='{"mode":"batch","vuln_type":"authorization","param_ids":["parameter:p1"]}',
        )
    )

    assert "endpoint_context" in result
    block = result["endpoint_context"]
    # The endpoint heading is always present.
    assert "Endpoint: endpoint:5" in block
    # Sibling parameter surfaces.
    assert "parameter:p1" in block or "id" in block
    # Prior test attempt surfaces with verdict.
    assert "authorization->inconclusive" in block
    # Finding title surfaces.
    assert "Horizontal escalation on /api/x" in block
    # Access observations surface per identity.
    assert "identity:admin=allowed" in block
    assert "identity:user=denied" in block
    # Slice 16 / G2: identities_block + identity_count are always present.
    assert "identities_block" in result
    assert "identity_count" in result
    # With load_identities stubbed to [], count is "0" and block is the
    # placeholder — not a raw template variable.
    assert result["identity_count"] == "0"
    assert result["identities_block"] == "No authenticated identities configured."
