"""Tests for specialist dispatch-mode context resolution (Slice 14.3).

``resolve_agent_context`` must emit two new template variables derived
from the dispatch mode:
- ``batch_params`` — populated only when ``mode='batch'`` (else empty)
- ``lead_evidence`` — populated only when ``mode='lead'`` (else empty)
Plus ``dispatch_mode`` echoed as a template string.
"""
from __future__ import annotations

import pytest

from src.greybox.temporal.activities import (
    ResolveContextInput,
    resolve_agent_context,
)


class _FakeGraphClient:
    """Minimal async context manager stub for GraphClient."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def raw_query(self, query, params=None):
        # Node-counts query
        if "SELECT count() AS c FROM" in query:
            return [{"c": 0}]
        # Batch mode: parameter lookup
        if "FROM parameter" in query and "WHERE id IN $ids" in query:
            ids = (params or {}).get("ids", [])
            return [
                {
                    "id": pid,
                    "name": f"name_{pid}",
                    "shape": "free_text",
                    "location": "query",
                    "data_type": "string",
                    "endpoints": [{"method": "GET", "path": "/api/x", "full_url": "http://t/api/x"}],
                }
                for pid in ids
            ]
        # Lead mode: lead lookup
        if "FROM type::thing" in query:
            return [
                {
                    "id": (params or {}).get("id"),
                    "signal": "timing_anomaly",
                    "hypothesis": "possible blind SQLi",
                    "signal_strength": "high",
                    "evidence_blob_path": "deliverables/leads/abc.json",
                }
            ]
        return []


@pytest.fixture(autouse=True)
def _stub_deps(monkeypatch, tmp_path):
    # Stub out the graph client so the activity runs fully offline.
    monkeypatch.setattr(
        "src.greybox.graph.client.GraphClient", _FakeGraphClient
    )
    # No real credentials on disk — stub the loader.
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
async def test_batch_mode_populates_batch_params_empties_lead_evidence():
    result = await resolve_agent_context(
        ResolveContextInput(
            session_id="gb-batch-001",
            credentials_path="/tmp/creds.yaml",
            web_url="http://target.local",
            target='{"mode":"batch","vuln_type":"injection","param_ids":["parameter:p1","parameter:p2"]}',
        )
    )

    assert result["dispatch_mode"] == "batch"
    # Lead-side variables are empty in batch mode.
    assert result["lead_id"] == ""
    assert result["lead_signal"] == ""
    assert result["lead_hypothesis"] == ""
    assert result["evidence_blob_path"] == ""
    assert result["lead_evidence"] == ""
    # Batch-side variables are populated.
    assert "parameter:p1" in result["param_ids"]
    assert "parameter:p2" in result["param_ids"]
    assert "parameter:p1" in result["batch_params"]
    assert "parameter:p2" in result["batch_params"]


@pytest.mark.asyncio
async def test_lead_mode_populates_lead_evidence_empties_batch_params():
    result = await resolve_agent_context(
        ResolveContextInput(
            session_id="gb-lead-001",
            credentials_path="/tmp/creds.yaml",
            web_url="http://target.local",
            target='{"mode":"lead","lead_id":"lead:xyz"}',
        )
    )

    assert result["dispatch_mode"] == "lead"
    # Batch-side variables are empty in lead mode.
    assert result["vuln_type"] == ""
    assert result["param_ids"] == ""
    assert result["batch_params"] == ""
    # Lead-side variables are populated.
    assert result["lead_id"] == "lead:xyz"
    assert result["lead_signal"] == "timing_anomaly"
    assert result["lead_hypothesis"] == "possible blind SQLi"
    assert result["evidence_blob_path"] == "deliverables/leads/abc.json"
    # lead_evidence summarises the blob + hypothesis for the prompt.
    assert "lead:xyz" in result["lead_evidence"]
    assert "timing_anomaly" in result["lead_evidence"]
    assert "deliverables/leads/abc.json" in result["lead_evidence"]
