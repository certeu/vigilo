"""Tests for ``graph-tool finding`` dedup on (vuln_type, target) — Slice 14.4.

The specialist roster consolidation (9 → 4+2) concentrates more findings
under fewer vuln_types, raising the chance that multiple agents file the
same (vuln_type, target) pair. The ``finding`` command must short-circuit
when a prior finding exists for the same pair: no new node, no new edge,
and a ``deduplicated=True`` success message with the existing id.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from scripts.graph_tool import _run, build_parser


class _FakeClient:
    """Minimal GraphClient stand-in for dedup tests."""

    def __init__(self, raw_query_results=None):
        self.raw_query_results = raw_query_results or {}
        self.created_nodes: list[tuple] = []
        self.created_edges: list[tuple] = []
        self.queries: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def raw_query(self, query, params=None):
        self.queries.append((query, params or {}))
        for substring, rows in self.raw_query_results.items():
            if substring in query:
                return rows
        return []

    async def create_node(self, node_type, node_id, node):
        self.created_nodes.append((node_type, node_id, node))
        return {"id": f"{node_type}:{node_id}"}

    async def create_edge(self, edge_type, from_id, to_id, properties=None):
        self.created_edges.append((edge_type, from_id, to_id, properties))
        return None


def _install_fake_client(monkeypatch, fake):
    import src.greybox.graph.client as client_mod

    def _factory(*args, **kwargs):
        return fake

    monkeypatch.setattr(client_mod, "GraphClient", _factory)


def _run_cli(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    asyncio.run(_run(args))


def test_finding_short_circuits_on_duplicate_vuln_type_and_target(monkeypatch, capsys):
    """An existing finding for the same (vuln_type, target) must prevent the insert."""
    fake = _FakeClient(raw_query_results={
        # target exists
        "SELECT 1 FROM type::thing": [{"1": 1}],
        # dedup query returns an existing finding
        "SELECT id, severity, title FROM finding": [
            {"id": "finding:F_existing123", "severity": "high", "title": "prior SQLi"},
        ],
    })
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "finding",
        "--target", "parameter:p1",
        "--vuln-type", "injection",
        "--severity", "high",
        "--title", "SQLi in p1",
        "--impact", "database read",
    ])

    # No new node or edge must be written when the finding already exists.
    assert fake.created_nodes == []
    assert fake.created_edges == []

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["status"] == "success"
    assert payload.get("deduplicated") is True
    assert payload["id"] == "finding:F_existing123"


def test_finding_dedup_scoped_by_vuln_type(monkeypatch, capsys):
    """A prior finding of a *different* vuln_type on the same target must NOT dedup."""
    seen_queries: list[tuple[str, dict]] = []

    class _DedupClient(_FakeClient):
        async def raw_query(self, query, params=None):
            seen_queries.append((query, params or {}))
            if "SELECT 1 FROM type::thing" in query:
                return [{"1": 1}]
            if "SELECT id, severity, title FROM finding" in query:
                # Only return matches when both vuln_type AND target match.
                p = params or {}
                if p.get("vuln") == "injection" and p.get("target") == "parameter:p1":
                    return [{"id": "finding:F_prior", "severity": "high", "title": "x"}]
                return []
            return []

    fake = _DedupClient()
    _install_fake_client(monkeypatch, fake)

    # First call: reflection on parameter:p1 — dedup query returns empty, insert runs.
    _run_cli([
        "finding",
        "--target", "parameter:p1",
        "--vuln-type", "reflection",
        "--severity", "medium",
        "--title", "Reflected XSS",
        "--impact", "script execution",
    ])

    assert len(fake.created_nodes) == 1
    assert fake.created_nodes[0][0] == "finding"
    assert any(e[0] == "exploits" for e in fake.created_edges)

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["status"] == "success"
    assert payload.get("deduplicated", False) is False
    assert "Finding recorded" in payload.get("message", "")

    # The dedup query parameters must include both vuln_type and target.
    dedup_calls = [
        (q, p) for (q, p) in seen_queries
        if "SELECT id, severity, title FROM finding" in q
    ]
    assert dedup_calls, "finding command must query for duplicates"
    _, dedup_params = dedup_calls[0]
    assert dedup_params.get("vuln") == "reflection"
    assert dedup_params.get("target") == "parameter:p1"
