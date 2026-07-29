"""Tests for graph-tool CLI argument parsing and command dispatch."""
from __future__ import annotations

import json

import pytest


def test_query_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args(["query", "--type", "endpoint", "--filter", "injectable=untested"])
    assert args.command == "query"
    assert args.type == "endpoint"
    assert args.filter == "injectable=untested"


def test_test_attempt_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "test-attempt",
        "--target", "parameter:search_q",
        "--vuln-type", "injection",
        "--technique", "union_based",
        "--payload", "' UNION SELECT NULL--",
        "--verdict", "conclusive_vulnerable",
        "--response-code", "200",
    ])
    assert args.command == "test-attempt"
    assert args.target == "parameter:search_q"
    assert args.vuln_type == "injection"
    assert args.verdict == "conclusive_vulnerable"
    assert args.failure_reason is None


def test_test_attempt_command_rejects_legacy_result_flag():
    import pytest
    from scripts.graph_tool import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "test-attempt",
            "--target", "parameter:search_q",
            "--vuln-type", "injection",
            "--technique", "union_based",
            "--payload", "x",
            "--result", "fail",
        ])


def test_test_attempt_command_accepts_failure_reason():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "test-attempt",
        "--target", "parameter:p1",
        "--vuln-type", "injection",
        "--technique", "timeout",
        "--payload", "' OR SLEEP(10)--",
        "--verdict", "failed",
        "--failure-reason", "agent_timeout",
    ])
    assert args.verdict == "failed"
    assert args.failure_reason == "agent_timeout"


def test_finding_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "finding",
        "--target", "parameter:search_q",
        "--vuln-type", "injection",
        "--severity", "high",
        "--cwe", "CWE-89",
        "--title", "SQL Injection in search",
        "--impact", "DB read access",
        "--grants", '["db_read"]',
        "--requires", '["authenticated"]',
    ])
    assert args.command == "finding"
    assert args.severity == "high"


def test_lead_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "lead",
        "--target", "endpoint:GET_admin",
        "--signal", "response_code_anomaly",
        "--hypothesis", "Possible auth bypass",
        "--signal-strength", "high",
    ])
    assert args.command == "lead"
    assert args.signal_strength == "high"


def test_lead_accepts_evidence_blob_and_produced_from():
    from scripts.graph_tool import build_parser
    from src.greybox.graph.schema import LeadNode

    parser = build_parser()
    args = parser.parse_args([
        "lead",
        "--target", "parameter:p1",
        "--signal", "timing_anomaly",
        "--hypothesis", "Possible blind SQLi",
        "--evidence-blob", "/ws/evidence/lead_L1.json",
        "--produced-from", "test_attempt:ta1",
    ])
    assert args.evidence_blob == "/ws/evidence/lead_L1.json"
    assert args.produced_from == "test_attempt:ta1"

    node = LeadNode(
        signal="timing_anomaly",
        hypothesis="...",
        evidence_blob_path="/ws/evidence/lead_L1.json",
        discovered_by="discovery",
    )
    assert node.evidence_blob_path == "/ws/evidence/lead_L1.json"


def test_claim_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "claim", "--id", "endpoint:GET_api_users",
        "--agent", "injection", "--ttl", "600",
    ])
    assert args.command == "claim"
    assert args.ttl == 600


def test_signal_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "signal", "--type", "credentials_found",
        "--data", '{"identity": "manager"}',
    ])
    assert args.command == "signal"
    assert args.type == "credentials_found"


def test_access_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "access", "--identity", "admin",
        "--endpoint", "GET:/api/admin",
        "--result", "allow", "--status-code", "200",
    ])
    assert args.command == "access"
    assert args.result == "allow"


def test_reflects_in_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "reflects-in",
        "--from", "parameter:p1",
        "--to", "endpoint:e1",
        "--context", "html_body",
    ])
    assert args.command == "reflects-in"
    assert args.from_id == "parameter:p1"
    assert args.to_id == "endpoint:e1"
    assert args.context == "html_body"


def test_reflects_in_rejects_unknown_context():
    import pytest
    from scripts.graph_tool import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "reflects-in", "--from", "parameter:p1",
            "--to", "endpoint:e1", "--context", "bogus",
        ])


@pytest.mark.parametrize("subcommand", ["slice", "bulk-add", "archive"])
def test_removed_subcommands_rejected(subcommand, capsys):
    """Slice 2: `slice`, `bulk-add`, and `archive` are removed — argparse must reject them as invalid choices."""
    from scripts.graph_tool import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([subcommand])
    err = capsys.readouterr().err
    # "invalid choice" — the subparser itself doesn't exist.
    # (A surviving subparser would instead complain about missing required args.)
    assert "invalid choice" in err, (
        f"Expected argparse to reject {subcommand!r} as invalid choice, "
        f"but stderr was: {err!r}"
    )


def test_raw_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "raw", "--query", "SELECT * FROM endpoint LIMIT 5",
    ])
    assert args.command == "raw"


def test_export_command_parses():
    from scripts.graph_tool import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "export", "--format", "yaml", "--max-tokens", "15000",
    ])
    assert args.command == "export"
    assert args.format == "yaml"
    assert args.max_tokens == 15000


def test_add_parameter_accepts_shape():
    """Shape field in --data payload must round-trip into a ParameterNode."""
    import json
    from src.greybox.graph.schema import ParameterNode

    payload = json.dumps({
        "name": "user_id",
        "location": "path",
        "data_type": "string",
        "shape": "numeric_id",
        "discovered_by": "discovery",
    })
    node = ParameterNode(**json.loads(payload))
    assert node.shape == "numeric_id"


def test_parse_filter_string():
    from scripts.graph_tool import parse_filter_string
    result = parse_filter_string("injectable=untested")
    assert result == {"injectable": "untested"}


def test_parse_filter_string_multiple():
    from scripts.graph_tool import parse_filter_string
    result = parse_filter_string("status=open,signal_strength=high")
    assert result == {"status": "open", "signal_strength": "high"}


def test_output_serializes_non_json_objects(capsys):
    from scripts.graph_tool import _output

    class _Opaque:
        def __str__(self) -> str:
            return "opaque-value"

    _output("success", id=_Opaque())
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"status": "success", "id": "opaque-value"}


# --- Slice 3 (A3): verify-target guard on finding and test-attempt -----------


class _FakeClient:
    """Minimal GraphClient stand-in for graph-tool CLI guard tests.

    - `raw_query_results` maps a query-substring → list-of-rows to return.
    - `created_nodes` / `created_edges` record writes so tests can assert
      the insert path ran (or didn't).
    """

    def __init__(self, raw_query_results=None):
        self.raw_query_results = raw_query_results or {}
        self.created_nodes: list[tuple] = []
        self.created_edges: list[tuple] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def raw_query(self, query, params=None):
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
    """Patch GraphClient in scripts.graph_tool's `_run` import site."""
    import src.greybox.graph.client as client_mod

    def _factory(*args, **kwargs):
        return fake

    monkeypatch.setattr(client_mod, "GraphClient", _factory)


def _run_cli(argv):
    """Parse argv and execute graph_tool._run synchronously (for tests)."""
    import asyncio

    from scripts.graph_tool import _run, build_parser

    parser = build_parser()
    args = parser.parse_args(argv)
    asyncio.run(_run(args))


def test_finding_rejects_missing_target(monkeypatch, capsys):
    """finding --target <nonexistent> must fail non-zero with a clear error."""
    fake = _FakeClient(raw_query_results={})  # empty → target not found
    _install_fake_client(monkeypatch, fake)

    with pytest.raises(SystemExit) as exc_info:
        _run_cli([
            "finding",
            "--target", "endpoint:nonexistent",
            "--vuln-type", "injection",
            "--severity", "high",
            "--title", "test",
            "--impact", "test",
        ])

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert "endpoint:nonexistent" in err
    # Insert path must not have run.
    assert fake.created_nodes == []
    assert fake.created_edges == []


def test_finding_accepts_existing_target(monkeypatch, capsys):
    """finding with an existing target must write the finding (no exit)."""
    fake = _FakeClient(raw_query_results={
        "SELECT 1 FROM type::thing": [{"1": 1}],
        # dedup query returns empty → not a duplicate
        "SELECT id, severity, title FROM finding": [],
    })
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "finding",
        "--target", "endpoint:exists",
        "--vuln-type", "injection",
        "--severity", "high",
        "--title", "test",
        "--impact", "test",
    ])

    assert len(fake.created_nodes) == 1
    node_type, _node_id, _node = fake.created_nodes[0]
    assert node_type == "finding"
    # One edge: exploits finding → target
    assert any(edge[0] == "exploits" for edge in fake.created_edges)
    out = capsys.readouterr().out
    assert "Finding recorded" in out or "Duplicate finding" in out


def test_test_attempt_rejects_missing_endpoint(monkeypatch, capsys):
    """test-attempt --target <nonexistent> must fail non-zero with a clear error."""
    fake = _FakeClient(raw_query_results={})  # empty → target not found
    _install_fake_client(monkeypatch, fake)

    with pytest.raises(SystemExit) as exc_info:
        _run_cli([
            "test-attempt",
            "--target", "parameter:nonexistent",
            "--vuln-type", "injection",
            "--technique", "union_based",
            "--payload", "' OR 1=1--",
            "--verdict", "conclusive_clean",
        ])

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert "parameter:nonexistent" in err
    # Insert path must not have run.
    assert fake.created_nodes == []
    assert fake.created_edges == []


def test_test_attempt_accepts_existing_endpoint(monkeypatch, capsys):
    """test-attempt with an existing target must write the attempt (no exit)."""
    fake = _FakeClient(raw_query_results={
        "SELECT 1 FROM type::thing": [{"1": 1}],
    })
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "test-attempt",
        "--target", "parameter:exists",
        "--vuln-type", "injection",
        "--technique", "union_based",
        "--payload", "' OR 1=1--",
        "--verdict", "conclusive_clean",
    ])

    assert len(fake.created_nodes) == 1
    node_type, _node_id, _node = fake.created_nodes[0]
    assert node_type == "test_attempt"
    assert any(edge[0] == "tested_against" for edge in fake.created_edges)
    out = capsys.readouterr().out
    assert "Test attempt recorded" in out
