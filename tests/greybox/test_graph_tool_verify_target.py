"""Slice 18 (G4): verify-target guard on every graph-tool subcommand that
references an existing node.

Slice 3 covered `test-attempt --target` and `finding --target`. This file
locks behavior for the remaining gaps enumerated in the hardening plan:
`finding --derived-from`, `lead --target`, `lead --produced-from`,
`access --identity`, `access --endpoint`, `relate --from`/`--to`,
`reflects-in --from`/`--to`, `update --id`, `claim --id`, `release --id`.
"""
from __future__ import annotations

import asyncio

import pytest


class _FakeClient:
    """GraphClient stand-in that can answer the verify-target lookup.

    `present_ids` is the set of record IDs that exist in the fake graph.
    The `SELECT 1 FROM type::thing($tgt)` verify query checks `params["tgt"]`
    against this set. Every other raw_query returns empty (so dedup / other
    lookups don't accidentally short-circuit the insert path).
    """

    def __init__(self, present_ids: set[str] | None = None):
        self.present_ids: set[str] = present_ids or set()
        self.created_nodes: list[tuple] = []
        self.created_edges: list[tuple] = []
        self.claim_calls: list[tuple] = []
        self.release_calls: list[tuple] = []
        self.update_calls: list[tuple] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def raw_query(self, query, params=None):
        q = query.strip()
        if "SELECT 1 FROM type::thing" in q:
            tgt = (params or {}).get("tgt", "")
            return [{"1": 1}] if tgt in self.present_ids else []
        # Any other query (dedup etc.) returns empty — let the insert path run.
        return []

    async def create_node(self, node_type, node_id, node):
        self.created_nodes.append((node_type, node_id, node))
        return {"id": f"{node_type}:{node_id}"}

    async def create_edge(self, edge_type, from_id, to_id, properties=None):
        self.created_edges.append((edge_type, from_id, to_id, properties))
        return None

    async def claim_node(self, node_id, agent, ttl):
        self.claim_calls.append((node_id, agent, ttl))
        return True

    async def release_claim(self, node_id, agent):
        self.release_calls.append((node_id, agent))
        return None

    async def update_node(self, node_id, pairs):
        self.update_calls.append((node_id, pairs))
        return None


def _install_fake_client(monkeypatch, fake):
    """Patch GraphClient in scripts.graph_tool's `_run` import site."""
    import src.greybox.graph.client as client_mod

    def _factory(*args, **kwargs):
        return fake

    monkeypatch.setattr(client_mod, "GraphClient", _factory)


def _run_cli(argv):
    """Parse argv and execute graph_tool._run synchronously (for tests)."""
    from scripts.graph_tool import _run, build_parser

    parser = build_parser()
    args = parser.parse_args(argv)
    asyncio.run(_run(args))


# ---------------------------------------------------------------------------
# "Rejects missing target" — one case per gapped subcommand + argument.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv,present_ids,expected_missing_id",
    [
        # finding --derived-from (target endpoint exists; test_attempt does not)
        (
            [
                "finding", "--target", "endpoint:ok", "--vuln-type", "injection",
                "--severity", "high", "--title", "t", "--impact", "i",
                "--derived-from", "test_attempt:missing",
            ],
            {"endpoint:ok"},
            "test_attempt:missing",
        ),
        # lead --target (the target endpoint is missing)
        (
            [
                "lead", "--target", "endpoint:missing", "--signal", "timing_anomaly",
                "--hypothesis", "maybe",
            ],
            set(),
            "endpoint:missing",
        ),
        # lead --produced-from (target exists; produced-from missing)
        (
            [
                "lead", "--target", "endpoint:ok", "--signal", "timing_anomaly",
                "--hypothesis", "h", "--produced-from", "test_attempt:missing",
            ],
            {"endpoint:ok"},
            "test_attempt:missing",
        ),
        # access --identity (identity missing; endpoint seeded as canonical id)
        (
            [
                "access", "--identity", "ghost", "--endpoint", "ok",
                "--result", "allow", "--status-code", "200",
            ],
            {"endpoint:ok"},
            "identity:ghost",
        ),
        # access --endpoint (identity present; endpoint missing)
        (
            [
                "access", "--identity", "admin", "--endpoint", "missing",
                "--result", "allow", "--status-code", "200",
            ],
            {"identity:admin"},
            "endpoint:missing",
        ),
        # relate --from (from-node missing)
        (
            [
                "relate", "--from", "endpoint:missing", "--to", "endpoint:ok",
                "--type", "links_to",
            ],
            {"endpoint:ok"},
            "endpoint:missing",
        ),
        # relate --to (to-node missing)
        (
            [
                "relate", "--from", "endpoint:ok", "--to", "endpoint:missing",
                "--type", "links_to",
            ],
            {"endpoint:ok"},
            "endpoint:missing",
        ),
        # reflects-in --from (from-parameter missing)
        (
            [
                "reflects-in", "--from", "parameter:missing", "--to", "endpoint:ok",
                "--context", "html_body",
            ],
            {"endpoint:ok"},
            "parameter:missing",
        ),
        # reflects-in --to (to-endpoint missing)
        (
            [
                "reflects-in", "--from", "parameter:ok", "--to", "endpoint:missing",
                "--context", "html_body",
            ],
            {"parameter:ok"},
            "endpoint:missing",
        ),
        # update --id (target node missing)
        (
            ["update", "--id", "parameter:missing", "--set", "name=foo"],
            set(),
            "parameter:missing",
        ),
        # claim --id (node to claim missing)
        (
            ["claim", "--id", "parameter:missing", "--agent", "a1"],
            set(),
            "parameter:missing",
        ),
        # release --id (node to release missing)
        (
            ["release", "--id", "parameter:missing", "--agent", "a1"],
            set(),
            "parameter:missing",
        ),
    ],
)
def test_missing_target_rejected(
    argv, present_ids, expected_missing_id, monkeypatch, capsys,
):
    """Every gapped subcommand must exit 1 with 'does not exist' on a missing ref."""
    fake = _FakeClient(present_ids=present_ids)
    _install_fake_client(monkeypatch, fake)

    with pytest.raises(SystemExit) as exc_info:
        _run_cli(argv)

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "does not exist" in err, f"stderr was: {err!r}"
    assert expected_missing_id in err, f"stderr was: {err!r}"

    # No write should land on a missing ref.
    assert fake.created_nodes == []
    assert fake.created_edges == []
    assert fake.claim_calls == []
    assert fake.release_calls == []
    assert fake.update_calls == []


# ---------------------------------------------------------------------------
# Happy path: with all refs present, each subcommand runs to completion
# and the expected write lands.
# ---------------------------------------------------------------------------


def test_finding_with_derived_from_writes_both_edges(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"endpoint:ok", "test_attempt:ta1"})
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "finding", "--target", "endpoint:ok", "--vuln-type", "injection",
        "--severity", "high", "--title", "t", "--impact", "i",
        "--derived-from", "test_attempt:ta1",
    ])

    assert any(e[0] == "exploits" for e in fake.created_edges)
    assert any(e[0] == "derived_from" and e[2] == "test_attempt:ta1"
               for e in fake.created_edges)


def test_lead_with_produced_from_writes_both_edges(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"endpoint:ok", "test_attempt:ta1"})
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "lead", "--target", "endpoint:ok", "--signal", "timing_anomaly",
        "--hypothesis", "h", "--produced-from", "test_attempt:ta1",
    ])

    assert any(e[0] == "observed_at" and e[2] == "endpoint:ok"
               for e in fake.created_edges)
    assert any(e[0] == "produced_from" and e[2] == "test_attempt:ta1"
               for e in fake.created_edges)


def test_access_writes_can_access_edge(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"identity:admin", "endpoint:ok"})
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "access", "--identity", "admin", "--endpoint", "ok",
        "--result", "allow", "--status-code", "200",
    ])

    assert any(e[0] == "can_access" and e[1] == "identity:admin"
               and e[2] == "endpoint:ok" for e in fake.created_edges)


def test_relate_writes_edge_when_both_present(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"endpoint:a", "endpoint:b"})
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "relate", "--from", "endpoint:a", "--to", "endpoint:b",
        "--type", "links_to",
    ])

    assert fake.created_edges == [("links_to", "endpoint:a", "endpoint:b", None)]


def test_reflects_in_writes_edge_when_both_present(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"parameter:p1", "endpoint:e1"})
    _install_fake_client(monkeypatch, fake)

    _run_cli([
        "reflects-in", "--from", "parameter:p1", "--to", "endpoint:e1",
        "--context", "html_body",
    ])

    assert len(fake.created_edges) == 1
    edge_type, from_id, to_id, props = fake.created_edges[0]
    assert edge_type == "reflects_in"
    assert from_id == "parameter:p1"
    assert to_id == "endpoint:e1"
    assert props == {"context": "html_body"}


def test_update_calls_update_node_when_present(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"parameter:p1"})
    _install_fake_client(monkeypatch, fake)

    _run_cli(["update", "--id", "parameter:p1", "--set", "name=foo"])

    assert fake.update_calls == [("parameter:p1", {"name": "foo"})]


def test_claim_calls_claim_node_when_present(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"parameter:p1"})
    _install_fake_client(monkeypatch, fake)

    _run_cli(["claim", "--id", "parameter:p1", "--agent", "a1"])

    assert fake.claim_calls == [("parameter:p1", "a1", 300)]


def test_release_calls_release_claim_when_present(monkeypatch, capsys):
    fake = _FakeClient(present_ids={"parameter:p1"})
    _install_fake_client(monkeypatch, fake)

    _run_cli(["release", "--id", "parameter:p1", "--agent", "a1"])

    assert fake.release_calls == [("parameter:p1", "a1")]
