"""Safety-net coverage for ``post_agent_bookkeeping`` PROBE_PARAMETERS.

When a specialist agent completes without writing test_attempts for
some of its assigned parameters, the workflow's post-agent bookkeeping
must fabricate a ``verdict='failed'`` row for each missing parameter.
This guarantees the scheduler's retry caps bite on parameters that
silently fall through, instead of re-dispatching the same batch
forever.

Tests exercise the activity end-to-end against an in-memory SurrealDB;
the production activity code is unchanged — this slice only adds
coverage.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.client import GraphClient
from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.temporal.activities import (
    PostAgentBookkeepingInput,
    post_agent_bookkeeping,
)


@pytest_asyncio.fixture
async def mem_graph_client(monkeypatch):
    """Wire post_agent_bookkeeping's GraphClient to an in-memory SurrealDB."""
    db = AsyncSurreal("mem://")
    async with db:
        await db.use("vigilo", "test_bookkeeping")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)

        class _MemGraphClient(GraphClient):
            def __init__(self, url, session_id, user, password):
                self._url = url
                self.session_id = session_id
                self._user = user
                self._password = password
                self.db = db
                self._surreal = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

        monkeypatch.setattr(
            "src.greybox.graph.client.GraphClient",
            _MemGraphClient,
        )
        yield db


async def _seed_param(db: AsyncSurreal, pid: str) -> None:
    await db.query(
        f"""
        CREATE endpoint:ep_{pid.split(':')[1]} SET method = 'GET', path = '/x',
            full_url = 'http://t/x', discovered_by = 'test',
            discovered_at = time::now(), rate_limited = false,
            requires_auth = false, status_codes_seen = [200];
        CREATE {pid} SET name = 'p', location = 'query', data_type = 'int',
            shape = 'numeric_id', discovered_by = 'test',
            discovered_at = time::now();
        RELATE endpoint:ep_{pid.split(':')[1]}->has_param->{pid};
        """
    )


async def _fetch_attempts_for(db: AsyncSurreal, param_id: str) -> list[dict]:
    rows = await db.query(
        "SELECT <-tested_against<-test_attempt.* AS attempts "
        "FROM type::thing($id)",
        {"id": param_id},
    )
    if not rows:
        return []
    return rows[0].get("attempts") or []


@pytest.mark.asyncio
async def test_safety_net_marks_all_untested_params_failed(mem_graph_client):
    """All three params gain a failed test_attempt when agent wrote none."""
    db = mem_graph_client
    await _seed_param(db, "parameter:a")
    await _seed_param(db, "parameter:b")
    await _seed_param(db, "parameter:c")

    await post_agent_bookkeeping(
        PostAgentBookkeepingInput(
            session_id="test_bookkeeping",
            action_type="PROBE_PARAMETERS",
            target={
                "vuln_type": "injection",
                "param_ids": ["parameter:a", "parameter:b", "parameter:c"],
            },
            had_findings=False,
        )
    )

    for pid in ("parameter:a", "parameter:b", "parameter:c"):
        attempts = await _fetch_attempts_for(db, pid)
        assert len(attempts) == 1, f"expected 1 safety-net attempt for {pid}"
        attempt = attempts[0]
        assert attempt["verdict"] == "failed"
        assert attempt["failure_reason"] == "agent_produced_no_test_attempt"
        assert attempt["vuln_type"] == "injection"


@pytest.mark.asyncio
async def test_safety_net_skips_params_with_existing_attempt(mem_graph_client):
    """Pre-existing test_attempt for the vuln_type leaves that param alone."""
    db = mem_graph_client
    await _seed_param(db, "parameter:a")
    await _seed_param(db, "parameter:b")
    await _seed_param(db, "parameter:c")

    # Param a already has a conclusive attempt — safety net must not touch it.
    await db.query(
        """
        CREATE test_attempt:pre SET vuln_type = 'injection', technique = 't',
            payload = 'x', payload_hash = 'sha256:pre',
            verdict = 'conclusive_vulnerable',
            response_code = 200, duration_ms = 1, agent = 'specialist',
            attempted_at = time::now();
        RELATE test_attempt:pre->tested_against->parameter:a;
        """
    )

    await post_agent_bookkeeping(
        PostAgentBookkeepingInput(
            session_id="test_bookkeeping",
            action_type="PROBE_PARAMETERS",
            target={
                "vuln_type": "injection",
                "param_ids": ["parameter:a", "parameter:b", "parameter:c"],
            },
            had_findings=False,
        )
    )

    attempts_a = await _fetch_attempts_for(db, "parameter:a")
    assert len(attempts_a) == 1
    assert attempts_a[0]["verdict"] == "conclusive_vulnerable"

    for pid in ("parameter:b", "parameter:c"):
        attempts = await _fetch_attempts_for(db, pid)
        assert len(attempts) == 1
        assert attempts[0]["verdict"] == "failed"
        assert attempts[0]["failure_reason"] == "agent_produced_no_test_attempt"
