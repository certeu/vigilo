"""Shared pytest fixtures for the grey-box test suite.

The ``graph_fixture`` boots an in-memory SurrealDB (``mem://``),
applies the full DDL from ``init_schema``, and seeds the known shape
the view tests depend on:

    - 5 parameters with ``shape = "numeric_id"`` (four under endpoint:e1,
      one under endpoint:e2)
    - 3 parameters with ``shape = "free_text"``  (under endpoint:e2)
    - 1 ``test_attempt`` (vuln_type=injection) against parameter:p1
    - 3 leads with varied signal_strength ("low", "medium", "high")
    - ``has_param`` edges binding parameters to endpoints

The fixture exposes a minimal adapter with the same ``raw_query``
signature as :class:`src.greybox.graph.client.GraphClient` so the views
under test can treat it as a drop-in substitute.
"""
from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL


class _InMemoryGraph:
    """Adapter matching the ``raw_query`` surface of ``GraphClient``.

    Views accept anything with ``async raw_query(query, params)`` — see
    ``_GraphReader`` in ``src/greybox/graph/views.py``.
    """

    def __init__(self, db: AsyncSurreal) -> None:
        self.db = db

    async def raw_query(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        result = await self.db.query(query, params or {})
        return result or []


_SEED_DDL = """
CREATE endpoint:e1 SET method = 'GET', path = '/items', full_url = 'http://t/items',
    discovered_by = 'test', discovered_at = time::now(), rate_limited = false,
    requires_auth = true, status_codes_seen = [200];
CREATE endpoint:e2 SET method = 'POST', path = '/search', full_url = 'http://t/search',
    discovered_by = 'test', discovered_at = time::now(), rate_limited = false,
    requires_auth = true, status_codes_seen = [200];

-- 5 numeric_id params
CREATE parameter:p1 SET name = 'id', location = 'query', data_type = 'int',
    shape = 'numeric_id', discovered_by = 'test', discovered_at = time::now();
CREATE parameter:p2 SET name = 'user_id', location = 'query', data_type = 'int',
    shape = 'numeric_id', discovered_by = 'test', discovered_at = time::now();
CREATE parameter:p3 SET name = 'order_id', location = 'path', data_type = 'int',
    shape = 'numeric_id', discovered_by = 'test', discovered_at = time::now();
CREATE parameter:p4 SET name = 'page', location = 'query', data_type = 'int',
    shape = 'numeric_id', discovered_by = 'test', discovered_at = time::now();
CREATE parameter:p5 SET name = 'limit', location = 'query', data_type = 'int',
    shape = 'numeric_id', discovered_by = 'test', discovered_at = time::now();

-- 3 free_text params
CREATE parameter:p6 SET name = 'q', location = 'query', data_type = 'string',
    shape = 'free_text', discovered_by = 'test', discovered_at = time::now();
CREATE parameter:p7 SET name = 'comment', location = 'body', data_type = 'string',
    shape = 'free_text', discovered_by = 'test', discovered_at = time::now();
CREATE parameter:p8 SET name = 'title', location = 'body', data_type = 'string',
    shape = 'free_text', discovered_by = 'test', discovered_at = time::now();

RELATE endpoint:e1->has_param->parameter:p1;
RELATE endpoint:e1->has_param->parameter:p2;
RELATE endpoint:e1->has_param->parameter:p3;
RELATE endpoint:e1->has_param->parameter:p4;
RELATE endpoint:e2->has_param->parameter:p5;
RELATE endpoint:e2->has_param->parameter:p6;
RELATE endpoint:e2->has_param->parameter:p7;
RELATE endpoint:e2->has_param->parameter:p8;

-- One injection attempt already ran against p1
CREATE test_attempt:ta1 SET vuln_type = 'injection', technique = 'union_based',
    payload = "' OR 1=1--", payload_hash = 'sha256:deadbeef',
    verdict = 'conclusive_vulnerable',
    response_code = 200, duration_ms = 12, agent = 'injection-specialist',
    attempted_at = time::now();
RELATE test_attempt:ta1->tested_against->parameter:p1;

-- One reflection attempt already ran against p6 (free_text)
CREATE test_attempt:ta2 SET vuln_type = 'reflection', technique = 'reflected',
    payload = '<script>alert(1)</script>', payload_hash = 'sha256:feedface',
    verdict = 'conclusive_vulnerable', response_code = 200, duration_ms = 9,
    agent = 'reflection-specialist', attempted_at = time::now();
RELATE test_attempt:ta2->tested_against->parameter:p6;

-- Leads at different signal strengths
CREATE lead:l1 SET signal = 'timing_anomaly', hypothesis = 'Maybe blind SQLi',
    signal_strength = 'high', investigation_hints = [], status = 'open',
    investigation_attempts = 0, max_attempts = 3,
    discovered_by = 'test', discovered_at = time::now();
CREATE lead:l2 SET signal = 'verbose_error', hypothesis = 'Stack trace leaks path',
    signal_strength = 'medium', investigation_hints = [], status = 'open',
    investigation_attempts = 1, max_attempts = 3,
    discovered_by = 'test', discovered_at = time::now();
CREATE lead:l3 SET signal = 'header_mismatch', hypothesis = 'Possibly noisy',
    signal_strength = 'low', investigation_hints = [], status = 'open',
    investigation_attempts = 0, max_attempts = 3,
    discovered_by = 'test', discovered_at = time::now();
CREATE lead:l4 SET signal = 'resolved_issue', hypothesis = 'Already handled',
    signal_strength = 'high', investigation_hints = [], status = 'dismissed',
    investigation_attempts = 2, max_attempts = 3,
    discovered_by = 'test', discovered_at = time::now();
"""


@pytest_asyncio.fixture
async def graph_fixture():
    """In-memory SurrealDB seeded with the shape the view tests expect."""
    db = AsyncSurreal("mem://")
    async with db:
        await db.use("vigilo", "test_views")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        await db.query(_SEED_DDL)
        yield _InMemoryGraph(db)
