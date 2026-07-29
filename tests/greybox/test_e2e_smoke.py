"""End-to-end smoke test for the deterministic scheduler.

Seeds an in-memory SurrealDB with an "sample" shape (many leads,
no findings), then runs the scheduler in a tight retire-as-you-go loop.
Exercises the full read path (views → rules → core) without Temporal.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from surrealdb import AsyncSurreal

from src.greybox.graph.init_schema import INDEXES_DDL, TABLES_DDL
from src.greybox.scheduler.core import schedule
from src.greybox.scheduler.rules import SchedulerConfig


class _Graph:
    def __init__(self, db: AsyncSurreal) -> None:
        self.db = db

    async def raw_query(self, q, params=None):
        return await self.db.query(q, params or {}) or []


_SAMPLE_DDL = """
-- 2 identities — unlocks test_access_matrix
CREATE identity:anonymous SET role = 'anonymous', discovered_by = 'seed',
    discovered_at = time::now();
CREATE identity:user SET role = 'user', discovered_by = 'seed',
    discovered_at = time::now();

-- 8 endpoints
CREATE endpoint:e1 SET method='GET', path='/api/users', full_url='http://t/api/users',
    discovered_by='seed', discovered_at=time::now(), rate_limited=false,
    requires_auth=false, status_codes_seen=[200];
CREATE endpoint:e2 SET method='POST', path='/api/login', full_url='http://t/api/login',
    discovered_by='seed', discovered_at=time::now(), rate_limited=false,
    requires_auth=false, status_codes_seen=[200];
CREATE endpoint:e3 SET method='GET', path='/api/items', full_url='http://t/api/items',
    discovered_by='seed', discovered_at=time::now(), rate_limited=false,
    requires_auth=false, status_codes_seen=[200];
CREATE endpoint:e4 SET method='POST', path='/api/comments', full_url='http://t/api/comments',
    discovered_by='seed', discovered_at=time::now(), rate_limited=false,
    requires_auth=false, status_codes_seen=[201];
CREATE endpoint:e5 SET method='GET', path='/api/search', full_url='http://t/api/search',
    discovered_by='seed', discovered_at=time::now(), rate_limited=false,
    requires_auth=false, status_codes_seen=[200];

-- parameters with mixed shapes
CREATE parameter:p_id SET name='id', location='query', data_type='int',
    shape='numeric_id', discovered_by='seed', discovered_at=time::now();
CREATE parameter:p_q SET name='q', location='query', data_type='string',
    shape='free_text', discovered_by='seed', discovered_at=time::now();
CREATE parameter:p_url SET name='url', location='body', data_type='string',
    shape='url', discovered_by='seed', discovered_at=time::now();
CREATE parameter:p_uuid SET name='token', location='query', data_type='string',
    shape='uuid', discovered_by='seed', discovered_at=time::now();
CREATE parameter:p_comment SET name='comment', location='body', data_type='string',
    shape='free_text', discovered_by='seed', discovered_at=time::now();

RELATE endpoint:e1->has_param->parameter:p_id;
RELATE endpoint:e3->has_param->parameter:p_id;
RELATE endpoint:e5->has_param->parameter:p_q;
RELATE endpoint:e4->has_param->parameter:p_comment;
RELATE endpoint:e2->has_param->parameter:p_url;
RELATE endpoint:e3->has_param->parameter:p_uuid;

-- 14 open leads at medium+ strength — triggers INVESTIGATE_LEAD verbs
CREATE lead:l01 SET signal='timing_anomaly', hypothesis='blind SQLi on id',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l02 SET signal='reflection', hypothesis='XSS in q',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l03 SET signal='response_code_anomaly', hypothesis='auth bypass',
    signal_strength='medium', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l04 SET signal='error_leak', hypothesis='stack trace on malformed JSON',
    signal_strength='medium', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l05 SET signal='verbose_error', hypothesis='NoSQL operator injection',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l06 SET signal='timing_anomaly', hypothesis='blind NoSQL on search',
    signal_strength='medium', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l07 SET signal='reflection', hypothesis='XSS in comment',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l08 SET signal='header_mismatch', hypothesis='cookie scope leak',
    signal_strength='medium', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l09 SET signal='response_size_drift', hypothesis='authz leak via enumeration',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l10 SET signal='timing_anomaly', hypothesis='SSRF via url param',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l11 SET signal='reflection', hypothesis='HTML-encoded XSS bypass',
    signal_strength='medium', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l12 SET signal='response_code_anomaly', hypothesis='IDOR via uuid',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l13 SET signal='error_leak', hypothesis='XXE on xml payload',
    signal_strength='medium', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
CREATE lead:l14 SET signal='timing_anomaly', hypothesis='command injection',
    signal_strength='high', investigation_hints=[], status='open',
    investigation_attempts=0, max_attempts=3,
    discovered_by='seed', discovered_at=time::now();
"""


@pytest_asyncio.fixture
async def sample_graph():
    db = AsyncSurreal("mem://")
    async with db:
        await db.use("vigilo", "test_e2e_smoke")
        await db.query(TABLES_DDL)
        await db.query(INDEXES_DDL)
        await db.query(_SAMPLE_DDL)
        yield _Graph(db)


@pytest.mark.asyncio
async def test_scheduler_dispatches_leads_on_first_ticks(sample_graph):
    config = SchedulerConfig()
    result = await schedule(sample_graph, config, active_claims=[], tick_number=1)
    verbs = result.verbs
    kinds = [v.kind for v in verbs]
    assert "INVESTIGATE_LEAD" in kinds, f"expected INVESTIGATE_LEAD in first tick, got {kinds}"
    # high-strength leads sort to priority=high and appear before medium-priority verbs
    assert verbs[0].kind == "INVESTIGATE_LEAD"
    assert verbs[0].priority == "high"


@pytest.mark.asyncio
async def test_loop_terminates_with_done_after_leads_retire(sample_graph):
    config = SchedulerConfig()
    seen_kinds: set[str] = set()

    for tick in range(1, 11):
        result = await schedule(sample_graph, config, active_claims=[], tick_number=tick)
        verbs = result.verbs
        seen_kinds.update(v.kind for v in verbs)

        if any(v.kind == "DONE" for v in verbs):
            break

        # Retire every dispatched lead by maxing its investigation_attempts.
        for verb in verbs:
            if verb.kind == "INVESTIGATE_LEAD":
                await sample_graph.db.query(
                    "UPDATE type::thing($id) SET investigation_attempts = 3",
                    {"id": verb.lead_id},
                )

        # Retire every probed parameter by creating a synthetic test_attempt —
        # the untested_parameters view excludes parameters that already have one.
        attempt_seq = 0
        for verb in verbs:
            if verb.kind != "PROBE_PARAMETERS":
                continue
            for pid in verb.param_ids:
                attempt_seq += 1
                ta_id = f"test_attempt:stub_{tick}_{attempt_seq}"
                assert pid.startswith("parameter:"), pid
                await sample_graph.db.query(
                    f"""
                    CREATE {ta_id} SET vuln_type = $vt, technique = 'stub',
                        payload = 'stub', payload_hash = 'sha256:stub',
                        verdict = 'conclusive_clean', response_code = 200,
                        duration_ms = 1,
                        agent = 'stub', attempted_at = time::now();
                    RELATE {ta_id}->tested_against->{pid};
                    """,
                    {"vt": verb.vuln_type},
                )
    else:
        pytest.fail(f"scheduler did not emit DONE within 10 ticks; seen kinds: {seen_kinds}")

    assert "INVESTIGATE_LEAD" in seen_kinds
    assert verbs[0].kind == "DONE"


@pytest.mark.asyncio
async def test_budget_exhaustion_short_circuits(sample_graph):
    # Below the floor (default 0.03) → exhausted mode → DONE short-circuit.
    result = await schedule(
        sample_graph,
        SchedulerConfig(),
        active_claims=[],
        budget_remaining_pct=0.01,
        tick_number=1,
    )
    verbs = result.verbs
    assert len(verbs) == 1
    assert verbs[0].kind == "DONE"
    assert verbs[0].reason == "budget_exhausted"
