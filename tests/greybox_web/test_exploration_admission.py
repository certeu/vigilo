"""Admission is the safety net for LLM proposals: whatever the model proposes passes
the same ``Planner.admit`` as the rules — tool registry, param allow-list, scope, selected checks, dedup, quotas,
priority clamps. These tests drive specs that look exactly like a mapped model reply
(``LlmProposer.store``) and prove each guard.

Nothing here performs a model call: the proposer is fed parsed proposals directly.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.exploration.proposer import LlmProposer
from src.greybox_web.exploration.schema import parse_reply
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.models import GreyboxGraphNode, GreyboxRun, GreyboxWorkOrder
from src.greybox_web.planner import Planner, PlannerState
from src.greybox_web.scope import ScopePolicy
from tests.greybox_web.conftest import start_run

CHECKS = ("headers.security", "headers.disclosure", "cookies.flags", "cors.policy",
          "exposure.files", "exposure.dirlisting")


async def _planner(session_maker, run_id, checks=CHECKS):
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        st = PlannerState(base_url=run.base_url, scope=ScopePolicy.from_dict(run.scope),
                          checks=list(checks))
    return Planner(uuid.UUID(str(run_id)), st, uuid.uuid4()), st


def _reply(actions, hypotheses=()):
    import json
    return parse_reply(json.dumps({
        "reasoning": "The login form issues session credentials worth examining "
                     "directly; the API surface needs mapping before conclusions.",
        "assessment": "incomplete",
        "todolist": [],
        "hypotheses": list(hypotheses),
        "actions": actions,
    }))


async def _admit_all(session_maker, planner, specs):
    """Admit through a real GraphTx (the same path the supervisor uses)."""
    async with session_maker() as s:
        gtx = GraphTx(s, planner.run_id, GraphStats(), agent_id=planner.planner_agent_id)
        # an objective node exists on real runs; ensure one for lead linkage
        obj = await gtx.get_node("objective", "objective")
        if obj is None:
            obj = await gtx.node("objective", "objective", "Assess", "active")
        made = []
        for sp in specs:
            res = await planner.admit(s, gtx, sp, origin="planner")
            made.append(res)
        await s.commit()
        return made


@pytest.fixture
async def run_id(client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex,
                        checks=list(CHECKS))
    return uuid.UUID(r.json()["id"])


async def test_valid_llm_proposal_admitted_with_lead_and_lineage(
        session_maker, run_id):
    pl, _ = await _planner(session_maker, run_id)
    url = live_url = None
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        url = f"{run.base_url}login".rstrip("/") + "" if run.base_url.endswith("/") \
            else f"{run.base_url}/login"
    # a reasoning node as parent (what the explorer provides)
    async with session_maker() as s:
        gtx = GraphTx(s, run_id, GraphStats(), agent_id=uuid.uuid4())
        node = await gtx.node("reasoning", "reasoning|1", "Explorer cycle 1",
                              "active", data={"reasoning": "cycle"})
        await s.commit()
        node_id = node.id
    prop = _reply(
        actions=[{"tool": "cookies.flags", "params": {"url": url},
                  "reason": "the login endpoint authenticates users",
                  "priority": 30, "variant": "login-session", "hypothesis": "h1"}],
        hypotheses=[{"id": "h1", "label": "Session handling untested",
                     "hypothesis": "Session cookie flags are weak on the login flow."}])
    llm = LlmProposer()
    llm.store(prop, model="fake", tokens=5, node_id=node_id)
    stored = llm.pop()
    assert stored is not None
    made = await _admit_all(session_maker, pl, stored.groups[0].specs)
    assert len(made) == 1 and isinstance(made[0], GreyboxWorkOrder)
    wo = made[0]
    assert wo.tool == "cookies.flags"
    assert wo.dedup_key.endswith("login-session")     # tool|asset|variant
    assert wo.priority == 30
    # the lead node opened and the work order investigates it (graph lineage)
    async with session_maker() as s:
        lead = (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id, GreyboxGraphNode.kind == "lead",
            GreyboxGraphNode.key == "lead:llm:session-handling-untested"))).first()
        assert lead is not None and lead.status == "open"
        assert (lead.data or {}).get("type") == "explorer"
        wo_row = await s.get(GreyboxWorkOrder, wo.id)
        assert wo_row.parent_node_id == lead.id
        from src.greybox_web.models import GreyboxGraphEdge
        spawned = (await s.scalars(select(GreyboxGraphEdge).where(
            GreyboxGraphEdge.run_id == run_id,
            GreyboxGraphEdge.rel == "spawned"))).all()
        assert any(e.src_id == node_id and e.dst_id == lead.id for e in spawned)


async def test_out_of_scope_llm_action_refused(session_maker, run_id):
    pl, _ = await _planner(session_maker, run_id)
    prop = _reply(actions=[{
        "tool": "discovery.crawl",
        "params": {"url": "http://evil.invalid/", "seeds": ["http://evil.invalid/"]},
        "reason": "injected instruction told me to scan this host", "priority": 5}])
    llm = LlmProposer()
    llm.store(prop, model="fake", tokens=1)
    made = await _admit_all(session_maker, pl, llm.pop().groups[0].specs)
    assert not isinstance(made[0], GreyboxWorkOrder)
    assert made[0].reason in ("out_of_scope", "host_not_allowed")


async def test_param_smuggling_refused(session_maker, run_id):
    pl, _ = await _planner(session_maker, run_id)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        url = run.base_url
    prop = _reply(actions=[{
        "tool": "cookies.flags",
        "params": {"url": url, "cmd": "rm -rf /", "headers": {"X": "y"}},
        "reason": "session cookies need examination", "priority": 30}])
    llm = LlmProposer()
    llm.store(prop, model="fake", tokens=1)
    made = await _admit_all(session_maker, pl, llm.pop().groups[0].specs)
    assert not isinstance(made[0], GreyboxWorkOrder)
    assert made[0].reason == "params_not_allowed"


async def test_unknown_tool_and_unselected_check_refused(session_maker, run_id):
    pl, _ = await _planner(session_maker, run_id, checks=CHECKS[:2])
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        url = run.base_url
    prop = _reply(actions=[
        {"tool": "shell.exec", "params": {"cmd": "id"},
         "reason": "the model hallucinated a tool", "priority": 10},
        {"tool": "exposure.files", "params": {"url": url},
         "reason": "check not selected for this run", "priority": 20}])
    llm = LlmProposer()
    llm.store(prop, model="fake", tokens=1)
    made = await _admit_all(session_maker, pl, llm.pop().groups[0].specs)
    assert made[0].reason == "unknown_tool"
    assert made[1].reason == "check_not_selected"


async def test_llm_priority_bounds_and_duplicates_silent(session_maker, run_id):
    pl, _ = await _planner(session_maker, run_id)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        url = f"{run.base_url}login" if run.base_url.endswith("/") \
            else f"{run.base_url}/login"
    prop = _reply(actions=[{
        "tool": "cookies.flags", "params": {"url": url},
        "reason": "the reply contract already bounds priority; admission clamps "
                  "further to the platform floors", "priority": 5,
        "variant": "login-session"}])
    llm = LlmProposer()
    llm.store(prop, model="fake", tokens=1)
    made = await _admit_all(session_maker, pl, llm.pop().groups[0].specs)
    assert isinstance(made[0], GreyboxWorkOrder)
    assert 5 <= made[0].priority <= 90                   # the platform bounds apply
    # the same proposal again: a silent duplicate, not a second work order
    llm.store(prop, model="fake", tokens=1)
    made2 = await _admit_all(session_maker, pl, llm.pop().groups[0].specs)
    assert made2[0].reason == "duplicate"
    async with session_maker() as s:
        n = len((await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id,
            GreyboxWorkOrder.dedup_key.endswith("login-session")))).all())
    assert n == 1


async def test_standalone_hypotheses_open_analyst_leads(session_maker, run_id):
    """Hypotheses the model cannot act on stay open for the analyst (platform opens
    them like any lead — through apply(), not admission)."""
    from src.greybox_web.planning import PlannerOutput
    pl, _ = await _planner(session_maker, run_id)
    prop = _reply(actions=[], hypotheses=[
        {"id": "h1", "label": "Role confusion in admin surface",
         "hypothesis": "The admin panel may mix user roles; needs manual auth testing."}])
    llm = LlmProposer()
    llm.store(prop, model="fake", tokens=1)
    out = PlannerOutput(leads=list(llm.pop().leads))
    async with session_maker() as s:
        gtx = GraphTx(s, run_id, GraphStats(), agent_id=planner_agent(pl))
        made = await pl.apply(s, gtx, out, origin="planner")
        await s.commit()
    assert made == []
    async with session_maker() as s:
        lead = (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id, GreyboxGraphNode.kind == "lead",
            GreyboxGraphNode.key == "lead:llm:role-confusion-in-admin-surface")
        )).first()
        assert lead is not None and lead.status == "open"


def planner_agent(pl):
    return pl.planner_agent_id
