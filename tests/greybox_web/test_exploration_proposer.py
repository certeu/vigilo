"""Unit tests for the LLM proposer seam (proposer.py): mapping, accumulation,
pop semantics and the automatic verification of candidate findings."""
from __future__ import annotations

import uuid

from src.greybox_web.exploration.proposer import LlmProposer
from src.greybox_web.exploration.schema import Proposal, parse_reply
from src.greybox_web.planning import PlannerInput


def _proposal(actions=1, label="Broken API authorization") -> Proposal:
    reply = {
        "reasoning": "The application exposes an API and a login form; both deserve "
                     "targeted, evidence-driven work before the assessment is done.",
        "assessment": "incomplete",
        "todolist": [{"step": "Examine the API authorization boundary",
                      "status": "in_progress"}],
        "hypotheses": [
            {"id": "h1", "label": label,
             "hypothesis": "Object-level authorization between roles is missing.",
             "signals": {"surface": "api"}}],
        "actions": [
            {"tool": "discovery.crawl", "params": {"url": "http://t/",
                                                   "seeds": ["http://t/api"]},
             "reason": "map the API surface so boundaries become observable",
             "priority": 25, "variant": "api-surface", "hypothesis": "h1"}
        ][:actions] + [
            {"tool": "exposure.dirlisting", "params": {"url": "http://t/files"},
             "reason": "stored user content may be listable", "priority": 30,
             "variant": "stored-content"}],
    }
    return parse_reply(__import__("json").dumps(reply))


def test_store_maps_specs_and_leads_with_parent():
    p = LlmProposer()
    node = uuid.uuid4()
    p.store(_proposal(), model="fake-explorer", tokens=42, node_id=node)
    st = p.stored
    assert st is not None and st.assessment == "incomplete"
    assert len(st.groups) == 1 and len(st.groups[0].specs) == 2
    crawl, listing = st.groups[0].specs
    assert crawl.tool == "discovery.crawl" and crawl.lead is not None
    assert crawl.lead.key == "lead:llm:broken-api-authorization"
    assert crawl.lead.parent_node_id == node and crawl.parent_node_id == node
    # the action without a hypothesis carries no lead; the hypothesis stays a lead
    assert listing.lead is None
    assert len(st.leads) == 0            # h1 was acted on: no standalone lead


def test_store_hypothesis_without_action_becomes_analyst_lead():
    p = LlmProposer()
    prop = _proposal(actions=0)
    prop = prop.model_copy(update={"actions": prop.actions[:0]})
    p.store(prop, model="m", tokens=1)
    st = p.stored
    assert st.groups == ()
    assert len(st.leads) == 1 and st.leads[0].type_id == "explorer"


def test_pending_accumulates_and_pops_once():
    p = LlmProposer()
    p.store(_proposal(label="Hypothesis A"), model="m", tokens=5)
    p.store(_proposal(label="Hypothesis B"), model="m", tokens=7)
    st = p.stored
    assert len(st.groups) == 2 and st.tokens == 12
    popped = p.pop()
    assert popped is not None and len(popped.groups) == 2
    assert p.stored is None and p.pop() is None
    assert p.consumed_cycles == 1


async def test_observe_emits_then_goes_quiet():
    p = LlmProposer()
    inp = PlannerInput(cycle=1, objective_node_id=uuid.uuid4())
    out = await p.start(inp)
    assert out.groups == [] and out.leads == []
    p.store(_proposal(), model="m", tokens=3)
    out = await p.observe(inp)
    assert len(out.groups) == 1 and out.rationale.startswith("The application")
    out2 = await p.observe(inp)
    assert out2.groups == [] and out2.leads == []


async def test_observe_adds_verification_for_candidate_findings():
    """The one automatic rule: a candidate finding gets its verify.* work order,
    next to whatever the model proposed (both go through admission)."""
    from src.greybox_web.planning import NewFinding
    p = LlmProposer()
    fid = uuid.uuid4()
    finding = NewFinding(id=fid, check_id="headers.security",
                         dedup_key="headers.security|http://t/|csp",
                         verify={"url": "http://t/", "header": "content-security-policy"})
    p.store(_proposal(), model="m", tokens=2)
    out = await p.observe(PlannerInput(cycle=1, objective_node_id=uuid.uuid4(),
                                       findings=(finding,)))
    tools = [s.tool for g in out.groups for s in g.specs]
    assert tools[0] == "verify.headers.security"
    assert "discovery.crawl" in tools
    verify = out.groups[0].specs[0]
    assert verify.params["finding_id"] == str(fid) and verify.priority == 10
    # no model proposals cached: still verified
    out = await p.observe(PlannerInput(cycle=2, objective_node_id=uuid.uuid4(),
                                       findings=(finding,)))
    assert [s.tool for g in out.groups for s in g.specs] == ["verify.headers.security"]


def test_no_rule_proposer_remains():
    import src.greybox_web.exploration.proposer as proposer
    import src.greybox_web.planner as planner
    assert not hasattr(proposer, "CompositeProposer")
    assert not hasattr(planner, "RulePlanner")


def test_trigger_keeps_scalar_attributes_as_plain_values():
    from src.greybox_web.planning import trigger
    t = trigger("agent", assessment="incomplete", model="gpt-5-5",
                node_ids=["b", "a", None])
    assert t == {"kind": "agent", "assessment": "incomplete", "model": "gpt-5-5",
                 "node_ids": ["a", "b"]}


def test_dispatch_reason_is_one_complete_sentence():
    from src.greybox_web.exploration.proposer import brief
    long = ("This is the first cycle and no data exists yet. " + "More words. " * 80)
    assert brief(long) == "This is the first cycle and no data exists yet."
    runon = "word " * 100
    out = brief(runon, 60)
    assert len(out) <= 61 and out.endswith("…") and not out.endswith(" …")
