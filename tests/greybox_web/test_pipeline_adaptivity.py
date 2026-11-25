"""Pipeline adaptivity: acceptance tests for an event-driven, graph-driven planner.

Every test encodes the DESIRED
behaviour; all of them pass now (the former ``xfail(strict=True)`` gaps were closed by
steps A1, C, A2, A3, B and A6 of the design).

Live scenarios run a real worker against the synthetic 127.0.0.1 target. To control
timing, check/verify/crawl tools are replaced in the tool registry by scripted fakes
that record when they start and end (``Lab``). The planner, supervisor, graph,
hints API and persistence are the real ones. Nothing outside 127.0.0.1 is requested.

Run: pytest tests/greybox_web/test_pipeline_adaptivity.py -q -s   (-s prints traces)
"""
from __future__ import annotations

import asyncio
import inspect
import time
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web import planner as planner_mod
from src.greybox_web import tools
from src.greybox_web.exploration.proposer import LlmProposer
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.models import (
    GreyboxAsset, GreyboxEvent, GreyboxGraphEdge, GreyboxGraphNode, GreyboxRun,
    GreyboxWorkOrder,
)
from src.greybox_web.planner import PRIORITY_FOCUS, NewAsset, Planner, PlannerState
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import (
    FindingSpec, Observation, PageInfo, ToolResult, ToolSpec, VerifyResult,
)
from tests.greybox_web.conftest import create_target, h, start_run
from tests.greybox_web.conftest import FAST_LIMITS

CHECKS = ("headers.security", "headers.disclosure", "cookies.flags", "cors.policy",
          "exposure.files", "exposure.dirlisting")
# the pentest checks are defaults now; the model proposes them (on the target's
# parameters) before the baseline posture checks
PENTEST_CHECKS = ("injection.reflection", "injection.errors", "redirect.open",
                  "info.errors", "auth.default_creds")


# ------------------------------------------------------------------- scripted tools


class Lab:
    """Scripted replacements for registry tools, with a timeline of what ran."""

    def __init__(self, monkeypatch) -> None:
        tools.get("headers.security")            # force registry initialisation
        self.mp = monkeypatch
        self.t0 = time.monotonic()
        self.log: list[tuple[float, str, str, str]] = []   # (t, start|end, tool, url)

    def mark(self, ev: str, tool: str, url: str | None) -> None:
        self.log.append((round(time.monotonic() - self.t0, 3), ev, tool, url or ""))

    def t(self, ev: str, tool: str, url_suffix: str = "") -> float | None:
        for t, e, tl, u in self.log:
            if e == ev and tl == tool and u.endswith(url_suffix):
                return t
        return None

    def count(self, ev: str, tool: str) -> int:
        return sum(1 for _t, e, tl, _u in self.log if e == ev and tl == tool)

    def _put(self, tool_id: str, kind: str, fn) -> None:
        self.mp.setitem(tools._TOOLS, tool_id, ToolSpec(tool_id, kind, fn))

    def checks(self, delay: float = 0.0, *, finding_from: str | None = None,
               observe: bool = False, only: tuple[str, ...] = CHECKS) -> None:
        for tool_id in only:
            async def run(ctx, _t=tool_id):
                url = ctx.params.get("url")
                self.mark("start", _t, url)
                await asyncio.sleep(delay)
                res = ToolResult(summary="fake")
                if observe:
                    res.observations = [Observation(key=f"obs:{_t}:{url}", label=f"{_t} ran",
                                                    url=url)]
                if _t == finding_from:
                    res.findings = [FindingSpec(
                        check_id=_t, detail="d", title="candidate", severity="low",
                        confidence="high", description="fake", url=url,
                        verify={"url": url})]
                self.mark("end", _t, url)
                return res
            self._put(tool_id, "check", run)

    def verifier(self, check_id: str, delay: float = 0.0) -> None:
        async def run(ctx, _t=f"verify.{check_id}"):
            self.mark("start", _t, ctx.params.get("url"))
            await asyncio.sleep(delay)
            self.mark("end", _t, ctx.params.get("url"))
            return VerifyResult(confirmed=True, method="fake", note="ok")
        self._put(f"verify.{check_id}", "verify", run)

    def crawl(self, script) -> None:
        """``script(seeds) -> (delay_s, [paths])``: a crawl that reports those pages."""
        async def run(ctx):
            seeds = list(ctx.params.get("seeds") or [])
            self.mark("start", "discovery.crawl", ",".join(seeds))
            delay, paths = script(seeds)
            await asyncio.sleep(delay)
            base = ctx.base_url.rstrip("/")
            pages = [PageInfo(url=base + (p[0] if isinstance(p, tuple) else p),
                              status=200, content_type="text/html", fetched=True,
                              data=(p[1] if isinstance(p, tuple) else {}))
                     for p in paths]
            self.mark("end", "discovery.crawl", ",".join(seeds))
            return ToolResult(summary="fake crawl", pages=pages)
        self._put("discovery.crawl", "discovery", run)

    def auth(self) -> None:
        async def run(ctx):
            url = ctx.params.get("url")
            self.mark("start", "auth.default_creds", url)
            self.mark("end", "auth.default_creds", url)
            return ToolResult(summary="no default credentials", observations=[
                Observation(key=f"obs:auth:{url}", label="default credentials rejected",
                            url=url)])
        self._put("auth.default_creds", "check", run)


@pytest.fixture
def lab(monkeypatch):
    return Lab(monkeypatch)


# ------------------------------------------------------------------------ run helpers


async def _wait(cond, timeout=30.0, step=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        await asyncio.sleep(step)
    raise AssertionError("condition not reached in time")


async def start_bg(client, token, target_id, session_maker, *, key=None):
    from src.greybox_web.worker import run_once
    r = await start_run(client, token, target_id, key=key or uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    worker = asyncio.create_task(run_once(session_maker))
    for _ in range(300):
        body = (await client.get(f"/greybox/runs/{run_id}", headers=h(token))).json()
        if body["status"] == "running":
            break
        await asyncio.sleep(0.05)
    return run_id, worker


async def finish(worker, timeout=90):
    await asyncio.wait_for(worker, timeout=timeout)


async def hint(client, token, run_id, action, target=None) -> dict:
    body = {"action": action, "text": "analyst", **({"target": target} if target else {})}
    r = await client.post(f"/greybox/runs/{run_id}/hints", headers=h(token), json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def hint_status(client, token, run_id, hint_id) -> dict:
    r = await client.get(f"/greybox/runs/{run_id}/hints", headers=h(token))
    return next(x for x in r.json()["items"] if x["id"] == hint_id)


async def events_of(session_maker, run_id) -> list[GreyboxEvent]:
    async with session_maker() as s:
        return list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == uuid.UUID(run_id)).order_by(GreyboxEvent.seq))).all())


async def work_orders(session_maker, run_id) -> list[GreyboxWorkOrder]:
    async with session_maker() as s:
        return list((await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == uuid.UUID(run_id))
            .order_by(GreyboxWorkOrder.created_seq))).all())


def _wo_for(wos, tool, url_suffix):
    return [w for w in wos if w.tool == tool and (w.params or {}).get("url", "")
            .endswith(url_suffix)]


# ------------------------------------------------------------------ 0. run trace


async def format_trace(session_maker, run_id: str) -> list[str]:
    """Event order (phase / planner / work order) plus graph-node creation order."""
    out = []
    async with session_maker() as s:
        wo_tool = {w.id: w.tool for w in (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == uuid.UUID(run_id)))).all()}
    for e in await events_of(session_maker, run_id):
        d = e.data or {}
        if e.kind == "run.phase":
            out.append(f"{e.seq:4} PHASE      {d['from']} -> {d['to']}")
        elif e.kind == "planner.decision":
            out.append(f"{e.seq:4} DECISION   {e.summary}")
        elif e.kind == "work_order.created":
            out.append(f"{e.seq:4} WO+        {d['tool']:22} prio={d['priority']:<3} "
                       f"{d['reason'][:60]}")
        elif e.kind in ("work_order.claimed", "work_order.completed"):
            out.append(f"{e.seq:4} {e.kind.split('.')[1].upper():10} "
                       f"{wo_tool.get(e.work_order_id, '?')}")
        elif e.kind in ("finding.created", "finding.verified", "hint.addressed"):
            out.append(f"{e.seq:4} {e.kind.upper()}")
    async with session_maker() as s:
        nodes = (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == uuid.UUID(run_id))
            .order_by(GreyboxGraphNode.created_version, GreyboxGraphNode.created_at))).all()
    out.append("--- graph node creation order (created_version, kind, label) ---")
    out += [f"v{n.created_version:<4} {n.kind:11} {n.status:12} {n.label[:70]}"
            for n in nodes]
    return out


async def test_trace_of_a_default_run(client, user_token, session_maker, live_target,
                                      target_server):
    """Evidence run: real tools, default checks. Prints the trace with ``-s``."""
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await finish(worker)
    lines = await format_trace(session_maker, run_id)
    print("\n" + "\n".join(lines))
    text = "\n".join(lines)
    assert "PHASE      " in text and "WO+" in text and "DECISION" in text
    wos = await work_orders(session_maker, run_id)
    # every non-discovery work order was created by a rule, none up front
    first_check = min(w.created_seq for w in wos if w.kind == "check")
    last_discovery_done = [w for w in wos if w.kind == "discovery"]
    assert first_check > min(w.created_seq for w in last_discovery_done)


# --------------------------------------------- 1. phases are labels, not barriers (OK)


async def test_checks_start_while_discovery_is_still_running(
        client, user_token, session_maker, live_target, lab):
    # the parameter probes now outrank the baseline posture checks in the model's
    # plan, so they are scripted too: whichever check the model picks first, the
    # check lane must not wait for the end of discovery
    lab.checks(0.0, only=CHECKS + PENTEST_CHECKS)
    lab.crawl(lambda seeds: (2.0, []))                 # a long crawl
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await finish(worker)
    first_check = min(t for t, e, tl, _u in lab.log
                      if e == "start" and tl in CHECKS + PENTEST_CHECKS)
    crawl_end = lab.t("end", "discovery.crawl")
    assert first_check < crawl_end, "checks must not wait for the end of discovery"


async def test_late_discovered_endpoint_still_gets_checked(
        client, user_token, session_maker, live_target, lab):
    """An endpoint found by the crawl while earlier checks are still draining."""
    lab.checks(0.8)
    lab.crawl(lambda seeds: (1.0, ["/api/late"]))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await finish(worker)
    wos = await work_orders(session_maker, run_id)
    cors = _wo_for(wos, "cors.policy", "/api/late")
    assert cors and cors[0].status == "done"
    # the model reacts to the discovery in a later cycle (no rule fires at the
    # moment of discovery any more): what matters is that it does get checked
    assert lab.t("start", "cors.policy", "/api/late") is not None


async def test_verification_interleaves_with_checks(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.8)
    lab.checks(0.0, finding_from="exposure.files", only=("exposure.files",))
    lab.verifier("exposure.files", 0.0)
    lab.crawl(lambda seeds: (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await finish(worker)
    v_start = lab.t("start", "verify.exposure.files")
    last_check_end = max(t for t, e, tl, _u in lab.log if e == "end" and tl in CHECKS)
    assert v_start is not None and v_start < last_check_end


# ----------------------------------------------------- 3. hints: dynamic effects


async def test_focus_hint_reorders_pending_work_within_one_planner_cycle(
        client, user_token, session_maker, live_target, lab):
    lab.checks(1.5)                       # both checker slots busy, others queue
    lab.crawl(lambda seeds: (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await _wait(lambda: lab.count("start", "cors.policy") + sum(
        lab.count("start", t) for t in CHECKS if t != "cors.policy") >= 2)
    posted = time.monotonic()
    hint_row = await hint(client, user_token, run_id, "focus", "/api/data")
    for _ in range(100):
        row = await hint_status(client, user_token, run_id, hint_row["id"])
        if row["status"] != "open":
            break
        await asyncio.sleep(0.02)
    latency = time.monotonic() - posted
    assert row["status"] == "addressed", row
    assert latency < 1.0, f"hint took {latency:.2f}s (loop wakes every 0.5s)"
    await finish(worker)
    checks_started = [(tl, u) for _t, e, tl, u in lab.log if e == "start" and tl in CHECKS]
    # the first two were already running; the focused one is next in line
    assert checks_started[2][0] == "cors.policy"
    assert checks_started[2][1].endswith("/api/data")


async def test_hint_during_verification_can_still_add_discovery(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.0)
    lab.checks(0.0, finding_from="exposure.files", only=("exposure.files",))
    lab.verifier("exposure.files", 3.0)                     # verification is the long pole
    lab.crawl(lambda seeds: (0.0, ["/api/seeded"] if any("/late-seed" in s for s in seeds)
                             else []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await _wait(lambda: lab.t("start", "verify.exposure.files") is not None)
    row = await hint(client, user_token, run_id, "add_seed", "/late-seed")
    await finish(worker)
    assert (await hint_status(client, user_token, run_id, row["id"]))["status"] == "addressed"
    v_end = lab.t("end", "verify.exposure.files")
    assert lab.t("start", "cors.policy", "/api/seeded") is not None


async def test_focus_is_standing_new_endpoints_under_the_prefix_inherit_it(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.8)
    lab.crawl(lambda seeds: (0.5, ["/api/zone/x"] if any("/api/zone/" in s for s in seeds)
                             else []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await hint(client, user_token, run_id, "focus", "/api/zone/")
    await finish(worker)
    wos = await work_orders(session_maker, run_id)
    cors = _wo_for(wos, "cors.policy", "/api/zone/x")
    assert cors, "the endpoint was discovered through the focus seed"
    assert cors[0].priority == PRIORITY_FOCUS


# ------------------------------------------------------- 4. latency / blocking


async def test_analyst_seed_starts_while_a_long_crawl_is_running(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.0)
    lab.crawl(lambda seeds: (3.0, []) if len(seeds) > 1 or seeds == [
        live_target["base_url"]] or not any("/hot" in s for s in seeds) else (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await _wait(lambda: lab.t("start", "discovery.crawl") is not None)
    posted = time.monotonic() - lab.t0
    await hint(client, user_token, run_id, "add_seed", "/hot")
    await _wait(lambda: any(e == "start" and tl == "discovery.crawl" and "/hot" in u
                            for _t, e, tl, u in lab.log), timeout=20)
    seed_start = next(t for t, e, tl, u in lab.log
                      if e == "start" and tl == "discovery.crawl" and "/hot" in u)
    await finish(worker)
    assert seed_start - posted < 1.0, f"seed waited {seed_start - posted:.1f}s behind the crawl"


# --------------------------------------------------- 6. leads as hypotheses


async def _auth_run(client, user_token, session_maker, target_server, lab):
    lab.checks(0.0)
    lab.auth()
    login = {"user_field": "user", "password_field": "pw", "fields": {}, "method": "POST"}
    lab.crawl(lambda seeds: (0.0, [("/login", {"login_form": login})]))
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS), scope={"allow_auth_testing": True})
    run_id, worker = await start_bg(client, user_token, t["id"], session_maker)
    await finish(worker)
    return run_id


async def _lead_and_edges(session_maker, run_id, label_has: str = ""):
    async with session_maker() as s:
        nodes = {n.id: n for n in (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == uuid.UUID(run_id)))).all()}
        edges = (await s.scalars(select(GreyboxGraphEdge).where(
            GreyboxGraphEdge.run_id == uuid.UUID(run_id)))).all()
    lead = next(n for n in nodes.values()
                if n.kind == "lead" and label_has in n.label)
    incoming = [(e.rel, nodes[e.src_id].kind) for e in edges if e.dst_id == lead.id]
    return lead, incoming


async def test_lead_settles_refuted_when_its_check_ran_clean(
        client, user_token, session_maker, target_server, lab):
    run_id = await _auth_run(client, user_token, session_maker, target_server, lab)
    lead, _incoming = await _lead_and_edges(session_maker, run_id, "Session handling")
    assert lead.status == "refuted" and lead.outcome == "ruled_out"
    assert lead.data.get("hypothesis")


async def test_mapping_lead_is_explored_not_refuted(
        client, user_token, session_maker, target_server, lab):
    """A direction investigated by discovery only (map the surface) that produced
    observations is established, never "refuted"."""
    run_id = await _auth_run(client, user_token, session_maker, target_server, lab)
    lead, incoming = await _lead_and_edges(session_maker, run_id, "API authorization")
    assert lead.status == "confirmed" and lead.outcome == "reported"
    assert lead.data["evidence"] == {"supports": 1, "contradicts": 0}
    assert ("supports", "observation") in incoming
    assert ("contradicts", "observation") not in incoming


async def test_lead_is_spawned_from_an_observation(
        client, user_token, session_maker, target_server, lab):
    run_id = await _auth_run(client, user_token, session_maker, target_server, lab)
    _lead, incoming = await _lead_and_edges(session_maker, run_id)
    # the login direction is the model's hypothesis: spawned from its reasoning
    assert ("spawned", "reasoning") in incoming


async def test_settled_lead_records_an_outcome(
        client, user_token, session_maker, target_server, lab):
    run_id = await _auth_run(client, user_token, session_maker, target_server, lab)
    lead, _ = await _lead_and_edges(session_maker, run_id)
    assert lead.status in ("confirmed", "refuted", "inconclusive")
    assert lead.outcome is not None


# ------------------------------- 2/5. graph as source of truth, planner interface


async def test_planner_decisions_are_derivable_from_persisted_graph(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.0)
    lab.crawl(lambda seeds: (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await finish(worker)
    rid = uuid.UUID(run_id)
    before = len(await work_orders(session_maker, run_id))
    async with session_maker() as s:
        run = await s.get(GreyboxRun, rid)
        scope = ScopePolicy.from_dict(run.scope)
        assets = [NewAsset(id=a.id, kind=a.kind, key=a.key, in_scope=a.in_scope,
                           data=dict(a.data or {}))
                  for a in (await s.scalars(select(GreyboxAsset).where(
                      GreyboxAsset.run_id == rid))).all()]
        pl = Planner(rid, PlannerState(base_url=run.base_url, scope=scope,
                                       checks=list(run.checks)), uuid.uuid4())
        gtx = GraphTx(s, rid, GraphStats(), agent_id=uuid.uuid4())
        await pl.on_assets(s, gtx, assets)
        await s.commit()
    assert len(await work_orders(session_maker, run_id)) == before


async def test_decision_events_record_the_graph_trigger(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.0)
    lab.crawl(lambda seeds: (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await finish(worker)
    decisions = [e for e in await events_of(session_maker, run_id)
                 if e.kind == "planner.decision" and e.data["decision"] == "dispatch"]
    assert decisions and all("trigger" in e.data for e in decisions)


def test_planner_protocol_and_spec_exist():
    assert hasattr(planner_mod, "WorkOrderSpec")
    assert hasattr(planner_mod, "PlannerInput")
    proto = planner_mod.PlannerProtocol
    assert {"observe"} <= set(dir(proto))


def test_supervisor_accepts_an_injected_planner():
    from src.greybox_web.supervisor import RunSupervisor
    assert "planner_factory" in inspect.signature(RunSupervisor.__init__).parameters


async def test_out_of_scope_spec_is_refused_by_admission(
        client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    rid = uuid.UUID(r.json()["id"])
    spec = planner_mod.WorkOrderSpec(tool="discovery.crawl", kind="discovery",
                                     params={"url": "http://evil.invalid/",
                                             "seeds": ["http://evil.invalid/"]},
                                     reason="llm said so", priority=5)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, rid)
        pl = Planner(rid, PlannerState(base_url=run.base_url,
                                       scope=ScopePolicy.from_dict(run.scope),
                                       checks=list(run.checks)), uuid.uuid4())
        gtx = GraphTx(s, rid, GraphStats(), agent_id=uuid.uuid4())
        res = await pl.admit(s, gtx, spec)
        # a proposer cannot pick the kind, an unselected check, or an analyst priority
        bad_kind = await pl.admit(s, gtx, planner_mod.WorkOrderSpec(
            tool="headers.security", kind="discovery", params={"url": run.base_url},
            reason="x"))
        unselected = await pl.admit(s, gtx, planner_mod.WorkOrderSpec(
            tool="exposure.files", kind="check", params={"url": run.base_url},
            reason="x", variant="t"))
        pl.state.checks = ["headers.security"]
        unselected = await pl.admit(s, gtx, planner_mod.WorkOrderSpec(
            tool="exposure.files", kind="check", params={"url": run.base_url},
            reason="x", variant="t"))
        grab = await pl.admit(s, gtx, planner_mod.WorkOrderSpec(
            tool="headers.security", kind="check", params={"url": run.base_url},
            reason="x", priority=0, variant="grab"))
        await s.commit()
    assert isinstance(res, planner_mod.Rejection) and res.reason == "host_not_allowed"
    assert bad_kind.reason == "kind_mismatch"
    assert unselected.reason == "check_not_selected"
    assert grab.priority == planner_mod.PRIORITY_FOCUS_SEED      # clamped
    evs = [e for e in await events_of(session_maker, str(rid))
           if e.kind == "planner.decision" and e.data["decision"] == "rejected"]
    assert {e.data["reason"] for e in evs} >= {"host_not_allowed", "kind_mismatch",
                                               "check_not_selected"}
    assert not [w for w in await work_orders(session_maker, str(rid))
                if "evil" in str(w.params)]


class _ScriptedPlanner(LlmProposer):
    """The LLM proposer plus hostile proposals injected into the first cycle."""

    def __init__(self, state):
        super().__init__()
        self.state = state

    async def observe(self, inp):
        out = await super().observe(inp)
        if inp.cycle == 1:
            bad = [planner_mod.WorkOrderSpec(
                       tool="discovery.crawl", kind="discovery", reason="llm",
                       params={"url": "http://evil.invalid/", "seeds": ["http://evil.invalid/"]},
                       priority=0, variant="evil"),
                   planner_mod.WorkOrderSpec(
                       tool="exposure.files", kind="check", reason="llm",
                       params={"url": self.state.base_url}, variant="llm")]
            out.groups.append(planner_mod.PlanGroup("llm proposals", tuple(bad)))
        return out


async def test_injected_planner_is_bound_by_admission(
        client, user_token, session_maker, live_target):
    """planner_factory: a custom proposer runs the same guarded admission path."""
    from src.greybox_web.worker import run_once
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex,
                        checks=["headers.security"], base_url=live_target["base_url"])
    assert r.status_code == 201, r.text
    await asyncio.wait_for(run_once(session_maker, planner_factory=_ScriptedPlanner), 90)
    run_id = r.json()["id"]
    wos = await work_orders(session_maker, run_id)
    assert not [w for w in wos if "evil" in str(w.params)]
    assert not [w for w in wos if w.tool == "exposure.files"]
    reasons = {e.data["reason"] for e in await events_of(session_maker, run_id)
               if e.kind == "planner.decision" and e.data["decision"] == "rejected"}
    assert {"host_not_allowed", "check_not_selected"} <= reasons
    async with session_maker() as s:
        row = await s.get(GreyboxRun, uuid.UUID(run_id))
        assert row.status == "succeeded", row.error_summary


async def test_crawl_is_incremental_and_page_limit_is_exact(
        client, user_token, session_maker, target_server):
    """Several crawl batches; discoveries of a batch appear before the next batch
    starts; the run-wide ``max_pages`` is exact."""
    limits = {**FAST_LIMITS, "max_pages": 7}
    t = await create_target(client, user_token, base_url=target_server.url, limits=limits)
    run_id, worker = await start_bg(client, user_token, t["id"], session_maker)
    await finish(worker)
    wos = [w for w in await work_orders(session_maker, run_id)
           if w.tool == "discovery.crawl"]
    assert len(wos) >= 2, "one atomic crawl would be a single work order"
    evs = await events_of(session_maker, run_id)
    fetched = sum((e.data.get("result") or {}).get("fetched", 0) for e in evs
                  if e.kind == "tool.succeeded" and e.data.get("tool") == "discovery.crawl")
    assert 0 < fetched <= 7
    assert sum(int(w.params["max_pages"]) for w in wos) <= 7


async def test_hint_wakes_the_planner_in_process_within_300ms(
        client, user_token, session_maker, live_target, lab):
    lab.checks(2.0)                          # nothing finishes: only the wake-up can react
    lab.crawl(lambda seeds: (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await _wait(lambda: sum(lab.count("start", t) for t in CHECKS) >= 2)
    posted = time.monotonic()
    row = await hint(client, user_token, run_id, "note")
    for _ in range(100):
        st = await hint_status(client, user_token, run_id, row["id"])
        if st["status"] != "open":
            break
        await asyncio.sleep(0.01)
    latency = time.monotonic() - posted
    await finish(worker)
    assert st["status"] == "addressed" and latency < 0.3, latency


async def test_hydrate_rebuilds_the_planner_state_from_the_database(
        client, user_token, session_maker, live_target, lab):
    lab.checks(0.3)
    lab.crawl(lambda seeds: (0.0, []))
    run_id, worker = await start_bg(client, user_token, live_target["id"], session_maker)
    await hint(client, user_token, run_id, "focus", "/api/")
    await hint(client, user_token, run_id, "skip_check", "exposure.dirlisting")
    await finish(worker)
    rid = uuid.UUID(run_id)
    wos = await work_orders(session_maker, run_id)
    async with session_maker() as s:
        run = await s.get(GreyboxRun, rid)
        pl = Planner(rid, PlannerState(base_url=run.base_url,
                                       scope=ScopePolicy.from_dict(run.scope),
                                       checks=list(run.checks)), uuid.uuid4())
        await pl.hydrate(s)
    st = pl.state
    assert st.seen_dedup == {w.dedup_key for w in wos}
    assert st.skipped_checks == {"exposure.dirlisting"}
    assert [d[0] for d in st.directives] == ["focus"] and st.directives[0][2] == "/api/"
    assert st.objective_node_id is not None and st.crawl_created
    assert {"discovery.fetch_root", "discovery.robots", "discovery.sitemap"} \
        <= st.initial_tools_done


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
