"""Sandboxed tool authoring: the agent writes its own analyser.

The story these tests tell, end to end and with no mocking of the engine:

1. the capability probe proves the interpreter a generated tool runs in cannot
   import a socket, start a process or open a file (:mod:`sandbox`);
2. the result contract is enforced — the tool returns DATA, and anything that is
   not that shape is a refusal with a reason;
3. ``tool.compose`` admission validates identity/purpose/inputs/source, refuses an
   off-scope input, and registers two tools (the analysis and its verifier);
4. a full run (fake model, real worker, real HTTP): the model finds something no
   built-in check can decide, composes an analyser for it, uses it on the live
   fixture, and the report carries the finding with its provenance;
5. a runaway or escaping tool is stopped and audited, never silently "no result".
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web import sandbox
from src.greybox_web import tools as gb_tools
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.netguard import (
    Budget,
    GuardedHttpClient,
    NetPolicy,
    NullRecorder,
)
from src.greybox_web.models import (
    GreyboxEvent,
    GreyboxFinding,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxWorkOrder,
)
from src.greybox_web.planning import Rejection, WorkOrderSpec
from src.greybox_web.planner import Planner, PlannerState
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, toolsmith
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    start_run,
)

# A real analysis need the built-in catalogue cannot answer: the fixture's
# ``/api/notes`` returns a JSON envelope whose ``meta`` block leaks the database
# driver and version -- a shape-dependent disclosure no header/cookie/exposure
# check can decide.
ENVELOPE_SOURCE = '''
"""Flag developer metadata leaked in a JSON envelope."""

def analyse(ctx):
    leaks = []
    for resp in ctx["responses"]:
        body = resp.get("body") or ""
        if "meta" not in body:
            continue
        try:
            doc = json.loads(body)
        except ValueError:
            continue
        meta = doc.get("meta") if isinstance(doc, dict) else None
        if isinstance(meta, dict) and meta.get("engine"):
            leaks.append({"url": resp["url"], "engine": str(meta["engine"]),
                          "owner": str(meta.get("owner") or "")})
    if not leaks:
        return {"summary": "no developer metadata in the envelope",
                "observations": [{"key": "envelope.clean",
                                  "facts": {"inputs": len(ctx["responses"])}}]}
    return {
        "summary": f"{len(leaks)} envelope(s) disclose the database engine",
        "observations": [{"key": "envelope.meta",
                          "facts": {"leaks": len(leaks),
                                    "engine": leaks[0]["engine"]}}],
        "findings": [{
            "title": "API response envelope discloses the database engine",
            "severity": "low",
            "description": "The JSON envelope carries a meta block naming the "
                           "database engine and its owner, which helps an attacker "
                           "target known CVEs.",
            "cwe": "CWE-200",
            "evidence": [json.dumps(leaks[0])[:300]],
            "remediation": "Remove the meta block from production responses.",
        }],
    }
'''

IMPORTS = "import json\n\n"


def _source() -> str:
    return IMPORTS + ENVELOPE_SOURCE


def _spec(**over):
    spec = {"id": "envelope-meta",
            "title": "Envelope metadata leak",
            "purpose": "no built-in check can read a JSON envelope's meta block",
            "source": _source(),
            "inputs": ["http://127.0.0.1:1/api/notes"]}
    spec.update(over)
    return spec


# ------------------------------------------------------- 1. the sandbox itself


async def test_capability_probe_shows_no_network_process_or_file_access():
    """The claim "generated code cannot escape" is worth exactly as much as the
    probe that verifies it in the interpreter that runs generated code."""
    caps = await sandbox.probe()
    for mod in ("socket", "subprocess", "ctypes", "multiprocessing", "ssl",
                "http", "urllib", "importlib"):
        assert caps[mod] == "blocked", (mod, caps[mod])
    for attr in ("os.system", "os.popen", "os.fork", "os.execv", "os.spawnv",
                 "os.kill"):
        assert caps[attr] == "removed", (attr, caps[attr])


@pytest.mark.parametrize("source", [
    "def analyse(ctx):\n    import socket\n    return {}\n",
    "def analyse(ctx):\n    __import__('socket')\n    return {}\n",
    "def analyse(ctx):\n    import subprocess\n    return {}\n",
    "def analyse(ctx):\n    import os\n    os.system('id')\n    return {}\n",
    "def analyse(ctx):\n    return {'summary': open('/etc/passwd').read()}\n",
    "def analyse(ctx):\n    import pathlib\n    return {}\n",
    "def analyse(ctx):\n    from io import open as o\n    return {'s': o('/etc/hosts').read()}\n",
    "def analyse(ctx):\n    import ctypes\n    return {}\n",
])
async def test_escape_attempts_fail_with_a_reason(source):
    out = await sandbox.run(source, {})
    assert out.ok is False
    assert out.error and ("not available" in out.error or "cannot open" in out.error
                          or "no attribute" in out.error), out.error


async def test_runaway_tool_is_stopped_and_the_worker_survives():
    out = await sandbox.run("def analyse(ctx):\n    while True:\n        pass\n",
                            {}, limits=sandbox.SandboxLimits(wall_s=2, cpu_s=5))
    assert out.ok is False and "wall clock" in out.error
    # the engine is still alive and its own file handles are untouched
    assert (await sandbox.run("def analyse(ctx):\n    return {'summary': 'ok'}\n",
                              {})).ok is True


async def test_the_result_contract_is_enforced():
    ok = await sandbox.run(
        "def analyse(ctx):\n"
        "    return {'summary': 's', 'observations': [{'key': 'k', "
        "'facts': {'a': 1, 'b': {'c': 2}}}], 'findings': []}\n", {})
    assert ok.ok and ok.result["observations"][0]["facts"]["b"] == '{"c": 2}'
    for bad in ("def analyse(ctx):\n    return {'summary': 'x', 'extra': 1}\n",
                "def analyse(ctx):\n    return 'not a dict'\n",
                "def analyse(ctx):\n    return {'findings': [{'title': 't', "
                "'description': 'd', 'severity': 'SEVERE'}]}\n"):
        await _unit(bad, expect_error=True)
    with pytest.raises(sandbox.SandboxError):
        sandbox.validate_source("print('no analyse here at all')\n")
    with pytest.raises(sandbox.SandboxError):
        sandbox.validate_source("def analyse(ctx)\n    return {}\n")   # syntax error


async def _unit(source, *, expect_error):
    out = await sandbox.run(source, {})
    assert out.ok is not expect_error, out.error
    return out


async def test_data_changes_the_analysis_but_never_the_code():
    """A tool is data-driven: the same source over two recorded responses reaches
    two verdicts, and the sandbox never sees a URL it was not handed."""
    source = ("def analyse(ctx):\n"
              "    hits = [r['url'] for r in ctx['responses'] if 'secret' in "
              "(r.get('body') or '')]\n"
              "    return {'summary': f'{len(hits)} hit(s)', 'observations': [], "
              "'findings': []}\n")
    one = await sandbox.run(source, {"responses": [
        {"url": "http://t/a", "body": "nothing"}]})
    two = await sandbox.run(source, {"responses": [
        {"url": "http://t/a", "body": "nothing"},
        {"url": "http://t/b", "body": "the secret"}]})
    assert one.result["summary"] == "0 hit(s)"
    assert two.result["summary"] == "1 hit(s)"


# ------------------------------------------------------ 2. the spec contract


def test_compose_spec_validation():
    spec, errs = toolsmith.check_spec(_spec())
    assert errs == [] and spec["id"] == "tool.envelope-meta"
    prefixed, errs = toolsmith.check_spec(_spec(id="tool.envelope-meta"))
    assert errs == [] and prefixed["id"] == "tool.envelope-meta"
    cases = {
        "bad id": _spec(id="Envelope_Meta"),
        "dotted id": _spec(id="bad.x"),
        "no purpose": _spec(purpose=""),
        "no analyse": _spec(source="x = 1\n"),
        "syntax": _spec(source="def analyse(ctx)\n    return {}\n"),
        "too big": _spec(source="def analyse(ctx):\n" + "    pass\n" * 3000),
        "not http": _spec(inputs=["ftp://t/x"]),
        "too many inputs": _spec(inputs=[f"http://t/{i}" for i in range(9)]),
        "verb": _spec(inputs=[{"url": "http://t/x", "method": "DELETE"}]),
        "severity": _spec(advisory={"title": "t", "severity": "SEVERE"}),
    }
    for name, raw in cases.items():
        got, errs = toolsmith.check_spec(raw)
        assert got is None and errs, name


def test_registry_entries_are_the_tool_and_its_verifier():
    spec, _ = toolsmith.check_spec(_spec())
    reg = toolsmith.registry_entries(spec)
    assert set(reg) == {"tool.envelope-meta", "verify.tool.envelope-meta"}
    assert reg["tool.envelope-meta"].kind == "check"
    assert reg["verify.tool.envelope-meta"].kind == "verify"
    assert reg["tool.envelope-meta"].title == "Envelope metadata leak"


# ------------------------------------------------------------- 3. admission


async def _planner(session_maker, run_id, checks):
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        st = PlannerState(base_url=run.base_url,
                          scope=ScopePolicy.from_dict(run.scope),
                          checks=list(checks), dynamic_tools={})
    return Planner(uuid.UUID(str(run_id)), st, uuid.uuid4()), st


async def _admit(session_maker, planner, specs):
    async with session_maker() as s:
        gtx = GraphTx(s, planner.run_id, GraphStats(),
                      agent_id=planner.planner_agent_id)
        obj = await gtx.get_node("objective", "objective")
        if obj is None:
            obj = await gtx.node("objective", "objective", "Assess", "active")
        made = [await planner.admit(s, gtx, sp, origin="planner") for sp in specs]
        await s.commit()
        return made


def _wo(tool, params, variant):
    return WorkOrderSpec(tool=tool, kind=None, title="", reason="test",
                         params=params, priority=30, variant=variant)


@pytest.fixture
async def compose_run(client, user_token, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex,
                        checks=["headers.security"])
    assert r.status_code == 201, r.text
    return uuid.UUID(r.json()["id"])


async def test_admission_registers_both_tools_and_audits_the_source(
        session_maker, compose_run):
    pl, st = await _planner(session_maker, compose_run, ["headers.security"])
    async with session_maker() as s:
        base_url = (await s.get(GreyboxRun, compose_run)).base_url
    made = await _admit(session_maker, pl, [
        _wo("tool.compose", {"spec": _spec(inputs=[base_url + "api/notes"])},
            "compose-1")])
    assert isinstance(made[0], GreyboxWorkOrder), made
    assert made[0].tool == "tool.compose" and made[0].kind == "discovery"
    assert set(st.dynamic_tools) == {"tool.envelope-meta",
                                     "verify.tool.envelope-meta"}
    async with session_maker() as s:
        evs = list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == compose_run,
            GreyboxEvent.kind == "tool.defined"))).all())
    assert len(evs) == 1
    data = evs[0].data
    assert data["id"] == "tool.envelope-meta" and data["kind_detail"] == "composed"
    assert "def analyse(ctx)" in data["source"]          # what ran is on the record
    assert data["inputs"] == [base_url + "api/notes"]
    assert data["limits"]["wall_s"] > 0

    # the composed tool is admitted like any other check (its own selection)
    use = await _admit(session_maker, pl, [
        _wo("tool.envelope-meta", {"url": base_url + "api/notes"}, "use-1")])
    assert isinstance(use[0], GreyboxWorkOrder), use
    assert use[0].kind == "check"
    # ... and its verifier resolves through the same registry
    ver = await _admit(session_maker, pl, [
        _wo("verify.tool.envelope-meta",
            {"finding_id": str(uuid.uuid4()), "url": base_url + "api/notes"},
            "verify-1")])
    assert isinstance(ver[0], GreyboxWorkOrder) and ver[0].kind == "verify"


async def test_off_scope_input_source_and_duplicate_are_refused(
        session_maker, compose_run):
    pl, st = await _planner(session_maker, compose_run, ["headers.security"])
    res = await _admit(session_maker, pl, [
        _wo("tool.compose", {"spec": _spec(inputs=["http://evil.invalid/x"])},
            "compose-oos"),
        _wo("tool.compose", {"spec": _spec(source="x = 1\n")}, "compose-bad"),
    ])
    assert isinstance(res[0], Rejection) and res[0].reason in (
        "host_not_allowed", "out_of_scope")
    assert isinstance(res[1], Rejection) and res[1].reason == "invalid_spec"
    assert st.dynamic_tools == {}          # a refused composition registers nothing
    async with session_maker() as s:
        base_url = (await s.get(GreyboxRun, compose_run)).base_url
    ok = await _admit(session_maker, pl, [
        _wo("tool.compose", {"spec": _spec(inputs=[base_url + "api/notes"])},
            "compose-ok")])
    assert isinstance(ok[0], GreyboxWorkOrder)
    again = await _admit(session_maker, pl, [
        _wo("tool.compose", {"spec": _spec(inputs=[base_url + "api/notes"])},
            "compose-again")])
    assert isinstance(again[0], Rejection) and again[0].reason == "tool_duplicate"


async def test_execution_reads_only_declared_in_scope_inputs(
        session_maker, compose_run):
    """The analyser never addresses a host: the engine fetches the declared inputs
    through the guarded client, and a work order may narrow but never widen them."""
    pl, st = await _planner(session_maker, compose_run, ["headers.security"])
    async with session_maker() as s:
        base_url = (await s.get(GreyboxRun, compose_run)).base_url
    await _admit(session_maker, pl, [
        _wo("tool.compose", {"spec": _spec(inputs=[base_url + "api/notes"])},
            "compose-1")])
    spec, _ = toolsmith.check_spec(_spec(inputs=[base_url + "api/notes"]))
    scope = ScopePolicy.from_dict({"allowed_hosts": ["127.0.0.1"],
                                   "allowed_schemes": ["http"],
                                   "allowed_ports": [80, 8080]})
    client = GuardedHttpClient(scope=scope, budget=Budget(5, 30),
                               policy=NetPolicy(allow_private=True),
                               recorder=NullRecorder())
    try:
        # the work order tries to steer the analysis at a third party: the engine
        # reads only the DECLARED, admitted inputs
        ctx = ToolContext(http=client.bind("tool.envelope-meta"), base_url=base_url,
                          scope=scope, limits=dict(FAST_LIMITS),
                          params={"urls": ["http://evil.invalid/steal"]})
        await toolsmith.execute(spec, ctx)
    finally:
        await client.aclose()
    hosts = [e.host for e in client.recorder.items]
    assert hosts and set(hosts) == {"127.0.0.1"}, hosts


# ------------------------------------------------------------- 4. the full run


async def test_full_run_composes_and_uses_an_analysis_tool(
        client, user_token, session_maker, target_server):
    """Fake model, real worker, real HTTP: the run discovers the JSON envelope,
    composes an analyser no built-in check could express, uses it, and the report
    carries the finding — with the composition itself on the audit trail."""
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    from tests.greybox_web.conftest import run_worker_once
    await run_worker_once(session_maker)
    body = (await client.get(f"/greybox/runs/{run_id}",
                             headers={"Authorization": f"Bearer {user_token}"})).json()
    assert body["status"] == "succeeded", body.get("error_summary")
    async with session_maker() as s:
        wos = list((await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id))).all())
        evs = list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id))).all())
    composed = [w for w in wos if w.tool == "tool.compose"]
    assert len(composed) == 1 and composed[0].status == "done"
    defined = [e for e in evs if e.kind == "tool.defined"]
    assert defined and defined[0].data["kind_detail"] == "composed"
    assert "def analyse(ctx)" in defined[0].data["source"]
    uses = [w for w in wos if w.tool.startswith("tool.") and w.tool != "tool.compose"]
    assert uses, "the composed tool was never used"
    # ... and its finding is in the run's ledger, marked as the candidate an
    # agent-authored analysis is (only verification promotes it)
    findings = [f for f in await _rows(session_maker, run_id, GreyboxFinding)
                if f.check_id == "tool.envelope-meta"]
    assert findings, sorted({f.check_id for f in
                             await _rows(session_maker, run_id, GreyboxFinding)})
    assert findings[0].status in ("candidate", "pending", "verified", "unverified")
    assert "database engine" in findings[0].title.lower()
    # nothing generated code wanted to reach left 127.0.0.1
    ex = await _rows(session_maker, run_id, GreyboxHttpExchange)
    assert {e.host for e in ex} == {"127.0.0.1"}


async def _rows(session_maker, run_id, model, *where):
    async with session_maker() as s:
        return list((await s.scalars(
            select(model).where(model.run_id == run_id, *where))).all())


def test_agent_finding_is_located_where_it_points_not_where_the_tool_ran():
    """Ledgerline run: an analyser run on /openapi.json reported that the audit
    events API is readable by a viewer; the finding was filed under /openapi.json."""
    from src.greybox_web.scope import ScopePolicy
    from src.greybox_web.tools.toolsmith import located
    scope = ScopePolicy.from_dict({"allowed_hosts": ["t.test"], "allowed_schemes": ["http"],
                                   "allowed_ports": [80], "path_prefixes": ["/"]})
    requested = ["http://t.test/openapi.json",
                 "http://t.test/v1/orgs/org_7Hq2/audit-events",
                 "http://t.test/v1/orgs/org_7Hq2",
                 "http://evil.test/v1/orgs/org_7Hq2/audit-events"]
    f = {"title": "Admin-only audit events readable by viewer",
         "description": "GET /v1/orgs/org_7Hq2/audit-events returned 200 to omar"}
    assert located(f, requested, scope) == "http://t.test/v1/orgs/org_7Hq2/audit-events"
    # a template named in the text matches its instance
    f2 = {"title": "x", "description": "/v1/orgs/{id}/audit-events is not role-checked"}
    assert located(f2, requested, scope) is None or "audit-events" in located(
        f2, requested, scope)
    assert located({"title": "nothing named"}, requested, scope) is None
    explicit = "http://t.test/v1/orgs/org_7Hq2/audit-events?cursor=abc"
    assert located({"title": "admin data readable", "affected": explicit}, requested,
                   scope) == explicit
    assert located({"title": "x", "affected": "http://evil.test/private"}, requested,
                   scope) is None
