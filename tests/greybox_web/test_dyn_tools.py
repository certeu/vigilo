"""Dynamic tools (batch E, "tools on demand"): the agent composes a DECLARATIVE
instrument when no built-in tool can express a check.

Four layers, each asserted on its own:

1. spec validation (``dynspec.validate_spec``): the fixed vocabulary — ids, enums,
   key sets, short strings, no code execution — accepts a real instrument and
   refuses every violation (bad method, out-of-vocabulary predicate, unsafe regex,
   missing ``url`` key, ``probe_host`` with follow, oversized strings, ...);
2. the executor (``dynrun``): the validated spec runs through the SAME guarded
   client and inert payloads as the fixed tools against the live synthetic
   target — the ``/echo`` header reflection is found and its negative control
   (``/safe-echo``, escaped) is not;
3. admission (``Planner.admit``): a ``tool.define`` proposal registers the
   instrument + its verify entry and emits ``tool.defined``; a redefinition of an
   existing id is REJECTED (duplicate, not a quota); an invalid spec, an
   out-of-scope target and an unknown dyn id are refused;
4. the full run (fake model, real worker, real HTTP): the model reacts to the
   header-echo hint the discovery marker recorded, composes the instrument, uses
   it on ``/echo``, and the run ends with a VERIFIED ``dyn.*`` finding — while no
   built-in tool can test a request-header reflection at all.

There is deliberately no count cap on dynamic tools: the gates are validation,
dedup and the run's own budgets.
"""
from __future__ import annotations

import copy
import json
import uuid
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from src.greybox_web import tools as gb_tools
from src.greybox_web.graph import GraphStats, GraphTx
from src.greybox_web.models import (
    GreyboxEvent,
    GreyboxFinding,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxWorkOrder,
)
from src.greybox_web.netguard import (
    Budget,
    GuardedHttpClient,
    NetPolicy,
    NullRecorder,
)
from src.greybox_web.planner import Planner, PlannerState
from src.greybox_web.planning import Rejection, WorkOrderSpec
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, dynrun, dynspec
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    h,
    run_worker_once,
    start_run,
)

# The instrument the fake model composes on the /echo hint (the same shape its
# rule 3e proposes in the acceptance run below).
HEADER_SPEC = {
    "id": "dyn.header-reflection",
    "kind": "check",
    "title": "Unencoded reflection of a request header (potential XSS)",
    "description": ("Sends the inert canary in a request header the endpoint was "
                    "seen to echo and reports a response that carries it back "
                    "unencoded."),
    "param_keys": ["url", "header"],
    "request": {"method": "GET",
                "inject": [{"into": "header", "key": "X-Note-Name",
                            "location": "header", "transform": "canary"}],
                "follow": True},
    "baseline": False,
    "verdict": {"mode": "any",
                "predicates": [{"type": "reflection_of", "of": "canary"}]},
    "finding": {"title": "Unencoded reflection of request header X-Note-Name "
                         "(potential XSS)",
                "description": ("The X-Note-Name request header is echoed into the "
                                "HTML without encoding: the inert canary Vigilo "
                                "sent, including its raw <, >, \" and ' characters, "
                                "appears verbatim in the response."),
                "severity": "medium", "confidence": "high", "cwe": "CWE-79",
                "hint": ("Encode untrusted header values by output context; a "
                         "reflection that still carries raw <, >, \" or ' "
                         "characters is exploitable.")},
}


@asynccontextmanager
async def probe_ctx(target_server, params, tool="check"):
    """A ToolContext on a guarded client pointed at the live synthetic target
    (the same pattern test_tools_pentest.py uses for the fixed tools)."""
    port = urlsplit(target_server.url).port
    scope = ScopePolicy.from_dict({
        "allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
        "allowed_ports": [port], "path_prefixes": ["/"],
        "redirect_policy": "in_scope", "allow_auth_testing": True})
    client = GuardedHttpClient(
        scope=scope, budget=Budget(200, 300), policy=NetPolicy(allow_private=True),
        rate_limit_rps=50, request_timeout_s=5, recorder=NullRecorder())
    try:
        yield ToolContext(http=client.bind(tool), base_url=target_server.url, scope=scope,
                          limits=dict(FAST_LIMITS), params=dict(params)), client
    finally:
        await client.aclose()


# ------------------------------------------------------------ 1. spec validation


def test_validate_accepts_a_real_instrument_and_builds_registry_entries():
    tool, errs = dynspec.validate_spec(HEADER_SPEC)
    assert tool is not None, errs
    assert tool.id == "dyn.header-reflection" and tool.kind == "check"
    assert tool.param_keys == ("url", "header")
    assert tool.request.method == "GET" and tool.request.follow is True
    assert tool.request.baseline is False
    assert tool.request.inject[0].transform == "canary"
    entries = dynspec.registry_entries(tool)
    assert set(entries) == {"dyn.header-reflection",
                            "verify.dyn.header-reflection"}
    check, verify = entries["dyn.header-reflection"], entries["verify.dyn.header-reflection"]
    assert check.kind == "check" and verify.kind == "verify"
    assert check.param_keys == ("url", "header")
    assert verify.param_keys == ("finding_id", "url", "header")
    assert check.title == HEADER_SPEC["title"]     # the report/knowledge title


def _reject(mutate, label):
    spec = copy.deepcopy(HEADER_SPEC)
    mutate(spec)
    tool, errs = dynspec.validate_spec(spec)
    assert tool is None, f"{label}: accepted!"
    assert errs, label
    return " ".join(errs)


@pytest.mark.parametrize("label,mutate", [
    ("bad method", lambda s: s["request"].__setitem__("method", "DELETE")),
    ("out-of-vocab predicate",
     lambda s: s["verdict"]["predicates"].__setitem__(
         0, {"type": "execute_command", "of": "canary"})),
    ("unsafe regex (nested quantifier)",
     lambda s: s["verdict"]["predicates"].__setitem__(
         0, {"type": "body_regex", "value": "(a|a)+"})),
    ("unsafe regex (backslash class)",
     lambda s: s["verdict"]["predicates"].__setitem__(
         0, {"type": "body_regex", "value": r"error \d+"})),
    ("missing url param key", lambda s: s["param_keys"].__setitem__(0, "header")),
    ("param key out of vocabulary",
     lambda s: s["param_keys"].__setitem__(1, "javascript")),
    ("probe_host followed",
     lambda s: s.__setitem__("request", {
         "method": "GET",
         "inject": [{"into": "url", "key": "next", "location": "query",
                     "transform": "probe_host"}], "follow": True})),
    ("unknown transform",
     lambda s: s["request"]["inject"][0].__setitem__("transform", "exec")),
    ("header injection not into a header",
     lambda s: s["request"]["inject"][0].__setitem__("into", "param")),
    ("form injection on GET",
     lambda s: s.__setitem__("request", {
         "method": "GET",
         "inject": [{"into": "param", "key": "q", "location": "form",
                     "transform": "canary"}], "follow": True})),
    ("oversized title", lambda s: s.__setitem__("title", "x" * 201)),
    ("oversized finding description",
     lambda s: s["finding"].__setitem__("description", "x" * 601)),
    ("uppercase id", lambda s: s.__setitem__("id", "dyn.Header-Reflection")),
    ("static id (not dyn.)", lambda s: s.__setitem__("id", "injection.reflection")),
    ("unknown top-level field", lambda s: s.__setitem__("timeout_s", 30)),
    ("unknown predicate field",
     lambda s: s["verdict"]["predicates"][0].__setitem__("value", "x")),
    ("duplicate predicate type",
     lambda s: s["verdict"]["predicates"].append(
         {"type": "reflection_of", "of": "canary"})),
    ("status_differs without baseline",
     lambda s: s["verdict"]["predicates"].__setitem__(
         0, {"type": "status_differs", "from": "baseline"})),
    ("header key with whitespace",
     lambda s: s["request"]["inject"][0].__setitem__("key", "X-Note Name")),
    ("header key with CR (smuggling)",
     lambda s: s["request"]["inject"][0].__setitem__("key", "X-Inject\r\nHost")),
    ("empty inject list", lambda s: s["request"].__setitem__("inject", [])),
    ("no injection points given",
     lambda s: s["request"].__setitem__("inject", [{}])),
    ("non-object spec", lambda s: s.__setitem__("verdict", "any")),
    ("kind not check", lambda s: s.__setitem__("kind", "discovery")),
    ("bad severity", lambda s: s["finding"].__setitem__("severity", "fatal")),
    ("bad cwe", lambda s: s["finding"].__setitem__("cwe", "79")),
])
def test_validate_rejects_every_violation(label, mutate):
    errs = _reject(mutate, label)
    assert len(errs) < 300          # a short, repairable message (the model retries)


def test_regex_gate_allows_normal_patterns_and_refuses_ambiguous_ones():
    for pat in ("500 internal", "error: (.+) occurred", "vgl[a-f0-9]+",
                "(ab|ac)+", "[0-9]+", "(a+)(b+)c?"):
        assert dynspec._regex_is_safe(pat) is None, pat
    for pat in ("(a|a)+", "(a+)+", "(a|ab)+", "((a)*)+", "(xy|yx)+"):
        assert dynspec._regex_is_safe(pat) is not None, pat


# --------------------------------------------------------------- 2. the executor


async def test_dyn_executor_finds_the_header_reflection_and_replays_it(target_server):
    """The /echo weakness, through the generic executor: the canary rides a request
    header (something no built-in tool can do), the reflection_of predicate fires,
    and the replay (the verifier) reproduces the verdict with fresh values."""
    tool, _ = dynspec.validate_spec(HEADER_SPEC)
    url = target_server.url + "echo"
    async with probe_ctx(target_server, {"url": url, "header": "X-Note-Name"},
                         tool="dyn.header-reflection") as (ctx, client):
        res = await dynrun.execute(tool, ctx)
        assert res.counts == {"probed": 1, "baseline": 0, "matched": 1, "verdict": 1}
        assert len(res.findings) == 1
        f = res.findings[0]
        assert f.check_id == "dyn.header-reflection" and f.severity == "medium"
        assert f.confidence == "high" and f.cwe == "CWE-79"
        assert f.parameter == "X-Note-Name" and f.param_location == "header"
        assert f.method == "GET" and f.url == url
        assert f.verify == {"url": url, "header": "X-Note-Name"}
        assert f.title == HEADER_SPEC["finding"]["title"]
        assert "vgl" in f.evidence[0].excerpt and "<>" in f.evidence[0].excerpt
        assert f.evidence[0].exchange_id is not None
        assert any(h["type"] == "remediation" and "Encode" in h["content"]
                   for h in f.detection_hints)
        obs = res.observations[0]
        assert obs.facts["verdict"] is True
        assert obs.facts["predicates"] == [{"type": "reflection_of", "ok": True}]
        # the single-point override worked: the canary went out in the header the
        # work order named, and only one request was made
        ex = client.recorder.items[-1]
        sent = dict(ex.request_headers or [])
        assert sent["X-Note-Name"].startswith("vgl") and "'<>" in sent["X-Note-Name"]
        assert len(client.recorder.items) == 1
        # the verifier: the same declarative spec, fresh values, same verdict
        vr = await dynrun.replay(tool, ctx)
        assert vr.confirmed is True
        assert "reproduced" in vr.note and vr.exchange_ids


async def test_dyn_executor_negative_control_is_the_escaped_echo(target_server):
    """The same instrument on /safe-echo (HTML-escaped header echo): no finding,
    the negative outcome is recorded work, and the replay honestly refuses."""
    tool, _ = dynspec.validate_spec(HEADER_SPEC)
    async with probe_ctx(target_server, {"url": target_server.url + "safe-echo",
                                  "header": "X-Note-Name"},
                         tool="dyn.header-reflection") as (ctx, _client):
        res = await dynrun.execute(tool, ctx)
        assert res.findings == []
        assert res.counts["verdict"] == 0 and res.counts["matched"] == 0
        assert res.observations[0].facts["verdict"] is False
        vr = await dynrun.replay(tool, ctx)
        assert vr.confirmed is False


async def test_dyn_executor_supports_baseline_query_and_signature(target_server):
    """A composed error-based instrument: append_quote on the /item parameter with
    a baseline — the fixed injection.errors semantics expressed as a spec, proving
    multi-predicate (mode all) and baseline evidence."""
    spec = {
        "id": "dyn.quote-error",
        "kind": "check",
        "title": "Error-based indicator through an appended quote",
        "description": "A single quote appended to the parameter, against a baseline.",
        "param_keys": ["url", "param", "location"],
        "request": {"method": "GET",
                    "inject": [{"into": "param", "key": "id", "location": "query",
                                "transform": "append_quote"}],
                    "follow": True},
        "baseline": True,
        "verdict": {"mode": "all",
                    "predicates": [{"type": "signature", "which": "sql"},
                                   {"type": "body_differs", "from": "baseline"}]},
        "finding": {"title": "Error-based injection indicator on id",
                    "description": "The quote triggers a database error.",
                    "severity": "high", "confidence": "high", "cwe": "CWE-209"},
    }
    tool, errs = dynspec.validate_spec(spec)
    assert tool is not None, errs
    async with probe_ctx(target_server, {"url": target_server.url + "item?id=1",
                                  "param": "id", "location": "query"},
                         tool="dyn.quote-error") as (ctx, client):
        res = await dynrun.execute(tool, ctx)
        assert len(res.findings) == 1
        f = res.findings[0]
        assert f.check_id == "dyn.quote-error" and f.severity == "high"
        assert f.parameter == "id" and f.param_location == "query"
        # the baseline was fetched first (id=1), the quote probe second
        assert [urlsplit(ex.url).query for ex in client.recorder.items] == \
            ["id=1", "id=1%27"]
        roles = [e.role for e in f.evidence]
        assert roles == ["proof", "baseline"]
        assert res.observations[0].facts["baseline_status"] == 200
        assert res.counts == {"probed": 1, "baseline": 1, "matched": 2, "verdict": 1}


async def test_dyn_executor_supports_set_transform_and_json_predicates(target_server):
    """A header 'set' instrument with json_path + header_contains predicates: the
    /api/data CORS reflection expressed as a composed check."""
    spec = {
        "id": "dyn.cors-reflect",
        "kind": "check",
        "title": "Arbitrary Origin accepted with credentials",
        "description": "Sets an Origin header and reads the CORS answer back.",
        "param_keys": ["url", "header", "value"],
        "request": {"method": "GET",
                    "inject": [{"into": "header", "key": "Origin",
                                "location": "header", "transform": "set"}],
                    "follow": True},
        "baseline": False,
        "verdict": {"mode": "all",
                    "predicates": [
                        {"type": "header_contains", "name": "Access-Control-Allow-Origin",
                         "value": "https://vigilo.example.test"},
                        {"type": "json_path", "path": "items.0", "op": "equals",
                         "value": "1"},
                        {"type": "status_class", "value": "2"}]},
        "finding": {"title": "CORS reflects any origin",
                    "description": "The endpoint echoes the Origin header.",
                    "severity": "medium", "confidence": "high", "cwe": "CWE-942"},
    }
    tool, errs = dynspec.validate_spec(spec)
    assert tool is not None, errs
    async with probe_ctx(target_server, {"url": target_server.url + "api/data",
                                  "header": "Origin",
                                  "value": "https://vigilo.example.test"},
                         tool="dyn.cors-reflect") as (ctx, client):
        res = await dynrun.execute(tool, ctx)
        assert len(res.findings) == 1, res.observations[0].facts
        assert res.findings[0].check_id == "dyn.cors-reflect"
        assert res.observations[0].facts["injections"] == \
            ["Origin@header:set"]
        assert len(client.recorder.items) == 1
        assert dict(client.recorder.items[-1].request_headers)["Origin"] == \
            "https://vigilo.example.test"


async def test_define_makes_no_requests_and_records_the_identity():
    """tool.define execution is free: no http (the context carries none), and the
    definition is recorded as an observation carrying the instrument's identity."""
    ctx = ToolContext(http=None, base_url="http://127.0.0.1:1/", scope=None,
                      limits={}, params={"spec": dict(HEADER_SPEC)})
    out = await gb_tools.get("tool.define").run(ctx)
    assert out.counts == {"defined": 1}
    assert out.observations[0].facts["id"] == "dyn.header-reflection"
    assert out.observations[0].facts["requests_made"] == 0
    assert out.observations[0].facts["param_keys"] == ["url", "header"]
    assert "header-reflection" in out.summary


# ---------------------------------------------------------------- 3. admission


async def _planner(session_maker, run_id, checks):
    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        st = PlannerState(base_url=run.base_url,
                          scope=ScopePolicy.from_dict(run.scope),
                          checks=list(checks), dynamic_tools={})
    return Planner(uuid.UUID(str(run_id)), st, uuid.uuid4()), st


async def _admit_all(session_maker, planner, specs):
    """Admit through a real GraphTx (the same path the supervisor uses)."""
    async with session_maker() as s:
        gtx = GraphTx(s, planner.run_id, GraphStats(),
                      agent_id=planner.planner_agent_id)
        obj = await gtx.get_node("objective", "objective")
        if obj is None:
            obj = await gtx.node("objective", "objective", "Assess", "active")
        made = []
        for sp in specs:
            made.append(await planner.admit(s, gtx, sp, origin="planner"))
        await s.commit()
        return made


@pytest.fixture
async def dyn_run(client, user_token, live_target):
    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex,
                        checks=["headers.security"])
    assert r.status_code == 201, r.text
    return uuid.UUID(r.json()["id"])


def _spec(tool, params, variant):
    return WorkOrderSpec(tool=tool, kind=None, title="", reason="test",
                         params=params, priority=30, variant=variant)


async def test_admission_registers_the_instrument_and_its_verifier(
        session_maker, dyn_run):
    """One tool.define admission: the work order is created, the run-scoped
    registry gains the check + verify entries, and a tool.defined event lands —
    the definition itself makes no request (it is a discovery-kind work order)."""
    pl, st = await _planner(session_maker, dyn_run, ["headers.security"])
    async with session_maker() as s:
        base_url = (await s.get(GreyboxRun, dyn_run)).base_url
    made = await _admit_all(session_maker, pl, [
        _spec("tool.define", {"spec": dict(HEADER_SPEC)}, "compose-header")])
    assert len(made) == 1 and isinstance(made[0], GreyboxWorkOrder), made
    wo = made[0]
    assert wo.tool == "tool.define" and wo.kind == "discovery"
    assert set(st.dynamic_tools) == {"dyn.header-reflection",
                                     "verify.dyn.header-reflection"}
    assert st.dynamic_tools["dyn.header-reflection"].param_keys == ("url", "header")
    async with session_maker() as s:
        evs = list((await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == dyn_run,
            GreyboxEvent.kind == "tool.defined"))).all())
        assert len(evs) == 1
        assert evs[0].data["id"] == "dyn.header-reflection"
        assert evs[0].data["param_keys"] == ["url", "header"]
        assert evs[0].work_order_id == wo.id
        # the use of the instrument resolves through the same admission
    use = await _admit_all(session_maker, pl, [
        _spec("dyn.header-reflection", {"url": base_url + "echo",
                                        "header": "X-Note-Name"}, "use-echo")])
    assert isinstance(use[0], GreyboxWorkOrder)
    assert use[0].kind == "check" and use[0].tool == "dyn.header-reflection"
    # its verifier resolves too (priority-10 evidence gate would propose it)
    ver = await _admit_all(session_maker, pl, [
        _spec("verify.dyn.header-reflection",
              {"finding_id": str(uuid.uuid4()), "url": base_url + "echo",
               "header": "X-Note-Name"}, "v1")])
    assert isinstance(ver[0], GreyboxWorkOrder)
    assert ver[0].kind == "verify"


async def test_redefinition_of_an_existing_id_is_rejected(
        session_maker, dyn_run):
    """A second tool.define with an id that already exists (static or dynamic) is
    a correctness rejection — never a count quota."""
    pl, _ = await _planner(session_maker, dyn_run, ["headers.security"])
    made = await _admit_all(session_maker, pl, [
        _spec("tool.define", {"spec": dict(HEADER_SPEC)}, "compose-header")])
    assert isinstance(made[0], GreyboxWorkOrder)
    again = await _admit_all(session_maker, pl, [
        _spec("tool.define", {"spec": dict(HEADER_SPEC)}, "compose-again")])
    assert isinstance(again[0], Rejection) and again[0].reason == "tool_duplicate"


async def test_invalid_and_unsafe_proposals_are_refused(session_maker, dyn_run):
    """An invalid spec, an out-of-scope use target and an unknown dyn id are all
    refused — the dynamic surface never widens admission."""
    pl, _ = await _planner(session_maker, dyn_run, ["headers.security"])
    bad = copy.deepcopy(HEADER_SPEC)
    bad["request"]["inject"][0]["transform"] = "rm -rf"          # not a vocabulary value
    res = await _admit_all(session_maker, pl, [
        _spec("tool.define", {"spec": bad}, "compose-bad"),
        _spec("tool.define", {"spec": {"id": "dyn.x", "kind": "check"}},
              "compose-missing"),
        _spec("dyn.never-defined", {"url": "http://127.0.0.1:1/echo"}, "use"),
    ])
    assert [r.reason for r in res] == ["invalid_spec", "invalid_spec", "unknown_tool"]
    # a well-formed instrument is still admitted after the refusals...
    ok = await _admit_all(session_maker, pl, [
        _spec("tool.define", {"spec": dict(HEADER_SPEC)}, "compose-ok")])
    assert isinstance(ok[0], GreyboxWorkOrder)
    # ...but its use on an out-of-scope host is not (same scope admission)
    out = await _admit_all(session_maker, pl, [
        _spec("dyn.header-reflection",
              {"url": "http://evil.invalid/echo", "header": "X"}, "use-oos")])
    assert isinstance(out[0], Rejection) and out[0].reason in (
        "host_not_allowed", "out_of_scope")


# ------------------------------------------------------------- 4. the full run


async def _full_run(client, user_token, session_maker, target_server):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert str(await run_worker_once(session_maker)) == str(run_id)
    body = (await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))).json()
    assert body["status"] == "succeeded", body.get("error_summary")
    return run_id, body


async def _rows(session_maker, run_id, model, *where):
    async with session_maker() as s:
        return list((await s.scalars(
            select(model).where(model.run_id == run_id, *where))).all())


async def test_full_run_defines_uses_and_verifies_a_dynamic_instrument(
        client, user_token, session_maker, target_server):
    """The end-to-end story (fake model, real worker, real HTTP): discovery's
    marker header records the /echo reflection as a hint; the model composes
    dyn.header-reflection (tool.define — no requests), uses it on /echo, and the
    run ends with a VERIFIED finding no built-in tool could produce. /safe-echo
    (the escaped control) stays clean, and nothing leaves 127.0.0.1."""
    run_id, body = await _full_run(client, user_token, session_maker, target_server)
    assert body["end_reason"] == "completed"
    wos = await _rows(session_maker, run_id, GreyboxWorkOrder)
    findings = await _rows(session_maker, run_id, GreyboxFinding)
    evs = await _rows(session_maker, run_id, GreyboxEvent)

    # --- the definition happened, made no requests, and is on the audit trail
    defines = [w for w in wos if w.tool == "tool.define"]
    assert len(defines) == 1 and defines[0].status == "done"
    assert defines[0].params["spec"]["id"] == "dyn.header-reflection"
    # declarations AND compositions are audited under tool.defined: the run may
    # also author an analyser (Phase 3) for a data shape no tool can decide
    defined = [e for e in evs if e.kind == "tool.defined"
               and e.data.get("kind_detail") != "composed"]
    assert len(defined) == 1
    assert defined[0].data["id"] == "dyn.header-reflection"
    assert defined[0].data["title"] == HEADER_SPEC["title"]

    # --- the instrument was used on /echo (and only there: the hinted endpoint)
    uses = [w for w in wos if w.tool == "dyn.header-reflection"]
    assert len(uses) == 1 and uses[0].status == "done"
    assert str(uses[0].params.get("url", "")).endswith("/echo")
    assert uses[0].params.get("header") == "X-Note-Name"

    # --- the finding is VERIFIED, with its own verify.<dyn id> work order
    dyn_findings = [f for f in findings
                    if f.check_id == "dyn.header-reflection"]
    assert len(dyn_findings) == 1
    f = dyn_findings[0]
    assert f.status == "verified", f.verification
    assert f.severity == "medium" and f.confidence == "high"
    assert f.title == HEADER_SPEC["finding"]["title"]
    assert f.cwe == "CWE-79"
    loc = f.location or {}
    assert str(loc.get("url", "")).endswith("/echo")
    assert loc.get("parameter") == "X-Note-Name"     # the injected header name
    excerpt = json.dumps(f.evidence, default=str)
    assert "vgl" in excerpt and "<>" in excerpt       # the raw canary came back
    assert f.verification and f.verification.get("result") == "confirmed"
    verify = [w for w in wos if w.tool == "verify.dyn.header-reflection"]
    assert len(verify) == 1 and verify[0].status == "done"
    assert str(verify[0].params.get("url", "")).endswith("/echo")

    # --- the negative control: nothing on /safe-echo, and no built-in tool
    #     touched /echo (they cannot: it has no parameter and no fixed tool
    #     injects into request headers)
    assert not [f for f in findings
                if str((f.location or {}).get("url", "")).endswith("/safe-echo")]
    echo_wos = [w for w in wos
                if str((w.params or {}).get("url", "")).endswith("/echo")]
    assert {w.tool for w in echo_wos} == {"dyn.header-reflection",
                                          "verify.dyn.header-reflection"}

    # --- scope discipline held: only 127.0.0.1 was ever requested
    exchanges = await _rows(session_maker, run_id, GreyboxHttpExchange)
    assert {e.host for e in exchanges} == {"127.0.0.1"}
    assert not [e for e in exchanges
                if (urlsplit(e.url).hostname or "").endswith(".invalid")]
    assert len(exchanges) <= FAST_LIMITS["max_requests"]

    # --- the report counts the agent-defined instrument as coverage
    rep = (await client.get(f"/greybox/runs/{run_id}/report",
                            headers=h(user_token))).json()
    assert rep["status"] == "ready"
    md = rep["markdown"]
    assert "dyn.header-reflection" in md and "tool.define" in md
    assert "Agent-defined" in md
    # no secrets on the dynamic surface: the define/use/verify params are exactly
    # the declared vocabulary — no credentials, no cookies
    for w in [*defines, *uses, *verify]:
        assert set(w.params) <= {"spec", "url", "header", "finding_id"}, \
            (w.tool, set(w.params))


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
