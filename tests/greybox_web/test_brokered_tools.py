"""Agent-written tools with the capability broker.

A generated tool runs isolated (bubblewrap: no network, no host files) and acts
only through ``ctx.broker``; every brokered call passes the declared-capability
gate, the run's capability policy and the protocol guard. These tests run real
generated code against the real SPA fixture:

* an access-control analyser compares two authorised identities and anonymous on
  object URLs it is given as arguments: the seeded weakness (any user reads any
  note) is reported, the enforced control (reports) is not — confirmed vs. negative;
* refusals are data the tool can read (undeclared capability, out of scope, raw
  TCP without a network scope, quota), and every one is audited;
* the OS boundary holds even for code that escapes the interpreter guard.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

from src.greybox_web import sandbox
from src.greybox_web.netcap import GuardedNet, ToolNet
from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy
from src.greybox_web.scope import PolicyContext, build_scope
from src.greybox_web.tools import ToolContext, toolsmith
from src.greybox_web.tools.authz import capability_url
from tests.greybox_web.fixtures import spa_app


class Rec:
    def __init__(self) -> None:
        self.rows = []

    async def record(self, ex):
        self.rows.append(ex)
        return len(self.rows)


def test_capability_url_requires_explicit_share_material():
    assert capability_url("http://t.test/share/abcdefghijk")
    assert capability_url("http://t.test/document/1?token=abcdefgh")
    assert not capability_url("http://t.test/documents/share")
    assert not capability_url("http://t.test/document/1?token=")


@pytest.fixture(scope="module")
def spa():
    server, url = spa_app.serve()
    yield url
    server.should_exit = True


async def _login(client, base: str, user: str) -> str:
    http = client.bind("auth.login")
    r = await http.request("POST", base + "api/session",
                           body=json.dumps({"username": user,
                                            "password": spa_app.USERS[user]}),
                           content_type="application/json", follow=False,
                           session="anon")
    cookie = next(v for k, v in r.headers if k.lower() == "set-cookie")
    return cookie.split(";", 1)[0]


async def _ctx(base: str, params: dict, *, sessions=("ana", "bruno"), scope_extra=None):
    _, scope, errs = build_scope(base, scope_extra or {},
                                 PolicyContext(allow_private=True))
    assert not errs
    rec = Rec()
    client = GuardedHttpClient(scope=scope, budget=Budget(300, 120),
                               policy=NetPolicy(allow_private=True), recorder=rec,
                               rate_limit_rps=100)
    for user in sessions:
        client.establish_session(user, await _login(client, base, user))
    http = client.bind("tool.authz-diff")
    ctx = ToolContext(http=http, base_url=base, scope=scope, limits={},
                      params=params, net=ToolNet(GuardedNet(client), http._prov))
    return ctx, rec, client


AUTHZ_SOURCE = '''
"""Compare who can read each object: anonymous and every identity of the run."""

def analyse(ctx):
    base = ctx.base_url.rstrip("/")
    identities = [s["label"] for s in ctx.broker.sessions()]
    rows, findings = [], []
    for path in ctx.args["objects"]:
        seen = {}
        for ident in ["anon"] + identities:
            r = ctx.broker.get(base + path, session=ident)
            owner = None
            if r["status"] == 200:
                try:
                    owner = json.loads(r["body"]).get("owner")
                except ValueError:
                    pass
            seen[ident] = {"status": r["status"], "owner": owner,
                           "exchange": r["exchange_id"]}
        rows.append({"path": path, "access": seen})
        readers = [i for i in identities if seen[i]["status"] == 200]
        owners = {seen[i]["owner"] for i in readers}
        foreign = [i for i in readers if seen[i]["owner"] not in (None, i)]
        if foreign:
            findings.append({
                "title": "Object-level authorisation missing on " + path.rsplit("/", 1)[0],
                "severity": "high", "class": "vulnerability", "cwe": "CWE-639",
                "description": f"{path} owned by {sorted(owners)} is readable by "
                               f"{foreign}, who do not own it.",
                "evidence": [json.dumps(seen)[:400]],
                "remediation": {"summary": "Enforce ownership on object reads.",
                                "steps": ["Check object.owner == session.user "
                                          "server-side before returning it."],
                                "validation": ["As a non-owner, the same request "
                                               "returns 403/404."]}})
    return {"summary": f"{len(rows)} object(s) compared across "
                       f"{len(identities) + 1} identities",
            "observations": [{"key": r["path"], "facts": {"access": json.dumps(r["access"])}}
                             for r in rows],
            "findings": findings}
'''


def _spec(**over):
    raw = {"id": "authz-diff", "title": "Cross-identity object access",
           "purpose": "authz.object reads one URL; this compares owners across "
                      "identities for a list of objects",
           "capabilities": ["http"], "source": "import json\n" + AUTHZ_SOURCE}
    raw.update(over)
    spec, errs = toolsmith.check_spec(raw)
    assert spec is not None, errs
    return spec


async def test_generated_tool_confirms_the_seeded_weakness_and_not_the_control(spa):
    ctx, rec, client = await _ctx(spa, {"args": {"objects": [
        "/api/notes/3", "/api/reports/2"]}})
    try:
        res = await toolsmith.execute(_spec(), ctx)
    finally:
        await client.aclose()
    titles = [f.title for f in res.findings]
    assert titles == ["Object-level authorisation missing on /api/notes"], res.summary
    f = res.findings[0]
    assert f.finding_class == "vulnerability" and f.confidence == "low"  # until verified
    assert f.remediation["validation"] and f.verify["args"]["objects"]
    # the negative control (reports enforce ownership) produced no finding, and the
    # evidence is the guard's own exchanges
    facts = res.observations[-1].facts
    assert facts["broker"]["calls"] >= 7 and facts["isolation"] in ("bwrap", "unshare",
                                                                     "process")
    assert all(row.tool == "tool.authz-diff" for row in rec.rows[2:])
    # replay (the engine's verification) reproduces it independently
    ctx.params["finding"] = {"title": f.title}
    ctx, rec2, client2 = await _ctx(spa, {"args": f.verify["args"],
                                          "finding": {"title": f.title}})
    try:
        v = await toolsmith.replay(_spec(), ctx)
    finally:
        await client2.aclose()
    assert v.confirmed


REFUSALS = '''
def analyse(ctx):
    out = {}
    for name, fn in [
        ("out_of_scope", lambda: ctx.broker.get("http://127.0.0.2:9/x")),
        ("undeclared_tcp", lambda: ctx.broker.tcp("127.0.0.1", 22)),
        ("undeclared_dns", lambda: ctx.broker.dns("example.com")),
        ("put", lambda: ctx.broker.http(ctx.base_url + "api/notes/1", method="PUT")),
        ("patch", lambda: ctx.broker.http(ctx.base_url + "api/notes/1", method="PATCH")),
        ("delete", lambda: ctx.broker.http(ctx.base_url + "api/notes/1", method="DELETE")),
        ("rpc", lambda: ctx.broker.post(ctx.base_url + "graphql", json={"query":"mutation { approveChange(id: \\"1\\") { id } }"})),
        ("unknown_op", lambda: ctx.broker.call("shell", cmd="id")),
    ]:
        try:
            fn()
            out[name] = "ALLOWED"
        except BrokerError as exc:
            out[name] = str(exc)[:120]
    return {"summary": "refusals", "observations": [{"key": "r", "facts": out}]}
'''


async def test_broker_refusals_are_readable_and_audited(spa):
    ctx, rec, client = await _ctx(spa, {}, sessions=())
    try:
        res = await toolsmith.execute(_spec(source=REFUSALS, id="refusals"), ctx)
    finally:
        await client.aclose()
    facts = next(o.facts for o in res.observations if o.label == "r")
    assert "host_not_allowed" in facts["out_of_scope"]
    assert "did not declare" in facts["undeclared_tcp"]
    assert "did not declare" in facts["undeclared_dns"]
    assert all("state_changing_not_allowed" in facts[method]
               for method in ("put", "patch", "delete", "rpc"))
    assert "unknown broker operation" in facts["unknown_op"]
    audit = res.observations[-1].facts["broker"]
    assert audit["calls"] == 8 and audit["by_outcome"].get("ok") is None
    assert all(r.blocked for r in rec.rows)       # nothing reached the network


async def test_raw_tcp_without_a_network_scope_is_refused_even_when_declared(spa):
    src = '''
def analyse(ctx):
    try:
        r = ctx.broker.tcp("127.0.0.1", 22)
        return {"summary": "state=" + r["state"] + " reason=" + str(r["reason"])}
    except BrokerError as exc:
        return {"summary": "refused: " + str(exc)}
'''
    ctx, rec, client = await _ctx(spa, {}, sessions=())
    try:
        res = await toolsmith.execute(
            _spec(source=src, id="tcp-try", capabilities=["tcp_connect"]), ctx)
    finally:
        await client.aclose()
    # web mode does not authorise tcp_connect at all
    assert "does not authorise" in res.summary, res.summary


async def test_quota_and_failure_text_reach_the_agent(spa):
    src = '''
def analyse(ctx):
    for i in range(10):
        ctx.broker.get(ctx.base_url)
    return {"summary": "never"}
'''
    ctx, rec, client = await _ctx(spa, {}, sessions=())
    try:
        with pytest.raises(sandbox.SandboxError) as exc:
            await toolsmith.execute(_spec(source=src, id="greedy", max_calls=3), ctx)
    finally:
        await client.aclose()
    msg = str(exc.value)
    assert "quota" in msg and "last broker calls" in msg
    assert len([r for r in rec.rows if not r.blocked]) == 3


# ------------------------------------------------------------- the OS boundary


@pytest.mark.skipif(sys.platform != "linux", reason="namespaces are Linux-only")
async def test_bwrap_has_no_network_and_no_host_files(tmp_path):
    if not await sandbox._works("bwrap"):
        pytest.skip("bubblewrap cannot create namespaces here")
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    probe = (f"import socket,os\nout=[]\n"
             f"try:\n socket.create_connection(('127.0.0.1',{port}),1); out.append('NET')\n"
             f"except OSError as e: out.append('nonet')\n"
             f"out.append('ETC' if os.path.exists('/etc/passwd') else 'noetc')\n"
             f"out.append('HOME' if os.path.exists({os.getcwd()!r}) else 'nohome')\n"
             f"print(','.join(out))")
    cmd = sandbox._bwrap_cmd(str(tmp_path), sandbox._python()) + [
        sandbox._python(), "-I", "-S", "-c", probe]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={})
    out, err = await proc.communicate()
    server.close()
    # unrestricted Python inside the box: still no route out, nothing to read
    assert out.decode().strip() == "nonet,noetc,nohome", err.decode()


async def test_generated_code_is_not_run_without_os_isolation(monkeypatch):
    monkeypatch.setenv(sandbox.ISOLATION_ENV, "auto")
    monkeypatch.setattr(sandbox, "_PROBED", {"bwrap": False, "unshare": False})
    with pytest.raises(sandbox.IsolationUnavailable):
        await sandbox.run('def analyse(ctx):\n    return {"summary": "x"}\n', {})
    # explicit operator opt-in is the only way to run with interpreter guards only
    monkeypatch.setenv(sandbox.ISOLATION_ENV, "process")
    res = await sandbox.run('def analyse(ctx):\n    return {"summary": "x"}\n', {})
    assert res.ok and res.isolation == "process"


async def test_interpreter_escape_hatches_are_closed():
    src = '''
def analyse(ctx):
    out = {}
    for m in ("posix", "_io", "socket", "_thread", "gc", "subprocess"):
        try:
            __import__(m)
            out[m] = "IMPORTED"
        except ImportError:
            out[m] = "blocked"
    return {"summary": "x", "observations": [{"key": "k", "facts": out}]}
'''
    res = await sandbox.run(src, {})
    assert res.ok, res.error
    assert set(res.result["observations"][0]["facts"].values()) == {"blocked"}


async def test_authz_object_sees_through_responses_that_echo_the_caller(spa):
    """Regression (real-model evaluation): /api/notes/{id} echoes "viewer": <caller>,
    so a byte-for-byte comparison never saw two identities receive the same note."""
    from src.greybox_web.tools import authz
    from src.greybox_web import verify
    ctx, rec, client = await _ctx(spa, {"url": spa + "api/notes/3"})
    ctx.accounts = (("ana", "ana", {}), ("bruno", "bruno", {}))
    try:
        res = await authz.object_access(ctx)
        assert len(res.findings) == 1 and "ana" in res.findings[0].title, res.summary
        assert res.findings[0].remediation["validation"]
        v = await verify.VERIFIERS["authz.object"](ctx)
        assert v.confirmed, v.note
        ctx.params["url"] = spa + "api/reports/2"            # ownership enforced
        assert not (await authz.object_access(ctx)).findings
    finally:
        await client.aclose()


async def test_authz_object_skips_non_concrete_route_templates(spa):
    from src.greybox_web.tools import authz
    ctx, _rec, client = await _ctx(spa, {"url": spa + "api/items/{id}"})
    ctx.accounts = (("ana", "ana", {}), ("bruno", "bruno", {}))
    try:
        result = await authz.object_access(ctx)
    finally:
        await client.aclose()
    assert result.counts["requests"] == 0 and not result.findings


async def test_authz_object_ignores_routes_that_answer_the_same_for_any_id(spa):
    """Regression (real-model evaluation): an SPA client route (/notebooks/3) returns
    the HTML shell for every id and identity; that is not a shared object."""
    from src.greybox_web.tools import authz
    ctx, rec, client = await _ctx(spa, {"url": spa + "notebooks/3"})
    ctx.accounts = (("ana", "ana", {}), ("bruno", "bruno", {}))
    try:
        res = await authz.object_access(ctx)
    finally:
        await client.aclose()
    assert not res.findings, res.summary
    assert res.observations[0].facts.get("generic_route") is True
    ctx, _rec, client = await _ctx(spa, {"url": spa + "?id=3"})
    ctx.accounts = (("ana", "ana", {}), ("bruno", "bruno", {}))
    try:
        query_result = await authz.object_access(ctx)
    finally:
        await client.aclose()
    assert not query_result.findings, query_result.summary
    assert query_result.observations[0].facts.get("generic_route") is True


SESSION_RECORDS = '''
def analyse(ctx):
    rows = {}
    for s in ctx.broker.sessions():
        # the record itself, as agent-written tools naturally pass it
        r = ctx.broker.get(ctx.base_url.rstrip("/") + "/api/me", session=s)
        rows[s["label"]] = r["status"]
    return {"summary": "ok", "observations": [{"key": "me", "facts": rows}],
            "findings": []}
'''


async def test_a_session_record_from_sessions_is_accepted_as_its_label(spa):
    """Regression (real Codex runs): tools passed the records ctx.broker.sessions()
    returns as ``session=`` and every call was refused."""
    ctx, rec, client = await _ctx(spa, {})
    try:
        res = await toolsmith.execute(_spec(source=SESSION_RECORDS, id="records"), ctx)
    finally:
        await client.aclose()
    facts = next(o.facts for o in res.observations if o.label == "me")
    assert set(facts) == {"ana", "bruno"}
    assert {r.identity for r in rec.rows if "/api/me" in r.url} == {"ana", "bruno"}


def test_generated_state_effect_requires_engine_owned_before_after_evidence():
    calls = [
        {"op": "http", "outcome": "ok", "method": "POST", "identity": "ana",
         "state_changing": False, "resource_markers": ["item-1"],
         "target": "POST http://t/graphql", "exchange_id": 1,
         "status": 200, "request_fingerprint": "same-query",
         "response_fingerprint": "before"},
        {"op": "http", "outcome": "ok", "method": "PATCH", "identity": "bruno",
         "state_changing": True, "resource_markers": ["item-1"],
         "target": "PATCH http://t/graphql",
         "exchange_id": 2, "status": 200, "response_fingerprint": "action"},
        {"op": "http", "outcome": "ok", "method": "POST", "identity": "ana",
         "state_changing": False, "resource_markers": ["item-1"],
         "target": "POST http://t/graphql", "exchange_id": 3,
         "status": 200, "request_fingerprint": "same-query",
         "response_fingerprint": "after"},
    ]
    evidence, outcome = toolsmith._validated_effect({"effect": {
        "before_exchange_id": 1, "action_exchange_id": 2,
        "after_exchange_id": 3, "impact": "bruno changed ana's item"}}, calls)
    assert outcome == "confirmed_exploitable"
    assert [e.exchange_id for e in evidence] == [1, 2, 3]
    calls[-1]["response_fingerprint"] = "before"
    assert toolsmith._validated_effect({"effect": {
        "before_exchange_id": 1, "action_exchange_id": 2,
        "after_exchange_id": 3, "impact": "claimed"}}, calls)[1] == "no_impact"
    calls[-1]["response_fingerprint"] = "after"
    calls[1]["application_error"] = True
    assert toolsmith._validated_effect({"effect": {
        "before_exchange_id": 1, "action_exchange_id": 2,
        "after_exchange_id": 3, "impact": "claimed"}}, calls)[1] == "inconclusive"


def test_generated_state_effect_cannot_forge_or_skip_guarded_evidence():
    blocked = [{"op": "http", "outcome": "blocked", "method": "DELETE",
                "state_changing": True, "target": "DELETE http://t/api/item"}]
    assert toolsmith._validated_effect({"effect": {
        "before_exchange_id": 91, "action_exchange_id": 92,
        "after_exchange_id": 93, "impact": "claimed"}}, blocked)[1] \
        == "blocked_by_configuration"


MUTATION_ATTEMPTS = '''
def analyse(ctx):
    statuses = {}
    for method in ("PUT", "PATCH", "DELETE"):
        r = ctx.broker.http(ctx.base_url.rstrip("/") + "/api/notes/1", method=method)
        statuses[method] = r["status"]
    statuses["POST-RPC"] = ctx.broker.post(
        ctx.base_url.rstrip("/") + "/graphql",
        json={"query":"mutation { approveChange(id: \\"1\\") { id } }"})["status"]
    return {"summary": "mutations reached target", "observations": [
        {"key": "mutations", "facts": statuses}], "findings": []}
'''


async def test_generated_mutations_reach_target_only_after_operator_opt_in(spa):
    ctx, rec, client = await _ctx(spa, {}, sessions=(),
                                  scope_extra={"activity": {"state_changing": True}})
    try:
        result = await toolsmith.execute(
            _spec(source=MUTATION_ATTEMPTS, id="mutations"), ctx)
    finally:
        await client.aclose()
    facts = next(o.facts for o in result.observations if o.label == "mutations")
    assert set(facts) == {"PUT", "PATCH", "DELETE", "POST-RPC"}
    assert {row.method for row in rec.rows if row.url.endswith("/api/notes/1")} \
        == {"PUT", "PATCH", "DELETE"}
    assert any(row.method == "POST" and row.url.endswith("/graphql")
               for row in rec.rows)


async def test_replay_does_not_confirm_same_title_without_effect(monkeypatch):
    from types import SimpleNamespace
    from src.greybox_web.tools import FindingSpec, ToolResult

    async def repeated(_spec, _ctx):
        return ToolResult(summary="same assertion", findings=[FindingSpec(
            check_id="tool.state", detail="x", title="Claimed state bypass",
            severity="high", confidence="low", description="claimed", url="http://t/",
            exploitability_outcome="no_impact")])

    monkeypatch.setattr(toolsmith, "execute", repeated)
    ctx = SimpleNamespace(params={"title": "Claimed state bypass",
                                  "requires_effect": True})
    result = await toolsmith.replay({"id": "tool.state"}, ctx)
    assert not result.confirmed and result.outcome == "no_impact"
    missing = SimpleNamespace(params={"requires_effect": False})
    result = await toolsmith.replay({"id": "tool.state"}, missing)
    assert not result.confirmed and result.outcome == "inconclusive"


async def test_state_effect_verifier_reads_persisted_postcondition_without_replaying_tool(monkeypatch):
    from types import SimpleNamespace

    class Http:
        async def request(self, *args, **kwargs):
            return SimpleNamespace(status=200, text='{"state":"APPROVED"}', exchange_ids=[44])

    expected = __import__("hashlib").sha256(b'200\n{"state":"APPROVED"}').hexdigest()
    ctx = SimpleNamespace(http=Http(), params={
        "title": "Member approved change", "requires_effect": True,
        "effect_probe": {"method": "POST", "url": "http://t/graphql",
                         "body": "query after", "content_type": "application/json",
                         "session": "member", "expected_fingerprint": expected}})
    result = await toolsmith.replay({"id": "tool.workflow"}, ctx)
    assert result.confirmed and result.outcome == "confirmed_exploitable"
    assert result.exchange_ids == [44]


def test_generated_effect_accepts_list_baseline_containing_action_resource():
    from src.greybox_web.tools import toolsmith
    calls = [
        {"op":"http", "outcome":"ok", "state_changing":False,
         "resource_markers":["workspace-1"], "response_resource_markers":["workspace-1", "item-9"],
         "target":"POST http://t/graphql", "identity":"owner", "exchange_id":1,
         "status":200, "request_fingerprint":"same-list", "response_fingerprint":"before"},
        {"op":"http", "outcome":"ok", "state_changing":True,
         "resource_markers":["item-9"], "response_resource_markers":["item-9"],
         "target":"POST http://t/graphql", "identity":"member", "exchange_id":2,
         "status":200, "request_fingerprint":"action", "response_fingerprint":"action",
         "application_error":False},
        {"op":"http", "outcome":"ok", "state_changing":False,
         "resource_markers":["workspace-1"], "response_resource_markers":["workspace-1", "item-9"],
         "target":"POST http://t/graphql", "identity":"owner", "exchange_id":3,
         "status":200, "request_fingerprint":"same-list", "response_fingerprint":"after"},
    ]
    _, outcome = toolsmith._validated_effect({"effect":{"before_exchange_id":1,
        "action_exchange_id":2,"after_exchange_id":3,"impact":"item state changed"}}, calls)
    assert outcome == "confirmed_exploitable"


def test_generated_effect_recovers_from_incorrect_model_exchange_reference():
    from src.greybox_web.tools import toolsmith
    calls = [
        {"op":"http","outcome":"ok","state_changing":False,"resource_markers":["item-7"],
         "target":"POST http://t/graphql","identity":"owner","exchange_id":11,"status":200,
         "request_fingerprint":"read","response_fingerprint":"pending"},
        {"op":"http","outcome":"ok","state_changing":True,"resource_markers":["item-7"],
         "target":"POST http://t/graphql","identity":"member","exchange_id":12,"status":200,
         "request_fingerprint":"write","response_fingerprint":"approved","application_error":False},
        {"op":"http","outcome":"ok","state_changing":False,"resource_markers":["item-7"],
         "target":"POST http://t/graphql","identity":"owner","exchange_id":13,"status":200,
         "request_fingerprint":"read","response_fingerprint":"approved"},
    ]
    evidence, outcome = toolsmith._validated_effect({"effect":{"before_exchange_id":999,
        "action_exchange_id":12,"after_exchange_id":13,"impact":"approved"}}, calls)
    assert outcome == "confirmed_exploitable" and [item.exchange_id for item in evidence] == [11,12,13]
