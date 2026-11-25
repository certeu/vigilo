from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from tests.greybox_web.fixtures import orbit_graphql

HERE = Path(orbit_graphql.__file__).parent
ASSESSMENT = json.loads((HERE / "assessment.json").read_text())
GT = json.loads((HERE / "ground_truth.json").read_text())


@pytest.fixture()
def api():
    server, url = orbit_graphql.serve(0)
    try:
        yield url
    finally:
        server.should_exit = True


def client(url, username=None):
    session = httpx.Client(base_url=url, trust_env=False)
    if username:
        password = next(item["password"] for item in GT["accounts"] if item["user"] == username)
        response = session.post("/rpc", json={"jsonrpc": "2.0", "method": "auth.login", "params": {"username": username, "password": password}, "id": 1})
        assert response.status_code == 200 and "result" in response.json()
        session.headers["Authorization"] = "Bearer " + response.json()["result"]["accessToken"]
    return session


def gql(session, query, variables=None):
    response = session.post("/graphql", json={"query": query, "variables": variables or {}})
    assert response.status_code == 200
    return response.json()


def test_manifests_and_protocol_discovery(api):
    assert [item["id"] for item in GT["seeded"]] == ["O1"]
    assert ASSESSMENT["scope"]["activity"]["state_changing"] is True
    assert [(item["user"], item["password"]) for item in ASSESSMENT["accounts"]] == [(item["user"], item["password"]) for item in GT["accounts"]]
    agent_text = json.dumps(ASSESSMENT).lower()
    for clue in ("approver-only", "approvechange", "chg-orbit-42", "bfla", "o1"):
        assert clue not in agent_text
    assert client(api).get("/").json()["_links"] == {"graphql": "/graphql", "schema": "/schema.graphql", "rpc": "/rpc"}
    schema = client(api).get("/schema.graphql").text
    assert 'approveChange(id: ID!, proofMarker: String)' in schema and '@requiresRole(role: "approver")' in schema
    assert gql(client(api), "query { __schema { mutationType { name } } }")["data"]["__schema"]["mutationType"]["name"] == "Mutation"


def test_seeded_member_can_approve_and_approver_verifies(api):
    milo, aria = client(api, "milo"), client(api, "aria")
    before = gql(milo, "query($id:ID!){ changeRequest(id:$id){ id state approvedBy version } }", {"id": "chg-orbit-42"})["data"]["changeRequest"]
    assert before["state"] == "PENDING" and before["approvedBy"] is None
    proof = gql(milo, "mutation($id:ID!,$proofMarker:String){ approveChange(id:$id,proofMarker:$proofMarker){ id state approvedBy proofMarker version } }", {"id": "chg-orbit-42", "proofMarker": "vigilo-o1-proof"})["data"]["approveChange"]
    assert proof["state"] == "APPROVED" and proof["approvedBy"] == "milo" and proof["proofMarker"] == "vigilo-o1-proof" and proof["version"] == 2
    events = gql(aria, "query($workspaceId:ID!){ auditEvents(workspaceId:$workspaceId){ action changeId actor proofMarker } }", {"workspaceId": "orbit"})["data"]["auditEvents"]
    assert events[-1]["actor"] == "milo" and events[-1]["proofMarker"] == "vigilo-o1-proof"


def test_positive_and_negative_controls(api):
    anon, aria, milo, sana = client(api), client(api, "aria"), client(api, "milo"), client(api, "sana")
    assert gql(anon, "query { me { username } }")["errors"][0]["extensions"]["code"] == "UNAUTHENTICATED"
    assert gql(milo, 'mutation { updateWorkspaceName(id:"orbit",name:"x"){ id } }')["errors"][0]["extensions"]["code"] == "FORBIDDEN"
    assert gql(milo, 'mutation { cancelChange(id:"chg-orbit-42"){ id } }')["errors"][0]["extensions"]["code"] == "FORBIDDEN"
    assert gql(milo, 'query { changeRequest(id:"chg-nova-17"){ id } }')["data"]["changeRequest"] is None
    assert gql(sana, 'mutation { approveChange(id:"chg-orbit-42"){ id } }')["errors"][0]["extensions"]["code"] == "NOT_FOUND"
    assert gql(aria, 'mutation { approveChange(id:"chg-orbit-42",proofMarker:"role-control"){ id state approvedBy } }')["data"]["approveChange"]["approvedBy"] == "aria"


def test_each_server_has_disposable_fresh_state(api):
    gql(client(api, "milo"), 'mutation { approveChange(id:"chg-orbit-42"){ id state } }')
    server, fresh_url = orbit_graphql.serve(0)
    try:
        fresh = gql(client(fresh_url, "aria"), 'query { changeRequest(id:"chg-orbit-42"){ state version } }')["data"]["changeRequest"]
        assert fresh["state"] == "PENDING" and fresh["version"] == 1
    finally:
        server.should_exit = True


def test_jsonrpc_login_hint_survives_credential_ingestion():
    from src.webapi.credential_guard import CredentialRejected, parse_login_secret

    secret = parse_login_secret('{"user":"aria","password":"secret","body":"jsonrpc"}')
    assert secret["body"] == "jsonrpc"
    with pytest.raises(CredentialRejected):
        parse_login_secret('{"user":"aria","password":"secret","body":"raw"}')


async def test_brokered_tool_demonstrates_and_reverifies_workflow_impact(api):
    from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy
    from src.greybox_web.scope import ScopePolicy
    from src.greybox_web.tools import ToolContext, toolsmith
    from tests.greybox_web.test_policy_network import Rec

    port = int(api.rsplit(":", 1)[1].rstrip("/"))
    scope = ScopePolicy(("127.0.0.1",), ("http",), (port,),
                        state_changing=True, allow_auth_testing=True)
    guarded = GuardedHttpClient(scope=scope, budget=Budget(30, 30),
                                policy=NetPolicy(allow_private=True), recorder=Rec())
    sessions = {}
    for username in ("aria", "milo"):
        password = next(item["password"] for item in GT["accounts"] if item["user"] == username)
        login = client(api).post("/rpc", json={"jsonrpc":"2.0","method":"auth.login","params":{"username":username,"password":password},"id":1}).json()
        sessions[username] = "Bearer " + login["result"]["accessToken"]
        guarded.establish_session(username, None, sessions[username])
    url = api.rstrip("/") + "/graphql"
    source = '''
import json
def analyse(ctx):
    target, item = ctx.url, "chg-orbit-42"
    query = "query($id:ID!){changeRequest(id:$id){id state approvedBy proofMarker version}}"
    before = ctx.broker.post(target, json={"query":query,"variables":{"id":item}}, session="aria")
    action = ctx.broker.post(target, json={"query":"mutation($id:ID!,$proofMarker:String){approveChange(id:$id,proofMarker:$proofMarker){id state approvedBy proofMarker}}","variables":{"id":item,"proofMarker":"vigilo-controlled-proof"}}, session="milo")
    after = ctx.broker.post(target, json={"query":query,"variables":{"id":item}}, session="aria")
    changed = json.loads(after["body"])["data"]["changeRequest"]
    return {"summary":"member approval test","observations":[],"findings":[{"title":"Member approved approver-only change","severity":"high","description":"A member changed a pending request to approved.","class":"vulnerability","affected":target,"remediation":{"summary":"Enforce approver role in the resolver."},"effect":{"before_exchange_id":before["exchange_id"],"action_exchange_id":action["exchange_id"],"after_exchange_id":after["exchange_id"],"impact":"State is %s and approvedBy is %s" % (changed["state"],changed["approvedBy"])}}]}
'''
    raw = {"id":"orbit-workflow-proof","title":"Orbit workflow proof",
           "purpose":"Compare an approver-observed object around a controlled member mutation",
           "capabilities":["http"],"max_calls":8,"source":source}
    spec, errors = toolsmith.check_spec(raw)
    assert spec is not None, errors
    ctx = ToolContext(http=guarded.bind("tool.orbit-workflow-proof"), base_url=api,
                      scope=scope, limits={}, params={"url":url})
    try:
        result = await toolsmith.execute(spec, ctx)
        finding = result.findings[0]
        assert finding.exploitability_outcome == "confirmed_exploitable"
        ctx.params = finding.verify
        verified = await toolsmith.replay(spec, ctx)
        assert verified.confirmed and verified.outcome == "confirmed_exploitable"
    finally:
        await guarded.aclose()

async def test_guarded_generic_operation_invoker_executes_graphql_semantics(api):
    from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy
    from src.greybox_web.scope import ScopePolicy
    from src.greybox_web.tools import ToolContext, apiops
    from tests.greybox_web.test_policy_network import Rec

    port = int(api.rsplit(":", 1)[1].rstrip("/"))
    scope = ScopePolicy(("127.0.0.1",), ("http",), (port,),
                        state_changing=True, allow_auth_testing=True)
    guarded = GuardedHttpClient(scope=scope, budget=Budget(12, 15),
                                policy=NetPolicy(allow_private=True), recorder=Rec())
    for username in ("aria", "milo"):
        password = next(item["password"] for item in GT["accounts"] if item["user"] == username)
        login = client(api).post("/rpc", json={"jsonrpc":"2.0","method":"auth.login","params":{"username":username,"password":password},"id":1}).json()
        guarded.establish_session(username, None, "Bearer " + login["result"]["accessToken"])
    operation = {
        "id": "graphql:approveChange", "protocol": "graphql", "endpoint": "/graphql",
        "operation_id": "approveChange", "method": "MUTATION",
        "parameters": [{"name": "id", "required": True, "schema": {"type": "string"}},
                       {"name": "proofMarker", "schema": {"type": "string"}}],
        "input_fields": ["id", "proofMarker"], "output_fields": ["ChangeRequest!"],
        "possible_state_effects": ["approval transition"],
        "protocol_document": {"kind": "mutation", "variable_types": {"id": "ID!", "proofMarker": "String"}, "selection_fields": ["id", "state", "approvedBy", "proofMarker"]},
    }
    ctx = ToolContext(http=guarded.bind("api.operation.invoke"), base_url=api,
                      scope=scope, limits={}, params={"operation_ref": operation,
                      "identity":"milo", "arguments":{"id":"chg-orbit-42", "proofMarker":"generic-operation-proof"}})
    try:
        result = await apiops.invoke(ctx)
        assert result.counts == {"attempted": 1, "succeeded": 1}
        changed = gql(client(api, "aria"), 'query { changeRequest(id:"chg-orbit-42"){ state approvedBy proofMarker } }')["data"]["changeRequest"]
        assert changed["state"] == "APPROVED" and changed["approvedBy"] == "milo" and changed["proofMarker"] == "generic-operation-proof"
    finally:
        await guarded.aclose()
