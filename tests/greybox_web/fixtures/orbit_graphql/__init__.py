"""Orbit Change Control: synthetic GraphQL/RPC authorization fixture."""
from __future__ import annotations

import copy
import json
import re
import secrets
import threading
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

USERS = {
    "aria": {"password": "Orbit-Aria-6w!Qp2", "name": "Aria Chen", "role": "approver", "workspace": "orbit"},
    "milo": {"password": "Orbit-Milo-8r#Ks4", "name": "Milo Novak", "role": "member", "workspace": "orbit"},
    "sana": {"password": "Orbit-Sana-3t$Lv9", "name": "Sana Idris", "role": "approver", "workspace": "nova"},
}
WORKSPACES = {"orbit": {"id": "orbit", "name": "Orbit Operations"}, "nova": {"id": "nova", "name": "Nova Research"}}
INITIAL_CHANGES = {
    "chg-orbit-42": {"id": "chg-orbit-42", "workspaceId": "orbit", "title": "Rotate synthetic on-call schedule", "state": "PENDING", "requestedBy": "aria", "approvedBy": None, "proofMarker": None, "version": 1},
    "chg-orbit-51": {"id": "chg-orbit-51", "workspaceId": "orbit", "title": "Refresh staging banner", "state": "PENDING", "requestedBy": "milo", "approvedBy": None, "proofMarker": None, "version": 1},
    "chg-nova-17": {"id": "chg-nova-17", "workspaceId": "nova", "title": "Rotate synthetic research schedule", "state": "PENDING", "requestedBy": "sana", "approvedBy": None, "proofMarker": None, "version": 1},
}
SDL = '''
directive @requiresRole(role: String!) on FIELD_DEFINITION
type User { username: ID!, name: String!, role: String!, workspaceId: ID! }
type Workspace { id: ID!, name: String!, members: [User!]! }
type ChangeRequest { id: ID!, workspaceId: ID!, title: String!, state: String!, requestedBy: ID!, approvedBy: ID, proofMarker: String, version: Int! }
type AuditEvent { id: ID!, workspaceId: ID!, action: String!, changeId: ID!, actor: ID!, proofMarker: String }
type Query { me: User!, workspace(id: ID!): Workspace, changeRequests(workspaceId: ID!): [ChangeRequest!]!, changeRequest(id: ID!): ChangeRequest, auditEvents(workspaceId: ID!): [AuditEvent!]! }
type Mutation { approveChange(id: ID!, proofMarker: String): ChangeRequest! @requiresRole(role: "approver"), cancelChange(id: ID!): ChangeRequest!, updateWorkspaceName(id: ID!, name: String!): Workspace! @requiresRole(role: "approver") }
'''.strip()


def _headers(response: Response) -> Response:
    response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"})
    return response


def _json(body, status=200):
    return _headers(JSONResponse(body, status_code=status))


def _gql_error(message, code):
    return _json({"errors": [{"message": message, "extensions": {"code": code}}], "data": None})


def _read_arg(query: str, name: str, variables: dict):
    if name in variables:
        return variables[name]
    found = re.search(rf"\b{name}\s*:\s*(?:\$(\w+)|\"([^\"]*)\"|([^,\s)]+))", query)
    if not found:
        return None
    variable, string, literal = found.groups()
    return variables.get(variable) if variable else string if string is not None else literal


def create_app() -> Starlette:
    changes = copy.deepcopy(INITIAL_CHANGES)
    workspaces = copy.deepcopy(WORKSPACES)
    events: list[dict] = []
    tokens: dict[str, str] = {}

    def current_user(request: Request):
        auth = request.headers.get("authorization", "")
        return tokens.get(auth[7:]) if auth.startswith("Bearer ") else None

    async def index(_request: Request):
        return _json({"service": "Orbit Change Control", "protocols": ["GraphQL", "JSON-RPC 2.0"], "_links": {"graphql": "/graphql", "schema": "/schema.graphql", "rpc": "/rpc"}, "authentication": "Call JSON-RPC auth.login, then use its bearer token for GraphQL"})

    async def schema(_request: Request):
        return _headers(PlainTextResponse(SDL))

    async def rpc(request: Request):
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return _json({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})
        rpc_id = body.get("id")
        if body.get("jsonrpc") != "2.0" or body.get("method") != "auth.login":
            return _json({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": rpc_id})
        params = body.get("params") or {}
        user = USERS.get(params.get("username"))
        if not user or user["password"] != params.get("password"):
            return _json({"jsonrpc": "2.0", "error": {"code": 401, "message": "Invalid credentials"}, "id": rpc_id})
        token = secrets.token_urlsafe(24)
        tokens[token] = params["username"]
        return _json({"jsonrpc": "2.0", "result": {"accessToken": token, "tokenType": "Bearer", "expiresIn": 3600}, "id": rpc_id})

    async def graphql(request: Request):
        if request.method == "GET":
            return _headers(HTMLResponse("<h1>Orbit GraphQL</h1><p>POST queries here; introspection is enabled. <a href='/schema.graphql'>Schema</a></p>"))
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            return _gql_error("Invalid JSON", "BAD_REQUEST")
        query, variables = body.get("query") or "", body.get("variables") or {}
        if "__schema" in query or "__type" in query:
            return _json({"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [{"name": name} for name in ("Query", "Mutation", "ChangeRequest", "AuditEvent")], "directives": [{"name": "requiresRole", "locations": ["FIELD_DEFINITION"]}]}}})
        username = current_user(request)
        if not username:
            return _gql_error("Bearer token required", "UNAUTHENTICATED")
        user = USERS[username]
        if "updateWorkspaceName" in query:
            workspace_id = _read_arg(query, "id", variables)
            if workspace_id != user["workspace"] or user["role"] != "approver":
                return _gql_error("Approver role required", "FORBIDDEN")
            workspaces[workspace_id]["name"] = _read_arg(query, "name", variables)
            return _json({"data": {"updateWorkspaceName": workspaces[workspace_id]}})
        if "approveChange" in query:
            change = changes.get(_read_arg(query, "id", variables))
            if not change or change["workspaceId"] != user["workspace"]:
                return _gql_error("Change not found", "NOT_FOUND")
            if change["state"] != "PENDING":
                return _gql_error("Change is not pending", "CONFLICT")
            change.update(state="APPROVED", approvedBy=username, proofMarker=_read_arg(query, "proofMarker", variables), version=change["version"] + 1)
            events.append({"id": f"evt-{len(events) + 1}", "workspaceId": change["workspaceId"], "action": "change.approved", "changeId": change["id"], "actor": username, "proofMarker": change["proofMarker"]})
            return _json({"data": {"approveChange": change}})
        if "cancelChange" in query:
            change = changes.get(_read_arg(query, "id", variables))
            if not change or change["workspaceId"] != user["workspace"]:
                return _gql_error("Change not found", "NOT_FOUND")
            if change["requestedBy"] != username and user["role"] != "approver":
                return _gql_error("Requester or approver required", "FORBIDDEN")
            if change["state"] != "PENDING":
                return _gql_error("Change is not pending", "CONFLICT")
            change.update(state="CANCELLED", version=change["version"] + 1)
            return _json({"data": {"cancelChange": change}})
        if "auditEvents" in query:
            workspace_id = _read_arg(query, "workspaceId", variables)
            if workspace_id != user["workspace"] or user["role"] != "approver":
                return _gql_error("Approver role required", "FORBIDDEN")
            return _json({"data": {"auditEvents": [event for event in events if event["workspaceId"] == workspace_id]}})
        if "changeRequests" in query:
            workspace_id = _read_arg(query, "workspaceId", variables)
            if workspace_id != user["workspace"]:
                return _gql_error("Workspace not found", "NOT_FOUND")
            return _json({"data": {"changeRequests": [change for change in changes.values() if change["workspaceId"] == workspace_id]}})
        if "changeRequest" in query:
            change = changes.get(_read_arg(query, "id", variables))
            return _json({"data": {"changeRequest": change if change and change["workspaceId"] == user["workspace"] else None}})
        if re.search(r"\bworkspace\s*\(", query):
            workspace_id = _read_arg(query, "id", variables)
            if workspace_id != user["workspace"]:
                return _gql_error("Workspace not found", "NOT_FOUND")
            item = {**workspaces[workspace_id], "members": [{"username": name, "name": account["name"], "role": account["role"], "workspaceId": account["workspace"]} for name, account in USERS.items() if account["workspace"] == workspace_id]}
            return _json({"data": {"workspace": item}})
        if "me" in query:
            return _json({"data": {"me": {"username": username, "name": user["name"], "role": user["role"], "workspaceId": user["workspace"]}}})
        return _gql_error("Unknown operation", "BAD_USER_INPUT")

    return Starlette(routes=[Route("/", index), Route("/schema.graphql", schema), Route("/rpc", rpc, methods=["POST"]), Route("/graphql", graphql, methods=["GET", "POST"])])


def serve(port: int = 0, host: str = "127.0.0.1"):
    import uvicorn
    server = uvicorn.Server(uvicorn.Config(create_app(), host=host, port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not server.started and thread.is_alive() and time.time() < deadline:
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("Orbit GraphQL fixture did not start")
    socket = next(iter(server.servers)).sockets[0]
    return server, f"http://{host}:{socket.getsockname()[1]}"
