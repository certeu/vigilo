"""Reusable API operation and pagination capability regressions."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
import pytest

from src.greybox_web import tools as gb_tools
from src.greybox_web.netguard import Budget, GuardedHttpClient, NetPolicy, NullRecorder
from src.greybox_web.operations import extract_operations
from src.greybox_web.pagination import decode_embedded_cursor, response_page
from src.greybox_web.scope import ScopePolicy
from src.greybox_web.tools import ToolContext, apiops
from tests.greybox_web.conftest import FAST_LIMITS
from tests.greybox_web.fixtures import ledgerline_api, orbit_graphql


@asynccontextmanager
async def _context(base_url, params, sessions=None):
    scope = ScopePolicy.from_dict({"allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
        "allowed_ports": [urlsplit(base_url).port], "path_prefixes": ["/"]})
    client = GuardedHttpClient(scope=scope, budget=Budget(200, 300),
        policy=NetPolicy(allow_private=True), rate_limit_rps=50, request_timeout_s=5,
        recorder=NullRecorder())
    if sessions:
        for label, headers in sessions.items():
            client.bind("setup").establish_session(label, None, headers.get("Authorization"))
    try:
        yield ToolContext(http=client.bind("test"), base_url=base_url, scope=scope,
                          limits=dict(FAST_LIMITS), params=params), client
    finally:
        await client.aclose()


def test_extracts_role_security_parameters_and_state_effects():
    operations = extract_operations(json.dumps(ledgerline_api.OPENAPI), "/openapi.json")
    audit = next(operation for operation in operations if operation.operation_id == "listAuditEvents")
    assert audit.documented_roles == ("admin",)
    assert audit.documented_security == ("bearerAuth",)
    assert {parameter["name"] for parameter in audit.parameters} >= {"org_id"}
    assert audit.possible_state_effects == ()
    create = next(operation for operation in operations if operation.operation_id == "createInvoice")
    assert create.method == "POST" and create.possible_state_effects == ("unspecified write",)
    assert "org_id" in create.input_fields


def test_extracts_graphql_queries_mutations_and_roles():
    operations = extract_operations(orbit_graphql.SDL, "/schema.graphql")
    names = {operation.operation_id for operation in operations}
    assert {"changeRequest", "approveChange", "cancelChange", "updateWorkspaceName"} <= names
    approve = next(operation for operation in operations if operation.operation_id == "approveChange")
    assert approve.documented_roles == ("approver",)
    assert approve.method == "MUTATION" and {"id", "proofMarker"} <= set(approve.input_fields)


def test_extracts_openrpc_method_parameters():
    document = {"openrpc": "1.2.6", "methods": [{"name": "admin.rotateKey",
        "params": [{"name": "tenantId", "required": True}], "x-required-role": "admin"}]}
    operation = extract_operations(json.dumps(document), "/openrpc.json")[0]
    assert operation.protocol == "json-rpc" and operation.documented_roles == ("admin",)
    assert operation.possible_state_effects and operation.input_fields == ("tenantId",)


def test_cursor_decode_is_evidence_not_interpretation():
    import base64
    cursor = base64.urlsafe_b64encode(json.dumps({"org": "org_7Hq2", "offset": 10}, separators=(",", ":")).encode()).decode().rstrip("=")
    assert decode_embedded_cursor(cursor) == {"org": "org_7Hq2", "offset": 10}
    assert decode_embedded_cursor("not-a-cursor") is None
    assert response_page({"data": [1, 2], "next_cursor": cursor, "has_more": True}) == (2, cursor, True)


@pytest.fixture(scope="module")
def services():
    ledger, ledger_url = ledgerline_api.serve(0)
    orbit, orbit_url = orbit_graphql.serve(0)
    yield ledger_url, orbit_url
    ledger.should_exit = orbit.should_exit = True


async def test_schema_inventory_and_paginate_use_guarded_requests(services):
    ledger_url, orbit_url = services
    async with _context(ledger_url, {"url": ledger_url.rstrip("/") + "/openapi.json"}) as (ctx, client):
        result = await apiops.inventory(ctx)
        assert result.counts["operations"] >= 10
        audit = next(observation for observation in result.observations
                     if observation.facts.get("operation_id") == "listAuditEvents")
        assert audit.facts["documented_roles"] == ["admin"]
        assert {urlsplit(item.url).hostname for item in client.recorder.items} == {"127.0.0.1"}
    async with _context(ledger_url, {"url": ledger_url.rstrip("/") + "/openapi.json"},) as (ctx, _):
        assert gb_tools.get("api.operations") is not None
    async with _context(orbit_url, {"url": orbit_url.rstrip("/") + "/schema.graphql"}) as (ctx, _):
        result = await apiops.inventory(ctx)
        assert any(observation.facts.get("operation_id") == "approveChange"
                   for observation in result.observations)
    password = ledgerline_api.ACCOUNTS["nadia"]["password"]
    with httpx.Client(base_url=ledger_url, trust_env=False) as login_client:
        login = login_client.post("/v1/auth/token", json={"username": "nadia", "password": password}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    async with _context(ledger_url, {"url": ledger_url.rstrip("/") + "/v1/orgs/org_7Hq2/invoices",
                         "identity": "admin", "max_pages": 5}, sessions={"admin": headers}) as (ctx, _):
        result = await apiops.paginate(ctx)
        assert result.counts == {"pages": 4, "items": 34}
        facts = result.observations[0].facts
        assert facts["stop_reason"] == "server indicated completion"
        assert facts["decoded_cursors"][0]["values"]["org"] == "org_7Hq2"
    async with _context(ledger_url, {"url": ledger_url.rstrip("/") + "/v1/orgs/org_7Hq2/audit-events",
                         "identities": ["anon", "admin"], "operation_id": "listAuditEvents",
                         "expected_role": "admin", "resource_scope": "org_7Hq2"},
                        sessions={"admin": headers}) as (ctx, _):
        result = await apiops.compare_access(ctx)
        assert result.counts == {"identities": 2, "served": 1}
        facts = result.observations[0].facts
        assert facts["expected_access"] == {"role": "admin", "basis": "documented"}
        assert {item["identity"]: item["status"] for item in facts["matrix"]} == {"anon": 401, "admin": 200}


async def test_inventory_preserves_operation_identity_and_builds_actionable_investigations(services):
    _, orbit_url = services
    async with _context(orbit_url, {"url": orbit_url.rstrip("/") + "/schema.graphql"}) as (ctx, _):
        result = await apiops.inventory(ctx)
    from src.greybox_web.investigation import discover_operations, investigations_from_operations
    facts = [item.facts for item in result.observations]
    assert len({item["id"] for item in facts}) == len(facts)
    approve = next(item for item in facts if item["operation_id"] == "approveChange")
    assert approve["identity"] == "approveChange"
    assert approve["observed_as"] == "anon"
    assert approve["evidence"]
    operations = discover_operations(facts)
    investigations = investigations_from_operations(operations, available_identities=["requester"])
    approve_investigation = next(item for item in investigations
                                 if item.operation_id == approve["id"])
    assert approve_investigation.ready
    assert approve_investigation.final_outcome is None
    assert approve_investigation.available_tools == ("tool.create", "tool.run")
    assert approve_investigation.planned_verification["operation"]["input"]["fields"]


async def test_persisted_operation_observation_reappears_as_investigation(
        session_maker, services):
    import uuid
    from src.greybox_web.exploration.knowledge import KnowledgeInputs, build
    from src.greybox_web.models import GreyboxGraphNode, GreyboxRun, GreyboxTarget

    _, orbit_url = services
    async with _context(orbit_url, {"url": orbit_url.rstrip("/") + "/schema.graphql"}) as (ctx, _):
        result = await apiops.inventory(ctx)
    approval = next(item for item in result.observations
                    if item.facts["operation_id"] == "approveChange")
    owner_id, target_id, run_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    scope = {"allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
             "allowed_ports": [urlsplit(orbit_url).port]}
    async with session_maker() as session:
        session.add(GreyboxTarget(id=target_id, owner_id=owner_id, name="orbit",
                                  base_url=orbit_url, scope=scope, limits={}, checks=[]))
        await session.flush()
        session.add(GreyboxRun(id=run_id, target_id=target_id, owner_id=owner_id,
                               base_url=orbit_url, scope=scope, limits={}, checks=[],
                               status="running", idempotency_key="operation-persistence"))
        session.add(GreyboxGraphNode(run_id=run_id, kind="observation", key=approval.key,
                                     label=approval.label, status="recorded", version=1,
                                     data={"facts": approval.facts, "url": approval.url}))
        await session.commit()
    async with session_maker() as resumed:
        knowledge = await build(resumed, run_id, KnowledgeInputs(
            sessions=[{"label": "requester"}, {"label": "approver"}]))
    operation = next(item for item in knowledge["operations"]
                     if item["id"] == approval.facts["id"])
    investigation = next(item for item in knowledge["investigations"]["active"]
                         if item["operation_id"] == operation["id"])
    assert investigation["status"] == "ready"
    assert investigation["progress"]["source"] == "persisted operation observation"
    assert investigation["required_observations"] == ["per-identity response",
                                                        "independent effect observation"]
    async with session_maker() as resumed:
        exhausted = await build(resumed, run_id, KnowledgeInputs(
            sessions=[{"label": "requester"}], agent={"calls_left": 0}))
    unresolved = next(item for item in exhausted["investigations"]["active"]
                      if item["operation_id"] == operation["id"])
    assert unresolved["status"] == "budget_exhausted"


async def test_inventory_follows_runtime_document_schema_link(services):
    _, orbit_url = services
    async with _context(orbit_url, {"url": orbit_url.rstrip("/") + "/graphql"}) as (ctx, _):
        result = await apiops.inventory(ctx)
    assert result.counts["operations"] > 0
    assert any(item.facts.get("operation_id") == "approveChange"
               and item.facts.get("documented_roles") == ["approver"]
               for item in result.observations)
