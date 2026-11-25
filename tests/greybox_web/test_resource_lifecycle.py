from __future__ import annotations

import uuid

import pytest

from src.greybox_web import resource_lifecycle as lifecycle
from src.greybox_web import secmodel as sm
from src.greybox_web.graph import GraphTx
from src.greybox_web.models import GreyboxHttpExchange, GreyboxRun, GreyboxTarget
from src.greybox_web.scope import PolicyContext, ScopePolicy, build_scope


@pytest.fixture
async def run(session_maker):
    owner, run_id, target_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    scope = {"allowed_hosts": ["target.test"], "allowed_schemes": ["http"],
             "allowed_ports": [80]}
    async with session_maker() as session:
        session.add(GreyboxTarget(id=target_id, owner_id=owner, name="target",
                                  base_url="http://target.test/", scope=scope,
                                  limits={"max_requests": 100}, checks=None))
        await session.flush()
        session.add(GreyboxRun(id=run_id, target_id=target_id, owner_id=owner,
                               base_url="http://target.test/", scope=scope,
                               limits={"max_requests": 100}, checks=[], status="running"))
        session.add(GreyboxHttpExchange(run_id=run_id, tool="discovery.crawl",
                                        method="GET", url="http://target.test/items/1",
                                        path="/items/1", status_code=200,
                                        identity="owner", request_headers=[],
                                        response_headers=[]))
        await session.commit()
    return run_id


async def test_resource_claim_requires_evidence_or_operator_policy(session_maker, run):
    ref = sm.EntityRef("resource", "pending item")
    async with session_maker() as session:
        declared = await lifecycle.declare(session, GraphTx(session, run),
            lifecycle.LifecycleDeclaration(
                resource=ref, mutability="mutable", disposal="disposable",
                reset="supported", basis="stated"))
        await session.commit()
    assert declared["disposal"] == "unknown"
    async with session_maker() as session:
        result = await lifecycle.inspect(session, run, ref.key)
    assert not result.suitable and result.reason == "not_evidence_backed_disposable"


async def test_operator_environment_makes_discovered_resources_suitable(session_maker, run):
    scope = ScopePolicy(("target.test",), ("http",), (80,), state_changing=True,
                        resource_lifecycle="disposable_resettable")
    ref = sm.EntityRef("resource", "pending item")
    async with session_maker() as session:
        await lifecycle.declare(session, GraphTx(session, run),
                                lifecycle.from_operator_policy(scope, ref))
        await session.commit()
        first = await lifecycle.reserve(session, run, ref.key, "investigation:one")
        other = await lifecycle.reserve(session, run, ref.key, "investigation:two")
        changed = await lifecycle.transition(session, run, ref.key, state="modified",
            investigation_ref="investigation:one", operation_ref="operation:approve",
            evidence=("http://target.test/items/1",))
        await session.commit()
    assert first.suitable and not other.suitable
    assert changed.lifecycle["history"][0]["evidence"]
    async with session_maker() as session:
        reusable = await lifecycle.inspect(session, run, ref.key)
        reset = await lifecycle.transition(session, run, ref.key, state="available",
            investigation_ref="investigation:one", operation_ref="operation:reset")
        await session.commit()
    assert reusable.suitable and reusable.lifecycle["reset"] == "supported"
    assert reset.reason == "available"


def test_lifecycle_scope_roundtrip_and_unknown_default():
    normalised, default, errors = build_scope("https://target.test", None, PolicyContext(allow_private=True))
    assert not errors and normalised == "https://target.test/"
    assert default.resource_lifecycle == "unknown"
    _, opted, errors = build_scope("https://target.test", {"activity": {
        "state_changing": True, "resource_lifecycle": "disposable_resettable"}}, PolicyContext(allow_private=True))
    assert not errors and opted.resource_lifecycle == "disposable_resettable"
    assert ScopePolicy.from_dict(opted.to_dict()).resource_lifecycle == "disposable_resettable"
