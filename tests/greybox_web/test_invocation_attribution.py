"""Investigation progress attribution from persisted operation invocations."""
from __future__ import annotations

import uuid

from src.greybox_web.exploration.knowledge import KnowledgeInputs, build
from src.greybox_web.models import GreyboxGraphNode, GreyboxRun, GreyboxTarget


def _operation(identifier: str, *, state_changing: bool = True) -> dict:
    return {
        "id": identifier,
        "operation_id": identifier,
        "protocol": "graphql",
        "identity": f"mutation {identifier}" if state_changing else f"query {identifier}",
        "endpoint": "/graphql",
        "method": "MUTATION" if state_changing else "QUERY",
        "documented_roles": ["approver"],
        "state_effects": ["approval state changes"] if state_changing else [],
        "input_fields": ["id"],
    }


async def _seed(session_maker, *, invocation: dict | None):
    owner_id, target_id, run_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    operation = _operation("op-approve")
    scope = {"allowed_hosts": ["target.test"], "allowed_schemes": ["http"],
             "allowed_ports": [80], "path_prefixes": ["/"]}
    async with session_maker() as session:
        session.add(GreyboxTarget(id=target_id, owner_id=owner_id, name="target",
                                  base_url="http://target.test", scope=scope, limits={}, checks=[]))
        await session.flush()
        session.add(GreyboxRun(id=run_id, target_id=target_id, owner_id=owner_id,
                               base_url="http://target.test", scope=scope, limits={}, checks=[],
                               status="running", idempotency_key=str(run_id)))
        session.add(GreyboxGraphNode(
            run_id=run_id, kind="observation", key="api.operation|graphql|op-approve",
            label="GraphQL operation", status="recorded", version=1,
            data={"facts": operation}))
        if invocation is not None:
            session.add(GreyboxGraphNode(
                run_id=run_id, kind="observation", key="api.invocation|op-approve|member|1",
                label="GraphQL invocation", status="recorded", version=2,
                data={"facts": invocation}))
        await session.commit()
    return run_id


async def test_persisted_invocation_advances_exact_operation_investigation(session_maker):
    run_id = await _seed(session_maker, invocation={
        "ok": True, "operation_ref": "op-approve", "operation_id": "op-approve",
        "protocol": "graphql", "identity": "member", "state_changing": True,
        "status": 200, "expected_effect": "approval state changes",
    })
    async with session_maker() as session:
        snapshot = await build(session, run_id, KnowledgeInputs(
            sessions=[{"label": "member"}, {"label": "approver"}]))

    investigation = next(item for item in snapshot["investigations"]["active"]
                         if item["operation_id"] == "op-approve")
    assert investigation["status"] == "verification_pending"
    assert investigation["progress_state"] == "verification_pending"
    assert investigation["progress"]["completed_steps"] == [
        "execute permitted test", "collect operation evidence"]
    assert investigation["progress"]["operation_invocations"][0]["identity"] == "member"
    assert investigation["evidence"] == ["api.invocation|op-approve|member|1"]
    assert investigation["final_outcome"] is None


async def test_denied_invocation_advances_execution_without_inferring_security_outcome(
        session_maker):
    run_id = await _seed(session_maker, invocation={
        "ok": False, "operation_ref": "op-approve", "operation_id": "op-approve",
        "protocol": "graphql", "identity": "member", "state_changing": True,
        "status": 403, "protocol_error": "forbidden",
    })
    async with session_maker() as session:
        snapshot = await build(session, run_id, KnowledgeInputs(sessions=[{"label": "member"}]))

    investigation = next(item for item in snapshot["investigations"]["active"]
                         if item["operation_id"] == "op-approve")
    assert investigation["status"] == "verification_pending"
    assert investigation["progress_state"] == "verification_pending"
    assert investigation["progress"]["operation_invocations"][0]["ok"] is False
    assert investigation["final_outcome"] is None
