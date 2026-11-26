"""Public API contract for agent-owned canonical issue correlation."""
import uuid

from src.greybox_web.models import GreyboxFinding
from tests.greybox_web.conftest import h, start_run


async def test_explicit_action_exposes_canonical_evidence_and_is_idempotent(
        client, user_token, live_target, session_maker):
    run_id = uuid.UUID((await start_run(client, user_token, live_target["id"])).json()["id"])
    async with session_maker() as session:
        finding = GreyboxFinding(run_id=run_id, dedup_key="route-cors",
            check_id="cors.policy", title="Credentialed arbitrary origin", severity="high",
            status="verified", confidence="high", description="Origin was reflected",
            location={"url": "/api", "method": "GET"},
            evidence=[{"role": "proof", "excerpt": "allow-origin: attacker"}],
            verification={"method": "replay", "result": "confirmed", "exchange_ids": []},
            finding_class="misconfiguration", first_event_seq=1, version=1)
        session.add(finding)
        await session.commit()
    body = {"action": "finding.merge", "params": {"finding_ids": [str(finding.id)],
        "rationale": "The response proves this route uses the affected CORS control.",
        "evidence_refs": [f"finding:{finding.id}"], "idempotency_key": "cors-api-merge",
        "root_cause": "Credentialed CORS policy accepts arbitrary origins."}}
    first = await client.post(f"/greybox/runs/{run_id}/finding-actions",
                              headers=h(user_token), json=body)
    assert first.status_code == 200, first.text
    replay = await client.post(f"/greybox/runs/{run_id}/finding-actions",
                               headers=h(user_token), json=body)
    assert replay.status_code == 200
    issue_id = first.json()["canonical_issue_id"]
    detail = (await client.get(f"/greybox/runs/{run_id}/canonical-issues/{issue_id}",
                               headers=h(user_token))).json()
    assert detail["observation_count"] == 1
    assert detail["verification_status"] == "confirmed_configuration"
    assert detail["affected_locations"][0]["observations"][0]["impact_status"] == "unverified"
    assert len(detail["correlation_history"]) == 1


async def test_same_title_does_not_group_without_agent_action(
        client, user_token, live_target, session_maker):
    run_id = uuid.UUID((await start_run(client, user_token, live_target["id"])).json()["id"])
    async with session_maker() as session:
        for key in ("a", "b"):
            session.add(GreyboxFinding(run_id=run_id, dedup_key=key, check_id="custom",
                title="Same title", severity="low", status="candidate", confidence="medium",
                description="Different observations", location={"url": f"/{key}"},
                evidence=[], finding_class="hardening", first_event_seq=1, version=1))
        await session.commit()
    items = (await client.get(f"/greybox/runs/{run_id}/canonical-issues",
                              headers=h(user_token))).json()["items"]
    assert items == []
