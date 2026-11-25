"""Regressions for explicit, reversible finding correlation.

The fixtures below contain no target ground truth.  They exercise the persistence
contract at the agent-action boundary: the backend validates references and
idempotency but never decides that matching text or locations imply equivalence.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.greybox_web import correlation, report
from src.greybox_web.models import (
    GreyboxCorrelationAudit,
    GreyboxFinding,
    GreyboxIssueFinding,
    GreyboxIssueObservation,
)
from tests.greybox_web.conftest import h, start_run


async def _finding(session, run_id, key, title, url, *, status="candidate",
                   finding_class="misconfiguration", description=None):
    row = GreyboxFinding(
        run_id=run_id, dedup_key=key, check_id="tool.fixture", title=title,
        severity="medium", status=status,
        confidence="high", description=description or title,
        location={"url": url, "method": "GET"},
        evidence=[{"role": "proof", "exchange_id": None,
                   "excerpt": f"evidence {key}"}], verification={
            "result": "confirmed" if status == "verified" else "inconclusive",
            "method": "fixture evidence", "exchange_ids": []},
        finding_class=finding_class, remediation={"summary": f"fix {key}"},
        first_event_seq=1, version=1,
    )
    session.add(row)
    await session.flush()
    return row


async def _run_id(client, user_token, live_target):
    response = await start_run(client, user_token, live_target["id"],
                               key=f"correlation-{uuid.uuid4()}")
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


async def _correlate(session, run_id, findings, key, *, title=None,
                     canonical_issue_id=None, root_cause="shared control"):
    return await correlation.correlate_findings(
        session, run_id, finding_ids=[finding.id for finding in findings],
        rationale="The agent compared the underlying security control evidence.",
        evidence_refs=[f"finding:{finding.id}" for finding in findings],
        idempotency_key=key, title=title, root_cause=root_cause,
        canonical_issue_id=canonical_issue_id)


async def test_identical_observation_replay_is_idempotent_and_conflicts_if_changed(
        client, user_token, live_target, session_maker):
    run_id = await _run_id(client, user_token, live_target)
    async with session_maker() as session:
        finding = await _finding(session, run_id, "csp-1", "Missing CSP", "/")
        issue = await _correlate(session, run_id, [finding], "create-csp")
        params = dict(canonical_issue_id=issue.id, event_key="scanner:41",
                      location={"url": "/", "method": "GET"},
                      observation_status="confirmed", impact_status="unverified",
                      identity="anonymous", evidence=[{"excerpt": "CSP absent"}])
        first = await correlation.record_observation(session, run_id, **params)
        replay = await correlation.record_observation(session, run_id, **params)
        assert replay.id == first.id
        with pytest.raises(correlation.CorrelationConflict):
            await correlation.record_observation(
                session, run_id, **{**params, "impact_status": "verified"})
        await session.commit()
    async with session_maker() as session:
        rows = (await session.scalars(select(GreyboxIssueObservation).where(
            GreyboxIssueObservation.run_id == run_id))).all()
        assert len(rows) == 2  # original finding occurrence plus one scanner event


async def test_agent_can_group_distinct_titles_and_routes_without_automatic_grouping(
        client, user_token, live_target, session_maker):
    run_id = await _run_id(client, user_token, live_target)
    async with session_maker() as session:
        api = await _finding(session, run_id, "cors-api", "Arbitrary origin accepted", "/api")
        version = await _finding(session, run_id, "cors-version", "Credentialed CORS exposure", "/api/version")
        same_title_elsewhere = await _finding(
            session, run_id, "cors-other", "Arbitrary origin accepted", "https://other.invalid/api")
        issue = await _correlate(session, run_id, [api, version], "merge-cors",
                                 title="CORS reflects arbitrary origins with credentials")
        await session.commit()
    async with session_maker() as session:
        detail = await correlation.inspect_issue(session, run_id,
            canonical_issue_id=issue.id)
        assert detail["affected_location_count"] == 2
        assert detail["observation_count"] == 2
        assert set(detail["finding_ids"]) == {str(api.id), str(version.id)}
        ungrouped = await correlation.inspect_issue(session, run_id,
            finding_id=same_title_elsewhere.id)
        assert ungrouped["canonical_issue"] is None
    response = await client.get(f"/greybox/runs/{run_id}/canonical-issues",
                                headers=h(user_token))
    assert response.status_code == 200
    assert response.json()["items"] == [{
        "canonical_issue_id": str(issue.id),
        "title": "CORS reflects arbitrary origins with credentials",
        "severity": "medium", "finding_class": "misconfiguration",
        "verification_status": "candidate", "affected_location_count": 2,
        "observation_count": 2, "finding_ids": [str(api.id), str(version.id)]}]
    original = (await client.get(f"/greybox/runs/{run_id}/findings",
                                 headers=h(user_token))).json()["items"]
    assert len(original) == 3
    assert sum(row["canonical_issue_id"] == str(issue.id) for row in original) == 2


async def test_incorrect_grouping_can_be_split_without_losing_history(
        client, user_token, live_target, session_maker):
    run_id = await _run_id(client, user_token, live_target)
    async with session_maker() as session:
        first = await _finding(session, run_id, "access-a", "Shared access control failure", "/a")
        second = await _finding(session, run_id, "access-b", "Shared access control failure", "/b")
        source = await _correlate(session, run_id, [first, second], "merge-access")
        split = await correlation.split_findings(
            session, run_id, canonical_issue_id=source.id, finding_ids=[second.id],
            title="Independent authorization failure", root_cause="separate policy",
            rationale="New identity evidence proves the policy engines differ.",
            evidence_refs=[f"finding:{second.id}"], idempotency_key="split-access")
        await session.commit()
    async with session_maker() as session:
        source_detail = await correlation.inspect_issue(session, run_id,
            canonical_issue_id=source.id)
        split_detail = await correlation.inspect_issue(session, run_id,
            canonical_issue_id=split.id)
        assert source_detail["finding_ids"] == [str(first.id)]
        assert split_detail["finding_ids"] == [str(second.id)]
        links = (await session.scalars(select(GreyboxIssueFinding).where(
            GreyboxIssueFinding.finding_id == second.id))).all()
        assert {link.active for link in links} == {False, True}
        history = (await session.scalars(select(GreyboxCorrelationAudit).where(
            GreyboxCorrelationAudit.run_id == run_id))).all()
        assert {entry.action for entry in history} == {"correlate", "split"}
        assert source_detail["correlation_history"][0]["action"] == "correlate"
        assert split_detail["correlation_history"][0]["action"] == "split"


async def test_observation_and_impact_verification_are_separate_and_survive_resumption(
        client, user_token, live_target, session_maker):
    run_id = await _run_id(client, user_token, live_target)
    async with session_maker() as session:
        finding = await _finding(session, run_id, "header", "Missing CSP", "/",
                                 status="verified")
        issue = await _correlate(session, run_id, [finding], "header-create")
        await correlation.add_location(session, run_id,
            canonical_issue_id=issue.id, event_key="header-second-pass",
            location={"url": "/", "method": "GET"},
            observation_status="confirmed", impact_status="unverified",
            rationale="A fresh read confirms absence, not browser execution impact.",
            evidence_refs=[f"finding:{finding.id}"], idempotency_key="header-location",
            finding_id=finding.id, evidence=[{"excerpt": "header remains absent"}])
        await correlation.add_location(session, run_id,
            canonical_issue_id=issue.id, event_key="browser-negative-control",
            location={"url": "/preview", "method": "GET"},
            observation_status="contradicted", impact_status="rejected",
            rationale="The controlled browser did not execute content at this route.",
            evidence_refs=[f"finding:{finding.id}"], idempotency_key="header-control",
            finding_id=finding.id, evidence=[{"excerpt": "canary remained text"}])
        await session.commit()
    # A resumed worker opens a new transaction and sees stable issue identity/history.
    async with session_maker() as session:
        detail = await correlation.inspect_issue(session, run_id,
            canonical_issue_id=issue.id)
        observations = [item for location in detail["affected_locations"]
                        for item in location["observations"]]
        assert detail["observation_count"] == 3
        assert {item["verification_status"] for item in observations} == {
            "confirmed", "contradicted"}
        assert {item["impact_status"] for item in observations} == {
            "unverified", "rejected"}
        assert detail["verification_status"] == "confirmed_configuration"
        assert any(entry["rationale"].startswith("A fresh read")
                   for entry in detail["correlation_history"])
        markdown = await report.generate(session, run_id)
        assert "**Status:** confirmed configuration weakness" in markdown
        assert "**Affected locations:** 2" in markdown
        assert "**Supporting observations:** 3" in markdown


async def test_correlation_references_and_actions_are_isolated_between_runs(
        client, user_token, live_target, session_maker):
    first_run = await _run_id(client, user_token, live_target)
    second_target = await client.post("/greybox/targets", headers=h(user_token), json={
        "name": "other-correlation-target", "base_url": live_target["base_url"]})
    second_run = uuid.UUID((await start_run(
        client, user_token, second_target.json()["id"], key=f"other-{uuid.uuid4()}"))
        .json()["id"])
    async with session_maker() as session:
        finding = await _finding(session, first_run, "one-run", "Issue", "/")
        with pytest.raises(correlation.CorrelationNotFound):
            await correlation.correlate_findings(session, second_run,
                finding_ids=[finding.id], rationale="cross-run reference",
                evidence_refs=[f"finding:{finding.id}"], idempotency_key="cross-run")
