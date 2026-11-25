"""Persistent, explicit agent decisions for canonical security issues.

No semantic matching happens here: candidate facts are exposed to the agent and all
membership changes require an evidence-backed action.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web.models import (
    GreyboxCanonicalIssue, GreyboxCorrelationAudit, GreyboxEvent, GreyboxFinding,
    GreyboxHttpExchange, GreyboxIssueFinding, GreyboxIssueObservation,
)

OBSERVATION_STATUSES = {"candidate", "confirmed", "contradicted", "inconclusive"}
IMPACT_STATUSES = {"unverified", "verified", "rejected", "inconclusive"}


class CorrelationError(ValueError):
    pass


class CorrelationNotFound(CorrelationError):
    pass


class CorrelationConflict(CorrelationError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _finding(session: AsyncSession, run_id: uuid.UUID, finding_id: uuid.UUID,
                   lock: bool = False) -> GreyboxFinding:
    statement = select(GreyboxFinding).where(GreyboxFinding.run_id == run_id,
                                              GreyboxFinding.id == finding_id)
    row = (await session.scalars(statement.with_for_update() if lock else statement)).one_or_none()
    if row is None:
        raise CorrelationNotFound(f"finding {finding_id} does not exist in this run")
    return row


async def _issue(session: AsyncSession, run_id: uuid.UUID, issue_id: uuid.UUID,
                 lock: bool = False) -> GreyboxCanonicalIssue:
    statement = select(GreyboxCanonicalIssue).where(GreyboxCanonicalIssue.run_id == run_id,
                                                     GreyboxCanonicalIssue.id == issue_id)
    row = (await session.scalars(statement.with_for_update() if lock else statement)).one_or_none()
    if row is None:
        raise CorrelationNotFound(f"canonical issue {issue_id} does not exist in this run")
    return row


def _uuid_list(values: Sequence[uuid.UUID | str]) -> list[uuid.UUID]:
    try:
        result = [value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)) for value in values]
    except ValueError as exc:
        raise CorrelationError("invalid UUID reference") from exc
    if len(set(result)) != len(result):
        raise CorrelationError("duplicate finding reference")
    return result


async def _evidence_refs(session: AsyncSession, run_id: uuid.UUID,
                         references: Sequence[str]) -> list[str]:
    references = [str(reference).strip() for reference in references if str(reference).strip()]
    if not references:
        raise CorrelationError("semantic decisions require supporting evidence references")
    for reference in references:
        kind, separator, raw_id = reference.partition(":")
        try:
            if not separator:
                raise ValueError
            if kind == "finding":
                value = await session.scalar(select(GreyboxFinding.id).where(
                    GreyboxFinding.run_id == run_id, GreyboxFinding.id == uuid.UUID(raw_id)))
            elif kind == "exchange":
                value = await session.scalar(select(GreyboxHttpExchange.id).where(
                    GreyboxHttpExchange.run_id == run_id, GreyboxHttpExchange.id == int(raw_id)))
            elif kind == "event":
                value = await session.scalar(select(GreyboxEvent.id).where(
                    GreyboxEvent.run_id == run_id, GreyboxEvent.seq == int(raw_id)))
            elif kind == "observation":
                value = await session.scalar(select(GreyboxIssueObservation.id).where(
                    GreyboxIssueObservation.run_id == run_id,
                    GreyboxIssueObservation.id == uuid.UUID(raw_id)))
            else:
                raise CorrelationError(f"unsupported evidence reference kind: {kind}")
        except (ValueError, TypeError) as exc:
            raise CorrelationError(f"invalid evidence reference: {reference}") from exc
        if value is None:
            raise CorrelationNotFound(f"evidence does not exist in this run: {reference}")
    return references


def _confirmed_status(finding: GreyboxFinding | None = None,
                      finding_class: str | None = None) -> str:
    finding_class = finding_class or (finding.finding_class if finding else None)
    if finding_class == "vulnerability":
        return "verified_impact"
    if finding_class == "misconfiguration":
        return "confirmed_configuration"
    return "confirmed_observation"


def _status(findings: Sequence[GreyboxFinding],
            observations: Sequence[GreyboxIssueObservation] = (),
            finding_class: str | None = None) -> str:
    impact_statuses = {observation.impact_status for observation in observations}
    if "verified" in impact_statuses:
        return "verified_impact"
    statuses = {finding.status for finding in findings}
    if "verified" in statuses:
        verified = next(finding for finding in findings if finding.status == "verified")
        return _confirmed_status(verified, finding_class)
    if statuses and statuses <= {"rejected"}:
        return "rejected"
    if impact_statuses and impact_statuses <= {"rejected"}:
        return "rejected"
    if "inconclusive" in impact_statuses:
        return "inconclusive"
    return "candidate" if "candidate" in statuses else "inconclusive"


async def _sync(session: AsyncSession, issue: GreyboxCanonicalIssue) -> None:
    findings = list((await session.scalars(select(GreyboxFinding).where(
        GreyboxFinding.run_id == issue.run_id,
        GreyboxFinding.canonical_issue_id == issue.id))).all())
    observations = list((await session.scalars(select(GreyboxIssueObservation).where(
        GreyboxIssueObservation.run_id == issue.run_id,
        GreyboxIssueObservation.issue_id == issue.id))).all())
    issue.verification_status = _status(findings, observations, issue.finding_class)
    dates = [observation.observed_at for observation in observations]
    if dates:
        ordered = sorted(dates, key=lambda value: value if value.tzinfo else
                         value.replace(tzinfo=timezone.utc))
        issue.first_observed_at, issue.last_observed_at = ordered[0], ordered[-1]
    issue.updated_at = _now()


async def _audit(session: AsyncSession, run_id: uuid.UUID, action: str,
                 issue_id: uuid.UUID, finding_ids: Sequence[uuid.UUID], rationale: str,
                 references: Sequence[str], idempotency_key: str,
                 related_issue_ids: Sequence[uuid.UUID] = ()) -> GreyboxCorrelationAudit:
    key, rationale = idempotency_key.strip(), rationale.strip()
    if not key or not rationale:
        raise CorrelationError("idempotency key and rationale are required")
    expected = (action, str(issue_id), sorted(map(str, finding_ids)), rationale,
                list(references), sorted(map(str, related_issue_ids)))
    previous = (await session.scalars(select(GreyboxCorrelationAudit).where(
        GreyboxCorrelationAudit.run_id == run_id,
        GreyboxCorrelationAudit.idempotency_key == key))).one_or_none()
    if previous:
        actual = (previous.action, str(previous.canonical_issue_id),
                  sorted(previous.finding_ids or []), previous.rationale,
                  list(previous.evidence_refs or []), sorted(previous.related_issue_ids or []))
        if actual != expected:
            raise CorrelationConflict("idempotency key belongs to another decision")
        return previous
    row = GreyboxCorrelationAudit(run_id=run_id, action=action,
        canonical_issue_id=issue_id, finding_ids=list(map(str, finding_ids)),
        rationale=rationale, evidence_refs=list(references), idempotency_key=key,
        related_issue_ids=list(map(str, related_issue_ids)))
    session.add(row)
    await session.flush()
    return row


async def record_observation(session: AsyncSession, run_id: uuid.UUID, *,
    canonical_issue_id: uuid.UUID, event_key: str, location: Mapping[str, Any],
    observation_status: str, impact_status: str = "unverified",
    identity: str | None = None, evidence: Sequence[Mapping[str, Any]] = (),
    finding_id: uuid.UUID | None = None) -> GreyboxIssueObservation:
    issue = await _issue(session, run_id, canonical_issue_id)
    finding = await _finding(session, run_id, finding_id) if finding_id else None
    if finding and finding.canonical_issue_id != issue.id:
        raise CorrelationConflict("observation finding does not belong to issue")
    if observation_status not in OBSERVATION_STATUSES or impact_status not in IMPACT_STATUSES:
        raise CorrelationError("invalid observation or impact status")
    normalized = (dict(location), observation_status, impact_status, identity,
                  [dict(item) for item in evidence], finding_id)
    previous = (await session.scalars(select(GreyboxIssueObservation).where(
        GreyboxIssueObservation.run_id == run_id,
        GreyboxIssueObservation.event_key == event_key))).one_or_none()
    if previous:
        actual = (previous.location, previous.observation_status, previous.impact_status,
                  previous.identity, previous.evidence, previous.finding_id)
        if actual != normalized:
            raise CorrelationConflict("event key was reused with different observation data")
        return previous
    row = GreyboxIssueObservation(run_id=run_id, issue_id=issue.id,
        finding_id=finding_id, event_key=event_key, location=dict(location),
        observation_status=observation_status, impact_status=impact_status,
        identity=identity, evidence=[dict(item) for item in evidence])
    session.add(row)
    await session.flush()
    issue.last_observed_at = row.observed_at
    return row


async def _attach(session: AsyncSession, issue: GreyboxCanonicalIssue,
                  finding: GreyboxFinding) -> uuid.UUID | None:
    source_id = finding.canonical_issue_id
    if source_id == issue.id:
        return source_id
    for row in (await session.scalars(select(GreyboxIssueFinding).where(
            GreyboxIssueFinding.run_id == issue.run_id,
            GreyboxIssueFinding.finding_id == finding.id,
            GreyboxIssueFinding.active.is_(True)))).all():
        row.active, row.removed_at = False, _now()
    for row in (await session.scalars(select(GreyboxIssueObservation).where(
            GreyboxIssueObservation.run_id == issue.run_id,
            GreyboxIssueObservation.finding_id == finding.id))).all():
        row.issue_id = issue.id
    finding.canonical_issue_id = issue.id
    session.add(GreyboxIssueFinding(run_id=issue.run_id, issue_id=issue.id,
                                    finding_id=finding.id, active=True))
    await session.flush()
    await record_observation(session, issue.run_id, canonical_issue_id=issue.id,
        event_key=f"finding:{finding.id}", finding_id=finding.id,
        location=dict(finding.location or {}), evidence=list(finding.evidence or []),
        observation_status="confirmed" if finding.status == "verified" else
            "contradicted" if finding.status == "rejected" else "candidate",
        impact_status="verified" if (finding.status == "verified" and
                                     finding.finding_class == "vulnerability") else
            "rejected" if finding.status == "rejected" else "unverified")
    return source_id


async def correlate_findings(session: AsyncSession, run_id: uuid.UUID, *,
    finding_ids: Sequence[uuid.UUID | str], rationale: str,
    evidence_refs: Sequence[str], idempotency_key: str,
    canonical_issue_id: uuid.UUID | None = None, title: str | None = None,
    root_cause: str = "", retesting_guidance: str | None = None) -> GreyboxCanonicalIssue:
    """Explicit ``finding.correlate`` action: create or extend one issue."""
    ids = _uuid_list(finding_ids)
    if not ids:
        raise CorrelationError("at least one finding is required")
    findings = [await _finding(session, run_id, finding_id, True) for finding_id in ids]
    references = await _evidence_refs(session, run_id, evidence_refs)
    previous = (await session.scalars(select(GreyboxCorrelationAudit).where(
        GreyboxCorrelationAudit.run_id == run_id,
        GreyboxCorrelationAudit.idempotency_key == idempotency_key.strip()))).one_or_none()
    if previous:
        issue = await _issue(session, run_id, previous.canonical_issue_id)
        await _audit(session, run_id, "correlate", issue.id, ids, rationale,
                     references, idempotency_key,
                     [uuid.UUID(value) for value in previous.related_issue_ids or []])
        return issue
    if canonical_issue_id:
        issue = await _issue(session, run_id, canonical_issue_id, True)
    else:
        first = findings[0]
        issue = GreyboxCanonicalIssue(run_id=run_id, title=(title or first.title).strip(),
            severity=first.severity, finding_class=first.finding_class,
            verification_status=_status(findings), root_cause=root_cause.strip(),
            remediation=first.remediation, retesting_guidance=retesting_guidance)
        session.add(issue)
        await session.flush()
    related = {source for finding in findings
               if (source := await _attach(session, issue, finding)) and source != issue.id}
    if title is not None:
        issue.title = title.strip()
    if root_cause:
        issue.root_cause = root_cause.strip()
    if retesting_guidance is not None:
        issue.retesting_guidance = retesting_guidance
    await _sync(session, issue)
    await _audit(session, run_id, "correlate", issue.id, ids, rationale,
                 references, idempotency_key, sorted(related, key=str))
    return issue


async def merge_findings(session: AsyncSession, run_id: uuid.UUID, **kwargs: Any
                         ) -> GreyboxCanonicalIssue:
    return await correlate_findings(session, run_id, **kwargs)


async def split_findings(session: AsyncSession, run_id: uuid.UUID, *,
    canonical_issue_id: uuid.UUID, finding_ids: Sequence[uuid.UUID | str],
    rationale: str, evidence_refs: Sequence[str], idempotency_key: str,
    title: str | None = None, root_cause: str = "",
    retesting_guidance: str | None = None) -> GreyboxCanonicalIssue:
    ids = _uuid_list(finding_ids)
    references = await _evidence_refs(session, run_id, evidence_refs)
    previous = (await session.scalars(select(GreyboxCorrelationAudit).where(
        GreyboxCorrelationAudit.run_id == run_id,
        GreyboxCorrelationAudit.idempotency_key == idempotency_key.strip()))).one_or_none()
    if previous:
        target = await _issue(session, run_id, previous.canonical_issue_id)
        await _audit(session, run_id, "split", target.id, ids, rationale,
                     references, idempotency_key,
                     [uuid.UUID(value) for value in previous.related_issue_ids or []])
        return target
    source = await _issue(session, run_id, canonical_issue_id, True)
    findings = [await _finding(session, run_id, finding_id, True) for finding_id in ids]
    if not findings or any(finding.canonical_issue_id != source.id for finding in findings):
        raise CorrelationConflict("split findings must belong to the source issue")
    first = findings[0]
    target = GreyboxCanonicalIssue(run_id=run_id, title=(title or first.title).strip(),
        severity=first.severity, finding_class=first.finding_class,
        verification_status=_status(findings), root_cause=root_cause.strip(),
        remediation=first.remediation, retesting_guidance=retesting_guidance)
    session.add(target)
    await session.flush()
    for finding in findings:
        await _attach(session, target, finding)
    await _sync(session, source)
    await _sync(session, target)
    await _audit(session, run_id, "split", target.id, ids, rationale,
                 references, idempotency_key, [source.id])
    return target


async def add_location(session: AsyncSession, run_id: uuid.UUID, *,
    canonical_issue_id: uuid.UUID, event_key: str, location: Mapping[str, Any],
    observation_status: str, rationale: str, evidence_refs: Sequence[str],
    idempotency_key: str, impact_status: str = "unverified",
    identity: str | None = None, evidence: Sequence[Mapping[str, Any]] = (),
    finding_id: uuid.UUID | None = None) -> GreyboxIssueObservation:
    references = await _evidence_refs(session, run_id, evidence_refs)
    row = await record_observation(session, run_id,
        canonical_issue_id=canonical_issue_id, event_key=event_key, location=location,
        observation_status=observation_status, impact_status=impact_status,
        identity=identity, evidence=evidence, finding_id=finding_id)
    await _audit(session, run_id, "add_location", canonical_issue_id,
                 [finding_id] if finding_id else [], rationale, references, idempotency_key)
    await _sync(session, await _issue(session, run_id, canonical_issue_id))
    return row


async def candidate_issue_summaries(session: AsyncSession, run_id: uuid.UUID) -> list[dict]:
    """Candidate context in stable order, deliberately without similarity ranking."""
    issues = list((await session.scalars(select(GreyboxCanonicalIssue).where(
        GreyboxCanonicalIssue.run_id == run_id).order_by(
        GreyboxCanonicalIssue.created_at, GreyboxCanonicalIssue.id))).all())
    result = []
    for issue in issues:
        detail = await inspect_issue(session, run_id, canonical_issue_id=issue.id)
        result.append({key: detail[key] for key in (
            "canonical_issue_id", "title", "severity", "finding_class",
            "verification_status", "affected_location_count", "observation_count",
            "finding_ids")})
    return result


async def candidate_finding_details(session: AsyncSession, run_id: uuid.UUID,
                                    finding_ids: Sequence[uuid.UUID | str] = ()) -> list[dict]:
    """Ungrouped/grouped finding facts for proposer semantic reasoning."""
    ids = _uuid_list(finding_ids)
    statement = select(GreyboxFinding).where(GreyboxFinding.run_id == run_id)
    if ids:
        statement = statement.where(GreyboxFinding.id.in_(ids))
    findings = list((await session.scalars(statement.order_by(
        GreyboxFinding.created_at, GreyboxFinding.id))).all())
    return [_finding_data(finding) for finding in findings]


async def inspect_issue(session: AsyncSession, run_id: uuid.UUID, *,
    canonical_issue_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None) -> dict:
    if canonical_issue_id is None:
        if finding_id is None:
            return {"candidate_issues": await candidate_issue_summaries(session, run_id)}
        finding = await _finding(session, run_id, finding_id)
        if finding.canonical_issue_id is None:
            return {"finding": _finding_data(finding), "canonical_issue": None}
        canonical_issue_id = finding.canonical_issue_id
    issue = await _issue(session, run_id, canonical_issue_id)
    findings = list((await session.scalars(select(GreyboxFinding).where(
        GreyboxFinding.run_id == run_id,
        GreyboxFinding.canonical_issue_id == issue.id).order_by(GreyboxFinding.created_at))).all())
    observations = list((await session.scalars(select(GreyboxIssueObservation).where(
        GreyboxIssueObservation.run_id == run_id,
        GreyboxIssueObservation.issue_id == issue.id).order_by(
        GreyboxIssueObservation.observed_at, GreyboxIssueObservation.id))).all())
    history = list((await session.scalars(select(GreyboxCorrelationAudit).where(
        GreyboxCorrelationAudit.run_id == run_id,
        GreyboxCorrelationAudit.canonical_issue_id == issue.id).order_by(
        GreyboxCorrelationAudit.created_at, GreyboxCorrelationAudit.id))).all())
    by_location: dict[str, dict] = {}
    for observation in observations:
        key = json.dumps(observation.location or {}, sort_keys=True, separators=(",", ":"))
        item = by_location.setdefault(key, {"location": observation.location,
            "url": (observation.location or {}).get("url", ""), "observations": [],
            "identities": [], "evidence": [], "observation_count": 0})
        item["observations"].append({"observation_id": str(observation.id),
            "finding_id": str(observation.finding_id) if observation.finding_id else None,
            "verification_status": observation.observation_status,
            "impact_status": observation.impact_status, "identity": observation.identity,
            "evidence": observation.evidence, "observed_at": observation.observed_at})
        if observation.identity and observation.identity not in item["identities"]:
            item["identities"].append(observation.identity)
        item["evidence"].extend(observation.evidence or [])
        item["observation_count"] += 1
    for item in by_location.values():
        observation_statuses = {row["verification_status"] for row in item["observations"]}
        impact_statuses = {row["impact_status"] for row in item["observations"]}
        item["observation_status"] = next(iter(observation_statuses)) \
            if len(observation_statuses) == 1 else "inconclusive"
        item["impact_status"] = "verified" if "verified" in impact_statuses else \
            "rejected" if impact_statuses and impact_statuses <= {"rejected"} else \
            "inconclusive" if "inconclusive" in impact_statuses else "unverified"
        item["verification_status"] = item["observation_status"]
    return {"canonical_issue_id": str(issue.id), "title": issue.title,
        "severity": issue.severity, "finding_class": issue.finding_class,
        "verification_status": issue.verification_status, "root_cause": issue.root_cause,
        "remediation": issue.remediation, "retesting_guidance": issue.retesting_guidance,
        "first_observed_at": issue.first_observed_at, "last_observed_at": issue.last_observed_at,
        "affected_locations": list(by_location.values()),
        "affected_location_count": len(by_location), "observation_count": len(observations),
        "finding_ids": [str(finding.id) for finding in findings],
        "findings": [_finding_data(finding) for finding in findings],
        "correlation_history": [{"action": row.action, "rationale": row.rationale,
            "evidence_refs": row.evidence_refs, "finding_ids": row.finding_ids,
            "related_issue_ids": row.related_issue_ids, "created_at": row.created_at}
            for row in history]}


def _finding_data(finding: GreyboxFinding) -> dict:
    return {"finding_id": str(finding.id),
        "canonical_issue_id": str(finding.canonical_issue_id) if finding.canonical_issue_id else None,
        "title": finding.title, "severity": finding.severity,
        "finding_class": finding.finding_class, "status": finding.status,
        "check_id": finding.check_id, "description": finding.description,
        "location": finding.location, "evidence": finding.evidence,
        "verification": finding.verification}


async def apply_agent_action(session: AsyncSession, run_id: uuid.UUID, action: str,
                             params: Mapping[str, Any]) -> dict:
    """Direct explorer proposer boundary for explicit ``finding.*`` tool calls."""
    clean = action.removeprefix("finding.")
    params = dict(params)
    for key in ("canonical_issue_id", "finding_id"):
        if params.get(key) is not None:
            try:
                params[key] = uuid.UUID(str(params[key]))
            except ValueError as exc:
                raise CorrelationError(f"invalid {key}") from exc
    if clean == "inspect":
        return await inspect_issue(session, run_id,
            canonical_issue_id=params.get("canonical_issue_id"), finding_id=params.get("finding_id"))
    if clean in {"correlate", "merge"}:
        issue = await correlate_findings(session, run_id, **params)
        return await inspect_issue(session, run_id, canonical_issue_id=issue.id)
    if clean == "split":
        issue = await split_findings(session, run_id, **params)
        return await inspect_issue(session, run_id, canonical_issue_id=issue.id)
    if clean == "add_location":
        row = await add_location(session, run_id, **params)
        return {"observation_id": str(row.id), "canonical_issue_id": str(row.issue_id)}
    raise CorrelationError(f"unknown finding action: {action}")

