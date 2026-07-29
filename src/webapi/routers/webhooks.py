"""GitLab webhook: start runs on merge-request events.

Unauthenticated (no JWT) but secret-verified: GitLab sends the repository's
``webhook_secret`` in the ``X-Gitlab-Token`` header (constant-time compared). On a
qualifying MR event, every enabled ``gitlab_mr`` schedule for a job on the matching
repository triggers a run of that job, tagged with the MR iid.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.db import get_async_session
from src.webapi.engine.base import ExecutionEngine
from src.webapi.engine.provider import get_engine
from src.webapi.models import Job, Repository, Schedule
from src.webapi.runsvc import create_and_maybe_start

router = APIRouter(tags=["webhooks"])

# MR actions that should trigger a scan.
_TRIGGER_ACTIONS = {"open", "reopen", "update"}


@router.post("/webhooks/gitlab")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> dict:
    payload = await request.json()
    if payload.get("object_kind") != "merge_request":
        return {"status": "ignored", "reason": "not a merge_request event"}

    project_id = str((payload.get("project") or {}).get("id", ""))
    attrs = payload.get("object_attributes") or {}
    action = attrs.get("action")
    mr_iid = str(attrs.get("iid", "")) or None

    if not project_id:
        raise HTTPException(status_code=400, detail="missing project id")

    # Match the repository by project id, then verify the secret (constant-time).
    repo = (
        await session.scalars(
            select(Repository).where(Repository.gitlab_project_id == project_id)
        )
    ).first()
    if repo is None or not repo.webhook_secret:
        raise HTTPException(status_code=404, detail="no repository/webhook for project")
    if not x_gitlab_token or not secrets.compare_digest(x_gitlab_token, repo.webhook_secret):
        raise HTTPException(status_code=401, detail="invalid webhook token")

    if action is not None and action not in _TRIGGER_ACTIONS:
        return {"status": "ignored", "reason": f"action {action} not triggering"}

    # Every enabled gitlab_mr schedule for a job on this repo → a run.
    schedules = (
        await session.scalars(
            select(Schedule).where(
                Schedule.kind == "gitlab_mr", Schedule.enabled == True  # noqa: E712
            )
        )
    ).all()
    started: list[str] = []
    for sched in schedules:
        job = await session.get(Job, sched.job_id)
        if job is None or job.repository_id != repo.id:
            continue
        run = await create_and_maybe_start(
            session, engine, job, triggered_by=None,
            trigger_type="gitlab_mr", gitlab_mr_iid=mr_iid,
        )
        sched.last_run_id = run.id
        await session.commit()
        started.append(str(run.id))

    return {"status": "ok", "runs_started": started, "mr_iid": mr_iid}
