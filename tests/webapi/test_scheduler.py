from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from src.webapi.engine.fake import FakeEngine
from src.webapi.models import Job, Repository, Schedule, User
from src.webapi.scheduler import run_due_schedules


async def _seed_job(session_maker) -> uuid.UUID:
    async with session_maker() as s:
        user = User(id=uuid.uuid4(), email="sch@example.com", hashed_password="h",
                    role="user", is_active=True, is_superuser=False, is_verified=True)
        repo = Repository(id=uuid.uuid4(), created_by=user.id, name="r",
                          source_type="upload")
        job = Job(id=uuid.uuid4(), created_by=user.id, repository_id=repo.id,
                  name="j", stage_preset="vuln", engine="whitebox", pipeline_overrides={})
        s.add_all([user, repo, job])
        await s.commit()
        return job.id


class TestRunDueSchedules:
    async def test_once_fires_when_due(self, session_maker):
        job_id = await _seed_job(session_maker)
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        async with session_maker() as s:
            s.add(Schedule(id=uuid.uuid4(), job_id=job_id,
                           created_by=uuid.uuid4(), kind="once", run_at=past, enabled=True))
            await s.commit()
        engine = FakeEngine()
        async with session_maker() as s:
            started = await run_due_schedules(s, engine)
        assert len(started) == 1
        # firing again does nothing (one-shot disabled + last_run_id set)
        async with session_maker() as s:
            started2 = await run_due_schedules(s, engine)
        assert started2 == []

    async def test_once_not_due_in_future(self, session_maker):
        job_id = await _seed_job(session_maker)
        future = datetime.now(timezone.utc) + timedelta(days=1)
        async with session_maker() as s:
            s.add(Schedule(id=uuid.uuid4(), job_id=job_id,
                           created_by=uuid.uuid4(), kind="once", run_at=future, enabled=True))
            await s.commit()
        async with session_maker() as s:
            started = await run_due_schedules(s, FakeEngine())
        assert started == []

    async def test_gitlab_mr_never_time_fires(self, session_maker):
        job_id = await _seed_job(session_maker)
        async with session_maker() as s:
            s.add(Schedule(id=uuid.uuid4(), job_id=job_id,
                           created_by=uuid.uuid4(), kind="gitlab_mr", enabled=True))
            await s.commit()
        async with session_maker() as s:
            started = await run_due_schedules(s, FakeEngine())
        assert started == []
