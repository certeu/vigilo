"""Seed demo data for the Vigilo platform dashboards.

Creates a couple of repositories with several completed runs over time whose
findings DECREASE (to demonstrate the per-repo timeline), plus a second repo so the
global dashboard's aggregations/top-repos have something to show.

Usage (against the eval DB):
    VIGILO_DATABASE_URL=sqlite+aiosqlite:///.../ui.db \
    VIGILO_JWT_SECRET=... VIGILO_FERNET_KEY=... \
    .venv-webapi/bin/python scripts/seed_demo_data.py
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from fastapi_users.password import PasswordHelper
from sqlalchemy import select

from src.webapi.db import create_all, get_async_session
from src.webapi.models import (
    RUN_SUCCEEDED,
    Job,
    Repository,
    Run,
    RunMetrics,
    User,
)

CATEGORIES = ["auth", "authz", "injection", "supply_chain", "ssrf", "xss", "crypto"]
DISPLAY = {
    "auth": "Authentication", "authz": "Authorization", "injection": "Injection",
    "supply_chain": "Supply Chain (SCA)", "ssrf": "SSRF", "xss": "XSS",
    "crypto": "Cryptography",
}


def _metrics_data(total: int) -> dict:
    crit = max(0, round(total * 0.30))
    high = max(0, round(total * 0.35))
    med = max(0, round(total * 0.22))
    low = max(0, total - crit - high - med)
    sc = max(0, round(total * 0.30))
    # spread remaining categories deterministically
    cats = {}
    remaining = total
    for i, c in enumerate(CATEGORIES):
        share = round(total * [0.1, 0.22, 0.12, 0.30, 0.05, 0.03, 0.06][i])
        cats[c] = min(share, remaining)
        remaining -= cats[c]
    pkgs = [
        {"package": "@vitest/ui", "version": "3.2.4", "ecosystem": "npm",
         "severity": "critical", "cve": "CVE-2026-47429", "fixed_version": "3.2.6"},
        {"package": "requests", "version": "2.19.1", "ecosystem": "pypi",
         "severity": "high", "cve": "CVE-2018-18074", "fixed_version": "2.20.0"},
        {"package": "jinja2", "version": "2.10", "ecosystem": "pypi",
         "severity": "high", "cve": "CVE-2019-10906", "fixed_version": "2.10.1"},
        {"package": "cryptography", "version": "2.3", "ecosystem": "pypi",
         "severity": "medium", "cve": "CVE-2020-25659", "fixed_version": "3.2"},
    ][: max(1, min(4, sc))]
    return {
        "total_findings": total,
        "severity_counts": {"critical": crit, "high": high, "medium": med,
                            "low": low, "informational": 0},
        "status_counts": {"exploited": round(total * 0.6),
                          "unconfirmed": total - round(total * 0.6)},
        "category_counts": cats,
        "supply_chain": sc,
        "supply_chain_packages": pkgs,
        "display_names": DISPLAY,
        "source": "seed",
    }


async def _ensure_admin(session) -> User:
    admin = await session.scalar(select(User).where(User.email == "admin@example.com"))
    if admin is None:
        admin = User(
            email="admin@example.com",
            hashed_password=PasswordHelper().hash("change-me-now"),
            role="admin", is_active=True, is_superuser=True, is_verified=True,
        )
        session.add(admin)
        await session.commit()
        await session.refresh(admin)
    return admin


async def _seed_repo(session, admin, name, totals_over_time):
    repo = Repository(id=uuid.uuid4(), created_by=admin.id, name=name,
                      source_type="upload", pipeline_config={}, scan_config={})
    session.add(repo)
    await session.commit()
    job = Job(id=uuid.uuid4(), created_by=admin.id, repository_id=repo.id,
              name=f"{name} full scan", stage_preset="full", engine="whitebox",
              pipeline_overrides={})
    session.add(job)
    await session.commit()
    now = datetime.now(timezone.utc)
    n = len(totals_over_time)
    for i, total in enumerate(totals_over_time):
        when = now - timedelta(days=7 * (n - i))
        run = Run(id=uuid.uuid4(), job_id=job.id, triggered_by=admin.id,
                  trigger_type="manual", status=RUN_SUCCEEDED,
                  session_id=f"seed-{uuid.uuid4().hex[:10]}", data_dir="/seed",
                  current_phase="report", total_cost_usd=4.2,
                  started_at=when, finished_at=when, created_at=when)
        session.add(run)
        await session.commit()
        data = _metrics_data(total)
        sev = data["severity_counts"]
        session.add(RunMetrics(
            id=uuid.uuid4(), run_id=run.id, repository_id=repo.id,
            total_findings=total, critical=sev["critical"], high=sev["high"],
            medium=sev["medium"], low=sev["low"], informational=0,
            exploited=data["status_counts"]["exploited"], supply_chain=data["supply_chain"],
            data=data, computed_at=when,
        ))
        await session.commit()
    return repo


async def main() -> None:
    await create_all()
    async for session in get_async_session():
        admin = await _ensure_admin(session)
        # decreasing over 4 scans → visible improvement
        await _seed_repo(session, admin, "acme-webapp", [82, 61, 38, 17])
        await _seed_repo(session, admin, "billing-service", [44, 40])
        await _seed_repo(session, admin, "auth-gateway", [12])
        print("Seeded demo data (3 repositories, decreasing timelines).")
        break


if __name__ == "__main__":
    asyncio.run(main())
