"""Persist per-run metrics and aggregate them for the dashboards."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.metrics import SEVERITIES, extract_run_metrics
from src.webapi.models import RUN_SUCCEEDED, Repository, Run, RunMetrics


async def upsert_run_metrics(session: AsyncSession, run: Run) -> RunMetrics | None:
    """Extract metrics from the run's deliverables and store them (once).

    If a SUCCEEDED run's deliverables can't be parsed, we store an explicit
    parse-error sentinel row (not nothing) so the UI can show 'couldn't parse
    findings for this run' instead of silently omitting it or showing zeros as if
    they were real. (Deleting the row forces a recompute if deliverables appear.)"""
    existing = await session.scalar(
        select(RunMetrics).where(RunMetrics.run_id == run.id)
    )
    if existing is not None:
        return existing
    from src.webapi.models import Job
    job = await session.get(Job, run.job_id)
    repository_id = job.repository_id if job else run.job_id
    # Did this scan include supply-chain analysis? (only the 'full' preset does)
    sca_scanned = False
    if job is not None:
        try:
            from src.types.stages import stages_for_preset
            sca_scanned = stages_for_preset(job.stage_preset).run_sca
        except Exception:
            sca_scanned = False

    data = extract_run_metrics(run.data_dir, run.session_id)
    if data is None:
        # Only persist a parse-error sentinel for a finished run (a still-running
        # run legitimately has no deliverables yet — don't cache that).
        if run.status != RUN_SUCCEEDED:
            return None
        data = {
            "parse_error": True, "supply_chain_scanned": sca_scanned,
            "severity_counts": {s: 0 for s in SEVERITIES},
            "status_counts": {"exploited": 0, "unconfirmed": 0},
            "category_counts": {}, "supply_chain": 0, "total_findings": 0,
        }
    else:
        data["supply_chain_scanned"] = sca_scanned
    sev = data["severity_counts"]
    row = RunMetrics(
        run_id=run.id, repository_id=repository_id,
        total_findings=data["total_findings"],
        critical=sev["critical"], high=sev["high"], medium=sev["medium"],
        low=sev["low"], informational=sev["informational"],
        exploited=data["status_counts"]["exploited"],
        supply_chain=data["supply_chain"], data=data,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


def metrics_to_dict(m: RunMetrics) -> dict:
    return {
        "run_id": str(m.run_id),
        "repository_id": str(m.repository_id),
        "computed_at": m.computed_at.isoformat(),
        "total_findings": m.total_findings,
        "severity_counts": {
            "critical": m.critical, "high": m.high, "medium": m.medium,
            "low": m.low, "informational": m.informational,
        },
        "exploited": m.exploited,
        "supply_chain": m.supply_chain,
        "category_counts": (m.data or {}).get("category_counts", {}),
        "display_names": (m.data or {}).get("display_names", {}),
        "supply_chain_packages": (m.data or {}).get("supply_chain_packages", []),
        # Explicit states so the UI never shows silent zeros / false negatives:
        "parse_error": bool((m.data or {}).get("parse_error", False)),
        "supply_chain_scanned": bool((m.data or {}).get("supply_chain_scanned", False)),
    }


async def repo_timeline(session: AsyncSession, repository_id: uuid.UUID) -> list[dict]:
    rows = (
        await session.scalars(
            select(RunMetrics)
            .where(RunMetrics.repository_id == repository_id)
            .order_by(RunMetrics.computed_at.asc())
        )
    ).all()
    return [metrics_to_dict(m) for m in rows]


async def _latest_per_repo(
    session: AsyncSession, allowed: set[uuid.UUID] | None = None
) -> list[RunMetrics]:
    """Most recent RunMetrics for each repository (optionally restricted to ``allowed``)."""
    rows = (
        await session.scalars(select(RunMetrics).order_by(RunMetrics.computed_at.asc()))
    ).all()
    latest: dict[uuid.UUID, RunMetrics] = {}
    for m in rows:  # ascending → last write wins = latest
        if allowed is None or m.repository_id in allowed:
            latest[m.repository_id] = m
    return list(latest.values())


async def global_dashboard(
    session: AsyncSession, allowed: set[uuid.UUID] | None = None
) -> dict:
    latest = await _latest_per_repo(session, allowed)
    repo_names = {
        r.id: r.name for r in (await session.scalars(select(Repository))).all()
        if allowed is None or r.id in allowed
    }
    severity_totals = {s: 0 for s in SEVERITIES}
    category_totals: dict[str, int] = {}
    total = supply_chain = exploited = parse_errors = 0
    per_repo: list[dict] = []
    # Aggregate vulnerable dependencies across repos, keyed by (package, version).
    pkg_agg: dict[tuple, dict] = {}
    for m in latest:
        # Never fold an unparseable run's zeros into the totals as if they were real.
        if (m.data or {}).get("parse_error"):
            parse_errors += 1
            continue
        total += m.total_findings
        supply_chain += m.supply_chain
        exploited += m.exploited
        for s in SEVERITIES:
            severity_totals[s] += getattr(m, s)
        for cat, n in ((m.data or {}).get("category_counts", {})).items():
            category_totals[cat] = category_totals.get(cat, 0) + int(n)
        for p in (m.data or {}).get("supply_chain_packages", []):
            key = (p.get("package"), p.get("version"))
            entry = pkg_agg.setdefault(key, {**p, "repos": 0})
            entry["repos"] += 1
        per_repo.append({
            "repository_id": str(m.repository_id),
            "repository_name": repo_names.get(m.repository_id, "unknown"),
            "total_findings": m.total_findings,
            "critical": m.critical, "high": m.high,
            "exploited": m.exploited, "supply_chain": m.supply_chain,
        })
    top_repos = sorted(per_repo, key=lambda r: r["total_findings"], reverse=True)[:10]
    _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    top_packages = sorted(
        pkg_agg.values(),
        key=lambda p: (_rank.get(p.get("severity", ""), 5), -p["repos"]),
    )[:15]
    return {
        "repositories_scanned": len(latest) - parse_errors,
        "total_findings": total,
        "exploited": exploited,
        "supply_chain": supply_chain,
        "severity_totals": severity_totals,
        "category_totals": category_totals,
        "top_repositories": top_repos,
        "top_packages": top_packages,
        # Completed runs whose findings couldn't be parsed (surfaced, not hidden).
        "parse_errors": parse_errors,
    }
