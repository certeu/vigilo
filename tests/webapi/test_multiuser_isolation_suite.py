"""Multi-user / multi-repo isolation & contamination suite.

Re-runnable regression coverage (no LLM calls — uses FakeEngine + planted markers)
for the guarantees that matter across users and concurrent runs:

- no cross-user data visibility in list AND detail views (repos/jobs/runs/dashboard)
- IDOR: one user cannot read/mutate another's private repo/job/run/report/logs
- no cross-run contamination: logs/reports of run A never leak into run B
- disk isolation: every run gets its own data_dir checkout
- the global concurrency cap holds across users, not just within one user

State is inserted directly via the API/DB so the suite is fast and deterministic.
"""
from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import select

from src.webapi.models import RUN_FAILED, RUN_SUCCEEDED, Run
from src.webapi.settings import get_settings
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


async def _user(client, session_maker, email, role="user"):
    await _make_user(session_maker, email, PW, role)
    return await _token(client, email, PW)


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


async def _repo(client, tok, name, private=True):
    r = await client.post("/repositories", headers=_h(tok),
                          json={"name": name, "source_type": "upload", "is_private": private})
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


async def _job(client, tok, repo_id, name="j", preset="vuln"):
    r = await client.post("/jobs", headers=_h(tok),
                          json={"repository_id": repo_id, "name": name, "stage_preset": preset})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _run(client, tok, job_id):
    r = await client.post(f"/jobs/{job_id}/run", headers=_h(tok))
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _run_row(session_maker, run_id) -> Run:
    import uuid as _uuid
    async with session_maker() as s:
        return await s.get(Run, _uuid.UUID(run_id))


def _write_log(data_dir, session_id, text):
    from src.webapi.logs import log_path_for
    p = log_path_for(data_dir, session_id)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestCrossUserVisibility:
    async def test_lists_and_dashboard_are_per_user(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        bob = await _user(client, session_maker, "bob@example.com")
        ra = await _repo(client, alice, "ALICEMARK-repo")
        rb = await _repo(client, bob, "BOBMARK-repo")
        ja = await _job(client, alice, ra); await _run(client, alice, ja)
        jb = await _job(client, bob, rb); await _run(client, bob, jb)

        # repositories list
        alist = (await client.get("/repositories", headers=_h(alice))).json()
        anames = [x["name"] for x in alist]
        assert "ALICEMARK-repo" in anames and "BOBMARK-repo" not in anames, anames
        # jobs list
        ajobs = (await client.get("/jobs", headers=_h(alice))).json()
        assert all(j["repository_id"] == ra for j in ajobs)
        # runs list
        aruns = (await client.get("/runs", headers=_h(alice))).json()
        assert len(aruns) == 1
        # dashboard metrics reflect only accessible repos
        dash = (await client.get("/dashboard/metrics", headers=_h(alice))).json()
        import json as _json
        assert "BOBMARK-repo" not in _json.dumps(dash)

    async def test_admin_sees_all(self, client, session_maker):
        admin = await _user(client, session_maker, "admin@example.com", role="admin")
        bob = await _user(client, session_maker, "bob@example.com")
        rb = await _repo(client, bob, "BOB-private")
        alist = (await client.get("/repositories", headers=_h(admin))).json()
        assert any(x["name"] == "BOB-private" for x in alist)


class TestIDOR:
    async def test_cross_user_resource_access_blocked(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        bob = await _user(client, session_maker, "bob@example.com")
        rb = await _repo(client, bob, "bob-secret")
        jb = await _job(client, bob, rb)
        run_b = await _run(client, bob, jb)

        # repo
        assert (await client.get(f"/repositories/{rb}", headers=_h(alice))).status_code == 404
        assert (await client.patch(f"/repositories/{rb}", headers=_h(alice), json={"name": "x"})).status_code in (403, 404)
        assert (await client.delete(f"/repositories/{rb}", headers=_h(alice))).status_code in (403, 404)
        # job
        assert (await client.get(f"/jobs/{jb}", headers=_h(alice))).status_code == 404
        assert (await client.post(f"/jobs/{jb}/run", headers=_h(alice))).status_code in (403, 404)
        # run + its sub-resources
        assert (await client.get(f"/runs/{run_b}", headers=_h(alice))).status_code == 404
        assert (await client.get(f"/runs/{run_b}/logs", headers=_h(alice))).status_code == 404
        assert (await client.get(f"/runs/{run_b}/report", headers=_h(alice))).status_code == 404
        assert (await client.get(f"/runs/{run_b}/metrics", headers=_h(alice))).status_code == 404


class TestCrossRunContamination:
    async def test_logs_do_not_leak_between_runs(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        ra = await _repo(client, alice, "repo-A")
        rb = await _repo(client, alice, "repo-B")
        run_a = await _run(client, alice, await _job(client, alice, ra))
        run_b = await _run(client, alice, await _job(client, alice, rb))

        row_a = await _run_row(session_maker, run_a)
        row_b = await _run_row(session_maker, run_b)
        # distinct data_dir per run (disk isolation)
        assert row_a.data_dir != row_b.data_dir
        assert run_a in row_a.data_dir and run_b in row_b.data_dir

        _write_log(row_a.data_dir, row_a.session_id, "[PHASE] Starting: recon\nSECRET-A-XYZ findings for repo A\n")
        _write_log(row_b.data_dir, row_b.session_id, "[PHASE] Starting: recon\nSECRET-B-QRS findings for repo B\n")

        logs_a = (await client.get(f"/runs/{run_a}/logs", headers=_h(alice))).json()
        logs_b = (await client.get(f"/runs/{run_b}/logs", headers=_h(alice))).json()
        text_a = "\n".join(logs_a["lines"] if isinstance(logs_a, dict) else logs_a)
        text_b = "\n".join(logs_b["lines"] if isinstance(logs_b, dict) else logs_b)
        assert "SECRET-A-XYZ" in text_a and "SECRET-B-QRS" not in text_a
        assert "SECRET-B-QRS" in text_b and "SECRET-A-XYZ" not in text_b

    async def test_reports_do_not_leak_between_runs(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        run_a = await _run(client, alice, await _job(client, alice, await _repo(client, alice, "repo-A")))
        run_b = await _run(client, alice, await _job(client, alice, await _repo(client, alice, "repo-B")))
        row_a = await _run_row(session_maker, run_a)
        row_b = await _run_row(session_maker, run_b)

        from src.webapi.reports import report_path
        for row, marker in ((row_a, "REPORT-A-UNIQUE"), (row_b, "REPORT-B-UNIQUE")):
            p = report_path(row.data_dir, row.session_id)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(f"# Report\n\n{marker}\n")
            # mark terminal so the report endpoint serves it
            async with session_maker() as s:
                r = await s.get(Run, row.id); r.status = RUN_SUCCEEDED; await s.commit()

        rep_a = (await client.get(f"/runs/{run_a}/report", headers=_h(alice))).json()
        rep_b = (await client.get(f"/runs/{run_b}/report", headers=_h(alice))).json()
        assert "REPORT-A-UNIQUE" in rep_a["markdown"] and "REPORT-B-UNIQUE" not in rep_a["markdown"]
        assert "REPORT-B-UNIQUE" in rep_b["markdown"] and "REPORT-A-UNIQUE" not in rep_b["markdown"]


class TestConcurrencyAcrossUsers:
    async def test_global_cap_holds_across_users(self, client, session_maker, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "2")
        settings_mod.get_settings.cache_clear()

        alice = await _user(client, session_maker, "alice@example.com")
        bob = await _user(client, session_maker, "bob@example.com")
        ja = await _job(client, alice, await _repo(client, alice, "a"))
        jb = await _job(client, bob, await _repo(client, bob, "b"))

        # 10 concurrent runs from BOTH users interleaved
        jobs = [ja, jb] * 5
        toks = [alice, bob] * 5
        results = await asyncio.gather(*[
            client.post(f"/jobs/{j}/run", headers=_h(t)) for j, t in zip(jobs, toks)
        ])
        assert all(r.status_code == 201 for r in results)

        # count running/preparing across the WHOLE system (both users)
        async with session_maker() as s:
            rows = (await s.scalars(select(Run))).all()
        running = sum(1 for r in rows if r.status in ("running", "preparing"))
        queued = sum(1 for r in rows if r.status == "queued")
        assert running <= 2, f"global cap exceeded across users: {running}"
        assert running + queued == 10
        settings_mod.get_settings.cache_clear()


class TestDashboardAndTreeIsolation:
    """The dashboard/findings-extraction + file-tree paths respect the same ACL."""

    async def test_cross_user_dashboard_metrics_and_tree_blocked(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        bob = await _user(client, session_maker, "bob@example.com")
        rb = await _repo(client, bob, "bob-secret")           # bob's PRIVATE repo
        run_b = await _run(client, bob, await _job(client, bob, rb))

        # alice cannot reach bob's repo via any metrics/findings/tree path (404, no leak)
        assert (await client.get(f"/repositories/{rb}/metrics/timeline", headers=_h(alice))).status_code == 404
        assert (await client.get(f"/repositories/{rb}/tree", headers=_h(alice))).status_code == 404
        assert (await client.get(f"/runs/{run_b}/metrics", headers=_h(alice))).status_code == 404
        # owner can
        assert (await client.get(f"/repositories/{rb}/metrics/timeline", headers=_h(bob))).status_code == 200
        assert (await client.get(f"/repositories/{rb}/tree", headers=_h(bob))).status_code == 200

    async def test_dashboard_metrics_scoped_to_user(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        bob = await _user(client, session_maker, "bob@example.com")
        await _run(client, alice, await _job(client, alice, await _repo(client, alice, "ALICE-only")))
        rb = await _repo(client, bob, "BOB-only")
        run_b = await _run(client, bob, await _job(client, bob, rb))
        # mark bob's run succeeded + compute its metrics so it would show on a dashboard
        from src.webapi.metrics_service import upsert_run_metrics
        async with session_maker() as s:
            run = await s.get(Run, __import__("uuid").UUID(run_b))
            run.status = RUN_SUCCEEDED
            await s.commit()
            await upsert_run_metrics(s, run)
        # alice's dashboard must not include bob's repo
        import json as _json
        dash = (await client.get("/dashboard/metrics", headers=_h(alice))).json()
        names = [r["repository_name"] for r in dash.get("top_repositories", [])]
        assert "BOB-only" not in _json.dumps(dash)
        assert "BOB-only" not in names

    async def test_cross_run_metrics_do_not_contaminate(self, client, session_maker):
        # Two runs on two repos with different planted findings never share metrics.
        alice = await _user(client, session_maker, "alice@example.com")
        ra = await _repo(client, alice, "repo-A")
        rb = await _repo(client, alice, "repo-B")
        run_a = await _run(client, alice, await _job(client, alice, ra))
        run_b = await _run(client, alice, await _job(client, alice, rb))
        row_a = await _run_row(session_maker, run_a)
        row_b = await _run_row(session_maker, run_b)
        # plant DIFFERENT critique findings into each run's own deliverables
        from src.webapi.reports import deliverables_dir
        import json as _json
        for row, sev, n in ((row_a, "critical", 3), (row_b, "low", 1)):
            base = deliverables_dir(row.data_dir, row.session_id)
            os.makedirs(base, exist_ok=True)
            anns = {f"F-{i}": {"severity_adjusted": sev, "confidence": "confirmed",
                               "include_in_report": True, "group_id": f"g{i}"} for i in range(n)}
            with open(os.path.join(base, "findings_critique.json"), "w") as fh:
                _json.dump({"annotations": anns}, fh)
            from src.webapi.metrics_service import upsert_run_metrics
            async with session_maker() as s:
                run = await s.get(Run, row.id); run.status = RUN_SUCCEEDED; await s.commit()
                await upsert_run_metrics(s, run)
        ma = (await client.get(f"/runs/{run_a}/metrics", headers=_h(alice))).json()
        mb = (await client.get(f"/runs/{run_b}/metrics", headers=_h(alice))).json()
        assert ma["severity_counts"]["critical"] == 3 and ma["severity_counts"]["low"] == 0
        assert mb["severity_counts"]["low"] == 1 and mb["severity_counts"]["critical"] == 0
