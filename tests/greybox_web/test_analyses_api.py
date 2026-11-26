"""Unified ``GET /analyses``: both modes, existing white-box ACL, cursors."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from src.greybox_web.models import GreyboxFinding, GreyboxRun, GreyboxTarget
from src.webapi.models import Run, RunMetrics
from tests.greybox_web.conftest import create_target, h, other_user_token, user_id


async def _repo(client, tok, name, private=True):
    r = await client.post("/repositories", headers=h(tok),
                          json={"name": name, "source_type": "upload", "is_private": private})
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


async def _wb_run(client, tok, repo_id, job_name="nightly"):
    j = await client.post("/jobs", headers=h(tok), json={
        "repository_id": repo_id, "name": job_name, "stage_preset": "vuln"})
    assert j.status_code == 201, j.text
    r = await client.post(f"/jobs/{j.json()['id']}/run", headers=h(tok))
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _gb_run(session_maker, target_id, owner_id, status="succeeded",
                  created_at=None, findings=()):
    async with session_maker() as s:
        t = await s.get(GreyboxTarget, uuid.UUID(target_id))
        run = GreyboxRun(target_id=t.id, owner_id=owner_id, status=status, phase="checks",
                         base_url=t.base_url, scope=t.scope, limits=t.limits, checks=[],
                         created_at=created_at or datetime.now(timezone.utc))
        s.add(run)
        await s.flush()
        for i, (sev, fstatus) in enumerate(findings):
            s.add(GreyboxFinding(
                run_id=run.id, dedup_key=f"k{i}", check_id="headers.security", title="t",
                severity=sev, status=fstatus, confidence="high", description="d",
                location={}, evidence=[], detection_hints=[], references=[],
                first_event_seq=1, version=1))
        await s.commit()
        return str(run.id)


async def _all_pages(client, tok, **params):
    items, cursor = [], None
    for _ in range(50):
        p = dict(params) | ({"cursor": cursor} if cursor else {})
        r = await client.get("/analyses", headers=h(tok), params=p)
        assert r.status_code == 200, r.text
        body = r.json()
        items += body["items"]
        cursor = body["next_cursor"]
        if not cursor:
            return items
    raise AssertionError("pagination did not terminate")


class TestUnifiedList:
    async def test_both_modes_and_shapes(self, client, user_token, session_maker):
        uid = await user_id(session_maker, "user@example.com")
        repo = await _repo(client, user_token, "shop-src")
        wb = await _wb_run(client, user_token, repo)
        t = await create_target(client, user_token, name="shop")
        gb = await _gb_run(session_maker, t["id"], uid, findings=[
            ("high", "verified"), ("low", "candidate"), ("medium", "rejected")])

        body = (await client.get("/analyses", headers=h(user_token))).json()
        assert body["next_cursor"] is None
        by_id = {i["id"]: i for i in body["items"]}
        assert set(by_id) == {wb, gb}
        g = by_id[gb]
        assert g["mode"] == "greybox" and g["name"] == "shop"
        assert g["subject"] == {"type": "target", "id": t["id"], "name": "shop",
                                "base_url": t["base_url"]}
        assert g["href"] == f"/greybox/runs/{gb}"
        assert g["owner_id"] == str(uid) and g["status"] == "succeeded"
        assert g["findings"] == {"total": 2, "by_severity": {
            "critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0}}
        w = by_id[wb]
        assert w["mode"] == "whitebox" and w["name"] == "nightly"
        assert w["subject"] == {"type": "repository", "id": repo, "name": "shop-src",
                                "base_url": None}
        assert w["href"] == f"/runs/{wb}"
        assert w["findings"] is None   # no RunMetrics row yet
        expected_keys = {"mode", "id", "name", "subject", "status", "phase", "owner_id",
                         "created_at", "started_at", "finished_at", "duration_s",
                         "findings", "href"}
        assert set(g) == expected_keys and set(w) == expected_keys

    async def test_whitebox_findings_from_metrics(self, client, user_token, session_maker):
        repo = await _repo(client, user_token, "r")
        wb = await _wb_run(client, user_token, repo)
        async with session_maker() as s:
            s.add(RunMetrics(run_id=uuid.UUID(wb), repository_id=uuid.UUID(repo),
                             total_findings=4, critical=1, high=1, medium=1, low=0,
                             informational=1))
            await s.commit()
        item = (await client.get("/analyses", headers=h(user_token),
                                 params={"mode": "whitebox"})).json()["items"][0]
        assert item["findings"] == {"total": 4, "by_severity": {
            "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 1}}

    async def test_mode_filter(self, client, user_token, session_maker):
        uid = await user_id(session_maker, "user@example.com")
        wb = await _wb_run(client, user_token, await _repo(client, user_token, "r"))
        t = await create_target(client, user_token)
        gb = await _gb_run(session_maker, t["id"], uid)
        wb_only = (await client.get("/analyses", headers=h(user_token),
                                    params={"mode": "whitebox"})).json()["items"]
        gb_only = (await client.get("/analyses", headers=h(user_token),
                                    params={"mode": "greybox"})).json()["items"]
        assert [i["id"] for i in wb_only] == [wb]
        assert [i["id"] for i in gb_only] == [gb]
        bad = await client.get("/analyses", headers=h(user_token), params={"mode": "blackbox"})
        assert bad.status_code == 422

    async def test_status_and_q_filters(self, client, user_token, session_maker):
        uid = await user_id(session_maker, "user@example.com")
        t1 = await create_target(client, user_token, name="alpha-shop")
        t2 = await create_target(client, user_token, name="beta-blog")
        a = await _gb_run(session_maker, t1["id"], uid, status="failed")
        b = await _gb_run(session_maker, t2["id"], uid, status="running")
        r = (await client.get("/analyses", headers=h(user_token),
                              params={"status": "failed"})).json()["items"]
        assert [i["id"] for i in r] == [a]
        r = (await client.get("/analyses", headers=h(user_token),
                              params={"status": "failed,running"})).json()["items"]
        assert {i["id"] for i in r} == {a, b}
        r = (await client.get("/analyses", headers=h(user_token),
                              params={"q": "BLOG"})).json()["items"]
        assert [i["id"] for i in r] == [b]
        r = (await client.get("/analyses", headers=h(user_token),
                              params={"q": "%"})).json()["items"]
        assert r == []   # LIKE wildcards are escaped


class TestWhiteboxAcl:
    async def test_existing_repo_acl_applies(self, client, user_token, admin_token,
                                             session_maker):
        other = await other_user_token(client, session_maker)
        private = await _wb_run(client, other, await _repo(client, other, "p", private=True))
        public = await _wb_run(client, other, await _repo(client, other, "q", private=False))
        mine = await _wb_run(client, user_token, await _repo(client, user_token, "m"))

        seen = {i["id"] for i in await _all_pages(client, user_token)}
        assert seen == {public, mine}    # team-visible public repo, not the private one
        admin_seen = {i["id"] for i in await _all_pages(client, admin_token)}
        assert {private, public, mine} <= admin_seen
        # unchanged white-box list agrees with the unified view
        legacy = {r["id"] for r in (await client.get("/runs", headers=h(user_token))).json()}
        wb_only = {i["id"] for i in await _all_pages(client, user_token, mode="whitebox")}
        assert legacy == wb_only

    async def test_greybox_owner_only(self, client, user_token, admin_token, session_maker):
        other = await other_user_token(client, session_maker)
        other_id = await user_id(session_maker, "other@example.com")
        t = await create_target(client, other)
        gb = await _gb_run(session_maker, t["id"], other_id)
        assert await _all_pages(client, user_token, mode="greybox") == []
        assert [i["id"] for i in await _all_pages(client, admin_token, mode="greybox")] == [gb]


class TestFlagAndPagination:
    async def test_flag_off_whitebox_only(self, client, user_token, session_maker, set_env):
        uid = await user_id(session_maker, "user@example.com")
        wb = await _wb_run(client, user_token, await _repo(client, user_token, "r"))
        t = await create_target(client, user_token)
        await _gb_run(session_maker, t["id"], uid)
        set_env("VIGILO_GREYBOX_WEB_ENABLED", "false")
        r = await client.get("/analyses", headers=h(user_token))
        assert r.status_code == 200
        assert [i["id"] for i in r.json()["items"]] == [wb]
        r = await client.get("/analyses", headers=h(user_token), params={"mode": "greybox"})
        assert r.json() == {"items": [], "next_cursor": None}

    async def test_merged_cursor_pagination_with_timestamp_ties(self, client, user_token,
                                                                session_maker):
        uid = await user_id(session_maker, "user@example.com")
        repo = await _repo(client, user_token, "r")
        wb_ids = [await _wb_run(client, user_token, repo, f"job{i}") for i in range(3)]
        t = await create_target(client, user_token)
        tie = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        # force white-box and grey-box runs to share the exact same created_at
        async with session_maker() as s:
            for i, rid in enumerate(wb_ids):
                run = await s.get(Run, uuid.UUID(rid))
                run.created_at = tie if i < 2 else tie - timedelta(minutes=5)
            await s.commit()
        gb_ids = [await _gb_run(session_maker, t["id"], uid, created_at=tie) for _ in range(3)]
        gb_ids.append(await _gb_run(session_maker, t["id"], uid,
                                    created_at=tie + timedelta(minutes=1)))

        for size in (1, 2, 3, 100):
            items = await _all_pages(client, user_token, limit=size)
            ids = [i["id"] for i in items]
            assert len(ids) == len(set(ids)) == 7, size
            assert set(ids) == set(wb_ids) | set(gb_ids)
            keys = [(i["created_at"], i["mode"], i["id"]) for i in items]
            assert keys == sorted(keys, reverse=True)

    async def test_limit_capped_and_bad_cursor(self, client, user_token):
        r = await client.get("/analyses", headers=h(user_token), params={"limit": 500})
        assert r.status_code == 200
        r = await client.get("/analyses", headers=h(user_token), params={"cursor": "Zm9v"})
        assert r.status_code == 422
