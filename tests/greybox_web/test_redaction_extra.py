"""Extra redaction coverage: response bodies, URL-bearing
response headers, structural masking of asset/param/finding data, the report code
fence, and failing a run whose credential cannot be loaded."""
from __future__ import annotations

import json
import uuid

from sqlalchemy import select

from src.audit import redact
from src.greybox_web import redaction
from src.greybox_web.models import (
    RUN_CHILD_MODELS,
    GreyboxAsset,
    GreyboxEvent,
    GreyboxFinding,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxTarget,
)
from src.greybox_web.report import _excerpt, _fence_for
from src.greybox_web.supervisor import BODY_STORE_CAP, _store_body
from tests.greybox_web.conftest import (
    create_target,
    h,
    run_worker_once,
    start_run,
)

SECRET = "session=extra-secret-cookie-99"
RAW = "extra-secret-cookie-99"
STRUCTURAL = ("ABC", "LOCSECRET789", "CSRFVALUE123", "APIKEYVALUE456")


def _blob(value) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return value if isinstance(value, str) else ""


async def test_full_run_redacts_bodies_headers_and_structure(
        client, user_token, target_server, session_maker):
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "x", "secret": SECRET})
    cred = r.json()
    t = await create_target(client, user_token, base_url=target_server.url + "leaky",
                            credential_id=cred["id"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert await run_worker_once(session_maker) == run_id
    try:
        async with session_maker() as s:
            run = await s.get(GreyboxRun, run_id)
            assert run.status == "succeeded", (run.status, run.end_reason)
            ex = (await s.scalars(select(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == run_id,
                GreyboxHttpExchange.path == "/leaky"))).all()
            assert ex
            # The target echoed the cookie; the stored body is masked.
            assert all(RAW not in (e.response_body or "") for e in ex)
            assert any("cookie: " in (e.response_body or "") for e in ex)
            # Location keeps its name but loses the token value.
            locs = [p[1] for e in ex for p in e.response_headers
                    if p[0].lower() == "location"]
            assert locs and all("LOCSECRET789" not in v and "token=***" in v
                                for v in locs), locs

            # Whole-DB scan: registered secret anywhere; structural values in
            # everything except the raw captured bodies / request-side rows.
            for model in (GreyboxTarget, GreyboxRun, *RUN_CHILD_MODELS):
                for row in (await s.scalars(select(model))).all():
                    for col in model.__table__.columns:
                        blob = _blob(getattr(row, col.name))
                        assert RAW not in blob, (model.__tablename__, col.name)
            structured = [GreyboxAsset, GreyboxFinding, GreyboxEvent]
            for model in structured:
                for row in (await s.scalars(select(model))).all():
                    for col in model.__table__.columns:
                        blob = _blob(getattr(row, col.name))
                        for needle in STRUCTURAL:
                            assert needle not in blob, (
                                model.__tablename__, col.name, needle, blob[:200])
            assets = (await s.scalars(select(GreyboxAsset).where(
                GreyboxAsset.run_id == run_id))).all()
            assert any("csrf_token" in _blob(a.data) for a in assets), \
                "form field names should stay visible"
    finally:
        redact.clear()


def test_store_body_redacts_before_truncating():
    redact.register_secret("boundary-secret-value")
    try:
        pad = "a" * (BODY_STORE_CAP - 8)
        body = (pad + "boundary-secret-value tail").encode()
        text, trunc, _ = _store_body(body, "text/html")
        assert trunc
        assert "boundary" not in text and "secret-value" not in text
        assert "boundary-secret-value" not in (text + "")
    finally:
        redact.clear()


def test_structural_masking_helpers():
    assert "token=***" in redaction.scrub("see /x?token=ABC&q=1")
    assert "q=1" in redaction.scrub("see /x?token=ABC&q=1")
    assert "ABC" not in redaction.scrub("https://h/p?api_key=ABC#f")
    out = redaction.structured({"url": "http://h/?session=S1",
                                "fields": {"csrf": "T", "q": "v"}})
    assert "S1" not in json.dumps(out) and out["fields"] == {"csrf": "***", "q": "v"}
    hdrs = dict(redaction.headers([("Location", "/a?token=Z"),
                                   ("Refresh", "0; url=/a?pass=Z"),
                                   ("Link", "</a?key=Z>; rel=next")]))
    assert all("Z" not in v for v in hdrs.values())


def test_excerpt_fence_cannot_be_broken_out_of():
    content = "```\n# injected heading\n````\n[x](http://evil)"
    fence = _fence_for(_excerpt(content))
    assert len(fence) > 4          # longer than the longest backtick run (4)
    assert fence not in content
    assert _fence_for("plain") == "```"


async def test_unloadable_credential_fails_the_run(
        client, user_token, target_server, session_maker):
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "gone", "secret": "session=gone-cred-1"})
    cred = r.json()
    t = await create_target(client, user_token, base_url=target_server.url,
                            credential_id=cred["id"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    from src.webapi.models import Credential
    async with session_maker() as s:        # the credential vanishes before start
        await s.delete(await s.get(Credential, uuid.UUID(cred["id"])))
        await s.commit()
    try:
        assert await run_worker_once(session_maker) == run_id
        async with session_maker() as s:
            run = await s.get(GreyboxRun, run_id)
            assert run.status == "failed", (run.status, run.end_reason)
            assert "credential" in (run.error_summary or "").lower()
            n = len((await s.scalars(select(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == run_id))).all())
            assert n == 0                    # never ran unauthenticated
            ev = (await s.scalars(select(GreyboxEvent).where(
                GreyboxEvent.run_id == run_id,
                GreyboxEvent.kind == "run.failed"))).all()
            assert ev and "credential" in json.dumps(ev[0].data).lower()
    finally:
        redact.clear()


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
