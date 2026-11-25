"""Name-based masking of target-issued secrets in stored response bodies
and evidence excerpts. Everything else stays byte-identical."""
from __future__ import annotations

import json
import uuid

from sqlalchemy import select

from src.audit import redact
from src.greybox_web import redaction
from src.greybox_web.models import (
    RUN_CHILD_MODELS,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxTarget,
)
from src.greybox_web.supervisor import BODY_STORE_CAP, _store_body
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    h,
    run_worker_once,
    start_run,
)

SECRETS = ("METACSRF-AAA111", "LINKTOKEN-BBB222", "HIDDENCSRF-CCC333",
           "APIKEYINPUT-DDD444", "JSONTOKEN-EEE555", "JSONPASS-FFF666")
VISIBLE = ("ORDINARY-CONTENT", "NOTE-VISIBLE", "VISIBLE-USER", "Rome")


def test_html_inputs_meta_and_links():
    html = ('<meta name="csrf-token" content="M1">'
            '<input type="hidden" name="csrf_token" value="C1">'
            "<input value='K1' id=api_key><input name=\"q\" value=\"keep\">"
            '<input name="note" value="n"><a href="/x?token=T1&amp;p=2">x</a>'
            '<form action="/a?session=S1"></form><meta name="viewport" content="w">')
    out = redaction.body_text(html)
    for s in ("M1", "C1", "K1", "T1", "S1"):
        assert s not in out, s
    assert out.count(redaction.MASK) == 5
    assert 'name="q" value="keep"' in out and 'content="w"' in out
    assert "&amp;p=2" in out


def test_html_excerpt_fragments_are_masked():
    frag = '<input type="hidden" name="api_key" value="CUTVAL'      # cut mid-value
    assert "CUTVAL" not in redaction.body_text(frag)


def test_json_values_by_key_any_depth_and_bytes_preserved():
    src = ('{"a": 1, "access_token": "T1", "nested": {"password": {"x": "y"}, '
           '"ok": "v"}, "keys": [1, 2], "empty_secret": "", "n": null}')
    out = redaction.body_text(src)
    assert "T1" not in out and '"x"' not in out
    assert '"a": 1' in out and '"ok": "v"' in out
    assert '"empty_secret": ""' in out and '"n": null' in out
    json.loads(out)                                   # still valid JSON
    # invalid / truncated JSON falls back to the same scan
    assert "tr" not in redaction.body_text('{"access_token": "tr').replace("***", "")
    assert redaction.MASK in redaction.body_text('{"access_token": "tr')


def test_form_encoded_bodies_still_masked():
    out = redaction.body("user=a&password=hunter2&csrf_token=Z",
                         "application/x-www-form-urlencoded")
    assert "hunter2" not in out and "Z" not in out.replace("***", "") and "user=a" in out
    text, _, _ = _store_body(b"user=a&password=hunter2",
                             "application/x-www-form-urlencoded; charset=utf-8")
    assert "hunter2" not in text and "user=a" in text


def test_untouched_content_is_byte_identical():
    for s in ("ref: refs/heads/main\n", "<html><body>Hello <b>world</b></body></html>",
              '{"items": [1, 2, 3], "ok": true}', "Server: DemoServer/1.2.3"):
        assert redaction.body_text(s) == s


def test_store_body_masks_before_truncation():
    pad = "a" * (BODY_STORE_CAP - 20)
    body = (pad + '<input name="csrf_token" value="SPLITSECRETVALUE-123"> tail').encode()
    text, trunc, _ = _store_body(body, "text/html")
    assert trunc and "SPLITSECRET" not in text and "SPLIT" not in text[-30:]


async def _run_against(client, user_token, session_maker, base_url):
    t = await create_target(client, user_token, base_url=base_url,
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    run_id = uuid.UUID(r.json()["id"])
    assert await run_worker_once(session_maker) == run_id
    return run_id


async def test_full_run_stores_no_target_issued_secrets(
        client, user_token, target_server, session_maker):
    redact.clear()
    run_id = await _run_against(client, user_token, session_maker,
                                target_server.url + "leaky-body")
    try:
        async with session_maker() as s:
            run = await s.get(GreyboxRun, run_id)
            assert run.status == "succeeded", (run.status, run.end_reason)
            rows = (await s.scalars(select(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == run_id))).all()
        paths = {e.path for e in rows}
        assert {"/leaky-body", "/leaky-json"} <= paths, paths

        # through the API (traffic detail), body by body
        api_bodies = []
        for e in rows:
            r = await client.get(f"/greybox/runs/{run_id}/traffic/{e.id}",
                                 headers=h(user_token))
            assert r.status_code == 200
            api_bodies.append(r.json()["response"]["body"] or "")
        joined = "\n".join(api_bodies)
        for secret in SECRETS:
            assert secret not in joined, secret
        for ok in VISIBLE:
            assert ok in joined, ok
        assert 'name="csrf_token"' in joined and "token=***" in joined

        r = await client.get(f"/greybox/runs/{run_id}/report", headers=h(user_token))
        assert r.status_code == 200
        findings = await client.get(f"/greybox/runs/{run_id}/findings",
                                    headers=h(user_token))
        for blob in (r.text, findings.text):
            for secret in SECRETS:
                assert secret not in blob, secret

        # DB-wide scan: nothing target-issued survives in any grey-box row
        async with session_maker() as s:
            for model in (GreyboxTarget, GreyboxRun, *RUN_CHILD_MODELS):
                for row in (await s.scalars(select(model))).all():
                    for col in model.__table__.columns:
                        v = getattr(row, col.name)
                        blob = json.dumps(v, default=str) if isinstance(
                            v, (dict, list)) else str(v)
                        for secret in SECRETS:
                            assert secret not in blob, (model.__tablename__, col.name)
    finally:
        redact.clear()
