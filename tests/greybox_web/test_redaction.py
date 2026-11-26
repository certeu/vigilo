"""A cookie credential is attached to every
in-scope request but never persists. The whole grey-box database is scanned for
the secret in raw and URL-encoded forms; the Cookie header is masked wholesale;
Set-Cookie masking keeps the name and the attributes (``cookies.flags`` evidence
stays meaningful) while masking only the value; the report carries no secret.

The mask registry (``src.audit.redact``) is process-global: the test clears it
in a ``finally`` so later tests are not over-redacted by this run's secret.
"""
from __future__ import annotations

import json
import re
import uuid

from sqlalchemy import select

from src.audit import redact
from src.greybox_web.models import (
    RUN_CHILD_MODELS,
    GreyboxHttpExchange,
    GreyboxRun,
    GreyboxTarget,
)
from tests.greybox_web.conftest import (
    create_target,
    h,
    run_worker_once,
    start_run,
)

SECRET = "session=topsecret-cookie-value-42"
# The raw cookie value, the whole pair, and percent-encoded forms (the equals
# sign and the hyphens) that a target could echo back in a URL or a form body.
NEEDLES = (
    "topsecret-cookie-value-42",
    "session=topsecret-cookie-value-42",
    "topsecret%2Dcookie%2Dvalue%2D42",
    "session%3Dtopsecret",
)
# /login answers: Set-Cookie: session=<value>; Path=/ — masked to this.
MASKED_SET_COOKIE = re.compile(r"session=\*\*\*; Path=/")


def _scan_text(value) -> str:
    """Everything a column value could contribute to a stored leak."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return ""    # uuids, datetimes and numbers cannot carry the secret


def _context(blob: str, needle: str) -> str:
    """A short window around the leak, for the failure message."""
    i = blob.find(needle)
    return "" if i < 0 else blob[max(0, i - 60):i + len(needle) + 60]


async def test_cookie_secret_never_persisted(client, user_token, target_server,
                                             session_maker):
    r = await client.post("/credentials", headers=h(user_token), json={
        "kind": "cookie_header", "label": "staging session", "secret": SECRET})
    assert r.status_code == 201, r.text
    cred = r.json()
    assert SECRET not in json.dumps(cred)      # the API never echoes it back

    t = await create_target(client, user_token, base_url=target_server.url,
                            credential_id=cred["id"])
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert await run_worker_once(session_maker) == run_id

    try:
        # The run completed and made requests carrying the credential.
        async with session_maker() as s:
            run = await s.get(GreyboxRun, run_id)
            assert run.status == "succeeded", (run.status, run.end_reason)
            exchanges = (await s.scalars(select(GreyboxHttpExchange).where(
                GreyboxHttpExchange.run_id == run_id))).all()
            assert exchanges

        # The attached Cookie header is masked wholesale.
        assert any(["Cookie", "***"] in ex.request_headers for ex in exchanges), \
            "no exchange carries the masked Cookie header"

        # Set-Cookie keeps the name and attributes, masking only the value.
        set_cookies = [pair[1] for ex in exchanges for pair in ex.response_headers
                       if str(pair[0]).lower() == "set-cookie"]
        assert any(MASKED_SET_COOKIE.fullmatch(v) for v in set_cookies), \
            set_cookies

        # Whole-database leak scan: every column of every grey-box row, raw and
        # encoded forms alike.
        async with session_maker() as s:
            for model in (GreyboxTarget, GreyboxRun, *RUN_CHILD_MODELS):
                for row in (await s.scalars(select(model))).all():
                    for column in model.__table__.columns:
                        blob = _scan_text(getattr(row, column.name))
                        for needle in NEEDLES:
                            assert needle not in blob, (
                                f"secret leaked into {model.__tablename__}."
                                f"{column.name} ({needle!r}), near: "
                                f"{_context(blob, needle)!r}")

        # The generated report markdown carries no secret either (the row itself
        # was already scanned above; this checks the API surface).
        r = await client.get(f"/greybox/runs/{run_id}/report", headers=h(user_token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "ready"
        assert all(needle not in body["markdown"] for needle in NEEDLES), \
            "the report leaked the cookie credential"
    finally:
        redact.clear()   # the mask registry is process-global


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
