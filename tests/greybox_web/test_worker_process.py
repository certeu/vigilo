"""The standalone worker (the default executor) must run a scan end to end.

Regression (acceptance review, 2026-11-20): ``python -m src.greybox_web.worker``
never imported the platform models, so ``users``/``credentials`` were missing from
the metadata, every flush raised NoReferencedTableError, the supervisor swallowed
it and the run sat in ``preparing`` until the reaper failed it. In-process tests
(and the API) import those models implicitly, which hid the bug; this test runs the
real entry point in a fresh interpreter."""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from pathlib import Path

from src.greybox_web.models import GreyboxRun
from tests.greybox_web.conftest import FAST_LIMITS, create_target, start_run

REPO = Path(__file__).resolve().parents[2]


def test_fresh_worker_interpreter_registers_platform_tables():
    code = ("import src.greybox_web.worker\n"
            "from src.greybox_web.models import GreyboxRun\n"
            "md = GreyboxRun.metadata\n"
            "assert 'users' in md.tables and 'credentials' in md.tables, sorted(md.tables)\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr


async def test_worker_once_subprocess_completes_a_run(client, user_token, session_maker,
                                                      target_server, tmp_path):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=dict(FAST_LIMITS))
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])

    env = {**os.environ,
           "VIGILO_DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'greybox-test.db'}"}
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "src.greybox_web.worker", "--once", cwd=REPO, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
    assert proc.returncode == 0, err.decode()[-2000:]
    assert f"finished run {run_id}" in out.decode(), (out.decode(), err.decode()[-2000:])

    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
    assert run.status == "succeeded", (run.status, run.end_reason, run.error_summary)
    assert run.requests_made > 0
