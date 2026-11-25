"""The report of a full default run against the live synthetic target.

One run over every implemented check, then GET .../report: deterministic markdown
whose Verified findings section carries one verified finding per planted weakness
(with detection hints) — including the pentest checks (reflection, error-based
injection, open redirect, debug disclosure) — where the /.env soft-404 and
/safe-search escaped-reflection negative controls never become findings, and which
contains no patch/MR vocabulary. The same markdown is served by the download
endpoint as a text/markdown attachment named after the run.
"""
from __future__ import annotations

import uuid

from tests.greybox_web.conftest import h, run_worker_once, start_run


async def test_full_report_markdown_and_download(client, user_token, session_maker,
                                                 live_target):
    r = await start_run(client, user_token, live_target["id"],
                        key=f"report-{uuid.uuid4().hex[:12]}")
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    assert str(await run_worker_once(session_maker)) == run_id

    r = await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))
    body = r.json()
    assert body["status"] == "succeeded", body.get("error_summary")
    assert body["report_status"] == "ready"

    r = await client.get(f"/greybox/runs/{run_id}/report", headers=h(user_token))
    assert r.status_code == 200
    report = r.json()
    assert report["status"] == "ready"
    md = report["markdown"]
    # header carries the real finish time and end reason (generated just before the
    # terminal event, when the run row has neither yet)
    run_line = next(l for l in md.splitlines() if l.startswith("- **Run:**"))
    assert "finished —" not in run_line and "(—)" not in run_line, run_line
    assert md

    # --- structure: the 10.5 sections in order of appearance
    for phrase in (
        "# Grey-box security assessment",
        "## Verified findings",
        "## Coverage",
        "## Limitations",
        "Endpoints checked:",           # the "N of M in-scope endpoints" line
    ):
        assert phrase in md, f"missing report section/line: {phrase!r}"

    # --- one verified finding per planted weakness, each with detection hints
    for phrase in (
        "Missing Content-Security-Policy header",
        "Exposed file: /.git/HEAD",
        "CORS reflects arbitrary origins with credentials",
        "Cookie 'session' is set without HttpOnly",
        "server header reveals a software version",
        "Directory listing: /static/",
        "Unencoded reflection of parameter q",       # /search (injection.reflection)
        "Error-based injection indicator on id",     # /item (injection.errors)
        "Open redirect through to",                  # /redirect (redirect.open)
        "Error/debug page disclosed at /debug",      # /debug (info.errors)
        "Detection hint",
    ):
        assert phrase in md, f"missing verified finding: {phrase!r}"

    # --- the pentest checks are defaults now, so a default run has work orders for
    # them and nothing is listed as not run (a scheduled-but-unregistered check is
    # still listed; see test_check_availability.py for the report-line helper).
    assert "Checks not run in this build" not in md

    # --- negative controls and vocabulary
    assert "Exposed file: /.env" not in md   # soft 404: no content signature, no finding
    verified_section = md.split("## Verified findings", 1)[1].split("\n## ", 1)[0]
    assert "safe-search" not in verified_section   # escaped reflection: no finding
    assert "Merge request" not in md         # no patch/MR sections (10.5)
    assert "Patch:" not in md

    # --- download: the same markdown as a text/markdown attachment
    r = await client.get(f"/greybox/runs/{run_id}/report/download",
                         headers=h(user_token))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert r.headers["content-disposition"] == \
        f'attachment; filename="greybox-report-{run_id[:8]}.md"'
    assert r.text == md


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
import pytest  # noqa: E402

pytestmark = pytest.mark.slow
