from __future__ import annotations

import os

from src.webapi.logs import log_path_for, read_from


async def _repo_job_run(client, token):
    h = {"Authorization": f"Bearer {token}"}
    repo = (await client.post("/repositories", headers=h,
            json={"name": "r", "source_type": "upload"})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
    run = (await client.post(f"/jobs/{job['id']}/run", headers=h)).json()
    return run


def _write_log(data_dir: str, session_id: str, lines: list[str]) -> str:
    path = log_path_for(data_dir, session_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


class TestReadFrom:
    def test_missing_file_returns_empty(self, tmp_path):
        lines, off = read_from(str(tmp_path / "nope.log"), 0)
        assert lines == [] and off == 0

    def test_incremental_offset(self, tmp_path):
        p = tmp_path / "workflow.log"
        p.write_text("a\nb\n", encoding="utf-8")
        lines, off = read_from(str(p), 0)
        assert lines == ["a", "b"]
        # append and read only the new line from the returned offset
        with open(p, "a", encoding="utf-8") as fh:
            fh.write("c\n")
        more, off2 = read_from(str(p), off)
        assert more == ["c"] and off2 > off


class TestLogsEndpoints:
    async def test_paged_logs(self, client, user_token, monkeypatch):
        # find the run's data_dir/session by reading settings + run fields
        from src.webapi.settings import get_settings
        run = await _repo_job_run(client, user_token)
        data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
        _write_log(data_dir, run["session_id"], ["line-1", "line-2"])
        h = {"Authorization": f"Bearer {user_token}"}
        resp = await client.get(f"/runs/{run['id']}/logs", headers=h)
        assert resp.status_code == 200
        assert resp.json()["lines"] == ["line-1", "line-2"]
        assert resp.json()["offset"] > 0

    async def test_sse_stream_drains_terminal_run(self, client, user_token):
        from src.webapi.settings import get_settings
        run = await _repo_job_run(client, user_token)
        data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
        _write_log(data_dir, run["session_id"], ["evt-a", "evt-b"])
        h = {"Authorization": f"Bearer {user_token}"}
        # cancel so the stream terminates promptly
        await client.post(f"/runs/{run['id']}/cancel", headers=h)
        async with client.stream("GET", f"/runs/{run['id']}/logs/stream", headers=h) as resp:
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            body = ""
            async for chunk in resp.aiter_text():
                body += chunk
        assert "evt-a" in body and "evt-b" in body
        assert "event: end" in body
