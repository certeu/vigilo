"""refresh_run records when a white-box run ended (finished_at used to stay empty)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from src.webapi.engine import common


class _Client:
    def __init__(self, status: int, close_time=None):
        self._desc = SimpleNamespace(status=SimpleNamespace(value=status), close_time=close_time)

    def get_workflow_handle(self, _wid):
        desc = self._desc

        class _Handle:
            async def describe(self_inner):
                return desc
        return _Handle()


def _run(tmp_path, **kw):
    base = dict(id="r1", workflow_id="wf-1", status="running", error_summary=None,
                finished_at=None, current_phase=None, data_dir=str(tmp_path),
                session_id="s1", total_cost_usd=None)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _no_secrets(monkeypatch):
    async def _noop(_run):
        return None
    monkeypatch.setattr(common, "drop_run_secrets", _noop)

    async def _detail(_client, _wid):
        return "failed"
    monkeypatch.setattr(common, "failure_detail", _detail)


def _factory(client):
    async def f():
        return client
    return f


async def test_completed_run_takes_the_workflow_close_time(tmp_path):
    closed = datetime(2026, 11, 25, 10, 8, 0, tzinfo=timezone.utc)
    run = _run(tmp_path)
    await common.refresh_run(run, _factory(_Client(2, closed)))
    assert run.status == common.RUN_SUCCEEDED and run.finished_at == closed


async def test_naive_close_time_is_treated_as_utc(tmp_path):
    run = _run(tmp_path)
    await common.refresh_run(run, _factory(_Client(3, datetime(2026, 11, 25, 9, 0, 0))))
    assert run.finished_at == datetime(2026, 11, 25, 9, 0, 0, tzinfo=timezone.utc)


async def test_falls_back_to_now_without_a_close_time(tmp_path):
    run = _run(tmp_path)
    before = datetime.now(timezone.utc)
    await common.refresh_run(run, _factory(_Client(4, None)))
    assert run.status == common.RUN_CANCELLED
    assert before <= run.finished_at <= datetime.now(timezone.utc) + timedelta(seconds=1)


async def test_an_existing_end_time_is_never_overwritten(tmp_path):
    first = datetime(2026, 11, 1, tzinfo=timezone.utc)
    run = _run(tmp_path, status="succeeded", finished_at=first)
    await common.refresh_run(run, _factory(_Client(2, datetime(2026, 12, 1, tzinfo=timezone.utc))))
    assert run.finished_at == first


async def test_a_running_run_has_no_end_time(tmp_path):
    run = _run(tmp_path)
    await common.refresh_run(run, _factory(_Client(1, None)))
    assert run.status == common.RUN_RUNNING and run.finished_at is None
