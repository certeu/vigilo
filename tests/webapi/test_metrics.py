from __future__ import annotations

import json
import os

from src.webapi.engine.provider import get_engine
from src.webapi.metrics import extract_run_metrics
from src.webapi.reports import deliverables_dir


def _write_stats(data_dir, session_id, stats):
    d = deliverables_dir(data_dir, session_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "report_stats.json"), "w") as fh:
        json.dump(stats, fh)


class TestExtract:
    def test_from_report_stats(self, tmp_path):
        stats = {
            "totals": {"unique_findings": 12},
            "severity_counts": {"critical": 3, "high": 5, "medium": 2, "low": 2},
            "status_counts": {"exploited": 7, "unconfirmed": 5},
            "category_counts": {
                "injection": {"total": 4}, "supply_chain": {"total": 6},
            },
        }
        _write_stats(str(tmp_path), "s1", stats)
        m = extract_run_metrics(str(tmp_path), "s1")
        assert m["total_findings"] == 12
        assert m["severity_counts"]["critical"] == 3
        assert m["status_counts"]["exploited"] == 7
        assert m["supply_chain"] == 6
        assert m["category_counts"]["injection"] == 4

    def test_findings_index_fallback(self, tmp_path):
        d = deliverables_dir(str(tmp_path), "s2")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "findings_index.json"), "w") as fh:
            json.dump({"findings": [
                {"severity": "critical", "vuln_type": "injection", "status": "exploited"},
                {"severity": "high", "vuln_type": "supply_chain", "status": "unconfirmed"},
            ]}, fh)
        m = extract_run_metrics(str(tmp_path), "s2")
        assert m["total_findings"] == 2
        assert m["severity_counts"]["critical"] == 1
        assert m["supply_chain"] == 1

    def test_none_when_absent(self, tmp_path):
        assert extract_run_metrics(str(tmp_path), "nope") is None


async def _mock_run(client, token):
    """Create repo+job and run it with the MockEngine active, returning the run json."""
    from src.webapi.engine.mock import MockEngine
    client._app.dependency_overrides[get_engine] = lambda: MockEngine()
    h = {"Authorization": f"Bearer {token}"}
    repo = (await client.post("/repositories", headers=h,
            json={"name": "demo", "source_type": "upload"})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "full"})).json()
    run = (await client.post(f"/jobs/{job['id']}/run", headers=h)).json()
    return repo, run


class TestDashboardEndpoints:
    async def test_mock_run_produces_metrics(self, client, user_token):
        repo, run = await _mock_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        assert run["status"] == "succeeded"
        # GET run triggers metric computation
        await client.get(f"/runs/{run['id']}", headers=h)
        m = await client.get(f"/runs/{run['id']}/metrics", headers=h)
        assert m.status_code == 200, m.text
        assert m.json()["total_findings"] > 0

    async def test_repo_timeline_and_global(self, client, user_token):
        repo, run = await _mock_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        await client.get(f"/runs/{run['id']}", headers=h)
        tl = await client.get(f"/repositories/{repo['id']}/metrics/timeline", headers=h)
        assert tl.status_code == 200
        assert len(tl.json()["timeline"]) == 1
        g = await client.get("/dashboard/metrics", headers=h)
        assert g.status_code == 200
        body = g.json()
        assert body["repositories_scanned"] == 1
        assert body["total_findings"] > 0
        assert "severity_totals" in body and "top_repositories" in body


class TestMockEngineScaling:
    def test_scaled_stats_are_smaller(self):
        from src.webapi.engine.mock import _scaled_stats
        small = _scaled_stats(0.25)
        assert small["severity_counts"]["critical"] >= 0
        # scaling by 0.25 should not exceed the sample's own critical count
        full = _scaled_stats(1.0)
        assert small["severity_counts"]["critical"] <= full["severity_counts"]["critical"]
