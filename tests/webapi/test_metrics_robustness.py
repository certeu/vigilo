"""Robust findings extraction: real-shape sample, parse-error state, supply-chain flag.

Ensures the dashboard never silently shows zeros for an unparseable run and that a
scan that didn't include SCA is distinguishable from 'ran, found none'."""
from __future__ import annotations

import json
import os
import uuid

from src.webapi.metrics import extract_run_metrics
from src.webapi.metrics_service import (
    global_dashboard,
    metrics_to_dict,
    upsert_run_metrics,
)
from src.webapi.models import RUN_SUCCEEDED, Job, Repository, Run
from src.webapi.reports import deliverables_dir
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


def _write(base, name, data):
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, name), "w") as fh:
        json.dump(data, fh)


class TestRealShapeSample:
    """A trimmed but faithful copy of a real findings_critique.json + findings_index."""

    def test_grouped_counts_from_real_shape(self, tmp_path):
        base = deliverables_dir(str(tmp_path), "real")
        _write(base, "findings_index.json", {"by_type": {
            "injection": [{"ID": "INJ-VULN-02"}, {"ID": "INJ-VULN-04"}],
            "auth": [{"ID": "AUTH-VULN-01"}],
            "authz": [{"ID": "AUTHZ-VULN-03"}, {"ID": "AUTHZ-VULN-04"}],
            "crypto": [{"ID": "CRYPTO-003"}],
        }})
        _write(base, "findings_critique.json", {
            "version": "1.0",
            "summary": {"total_findings": 6},
            "annotations": {
                "INJ-VULN-02": {"severity_original": "high", "severity_adjusted": "high",
                                "confidence": "potential", "include_in_report": True,
                                "group_id": "g-inj-02"},
                # INJ-VULN-04 + AUTHZ-VULN-04 share a group -> one High unique finding
                "INJ-VULN-04": {"severity_original": "high", "severity_adjusted": "high",
                                "confidence": "potential", "include_in_report": True,
                                "group_id": "g-studio-import"},
                "AUTHZ-VULN-04": {"severity_original": "medium", "severity_adjusted": "high",
                                  "confidence": "potential", "include_in_report": True,
                                  "group_id": "g-studio-import"},
                # AUTH-VULN-01 + AUTHZ-VULN-03 share a group -> one High unique finding
                "AUTH-VULN-01": {"severity_original": "high", "severity_adjusted": "high",
                                 "confidence": "confirmed", "include_in_report": True,
                                 "group_id": "g-studio-auth"},
                "AUTHZ-VULN-03": {"severity_original": "high", "severity_adjusted": "high",
                                  "confidence": "potential", "include_in_report": True,
                                  "group_id": "g-studio-auth"},
                # excluded from the report body
                "CRYPTO-003": {"severity_original": "low", "severity_adjusted": "low",
                               "confidence": "theoretical", "include_in_report": False,
                               "group_id": "g-crypto"},
            },
        })
        m = extract_run_metrics(str(tmp_path), "real")
        assert m["source"] == "critique"
        # 5 annotations included, in 3 groups -> 3 unique High findings
        assert m["severity_counts"]["high"] == 3
        assert m["total_findings"] == 3
        # a confirmed member in one group -> that group counts as exploited
        assert m["status_counts"]["exploited"] == 1

    def test_supply_chain_packages_parsed_from_sca(self, tmp_path):
        base = deliverables_dir(str(tmp_path), "sca")
        _write(base, "findings_index.json", {"by_type": {"supply_chain": [{"ID": "SCA-1"}]}})
        _write(base, "findings_critique.json", {"annotations": {
            "SCA-1": {"severity_adjusted": "high", "confidence": "confirmed",
                      "include_in_report": True}}})
        _write(base, "sca_findings.json", {"vulnerabilities": [
            {"package": "lodash", "version": "4.17.0", "severity": "high",
             "cve_ids": ["CVE-2020-8203"], "fixed_version": "4.17.20"},
        ]})
        m = extract_run_metrics(str(tmp_path), "sca")
        assert len(m["supply_chain_packages"]) == 1
        assert m["supply_chain_packages"][0]["package"] == "lodash"


class TestParseErrorState:
    async def _run(self, client, session_maker, email="u@example.com", preset="vuln"):
        await _make_user(session_maker, email, PW, "user")
        tok = await _token(client, email, PW)
        h = {"Authorization": f"Bearer {tok}"}
        rid = (await client.post("/repositories", headers=h,
               json={"name": "r", "source_type": "upload", "is_private": True})).json()["id"]
        jid = (await client.post("/jobs", headers=h,
               json={"repository_id": rid, "name": "j", "stage_preset": preset})).json()["id"]
        run_id = (await client.post(f"/jobs/{jid}/run", headers=h)).json()["id"]
        return tok, run_id

    async def test_succeeded_run_with_no_deliverables_records_parse_error(self, client, session_maker):
        _, run_id = await self._run(client, session_maker)
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id))
            run.status = RUN_SUCCEEDED                    # terminal, but data_dir is empty
            await s.commit()
            row = await upsert_run_metrics(s, run)
        assert row is not None
        d = metrics_to_dict(row)
        assert d["parse_error"] is True                   # explicit, not silent zeros
        assert d["total_findings"] == 0

    async def test_running_run_no_deliverables_returns_none_not_sentinel(self, client, session_maker):
        _, run_id = await self._run(client, session_maker)
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id))     # still "running"/"queued"
            row = await upsert_run_metrics(s, run)
        assert row is None                                # don't cache a not-yet-finished run

    async def test_dashboard_excludes_parse_error_from_totals(self, client, session_maker):
        tok, run_id = await self._run(client, session_maker)
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id))
            run.status = RUN_SUCCEEDED
            await s.commit()
            await upsert_run_metrics(s, run)
            from src.webapi.acl import accessible_repo_ids
            from src.webapi.models import User
            user = (await s.scalars(__import__("sqlalchemy").select(User))).first()
            allowed = await accessible_repo_ids(s, user)
            dash = await global_dashboard(s, allowed)
        assert dash["parse_errors"] == 1
        assert dash["repositories_scanned"] == 0          # the only repo failed to parse
        assert dash["total_findings"] == 0

    async def test_supply_chain_scanned_flag_reflects_preset(self, client, session_maker):
        # vuln preset -> SCA not run
        _, run_id = await self._run(client, session_maker, email="v@example.com", preset="vuln")
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id)); run.status = RUN_SUCCEEDED; await s.commit()
            row = await upsert_run_metrics(s, run)
        assert metrics_to_dict(row)["supply_chain_scanned"] is False
        # full preset -> SCA in scope
        _, run_id2 = await self._run(client, session_maker, email="f@example.com", preset="full")
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id2)); run.status = RUN_SUCCEEDED; await s.commit()
            row = await upsert_run_metrics(s, run)
        assert metrics_to_dict(row)["supply_chain_scanned"] is True
