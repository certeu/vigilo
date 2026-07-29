"""Mock execution engine — simulates a scan without Claude/Temporal/Docker.

On start it writes a realistic deliverables set (report_stats.json derived from the
bundled sample, a short report, and a workflow.log) into the run's data dir and marks
the run succeeded. This lets the platform + dashboards be exercised end-to-end. Counts
are scaled by a per-run factor so repeated runs vary (useful for the timeline demo).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from src.webapi.models import RUN_SUCCEEDED, Job, Repository, Run

_SAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "samples", "sample_deliverables",
)


def _scaled_stats(scale: float) -> dict:
    with open(os.path.join(_SAMPLE, "report_stats.json"), encoding="utf-8") as fh:
        stats = json.load(fh)

    def scale_map(m: dict) -> dict:
        return {k: (round(v * scale) if isinstance(v, (int, float)) else v)
                for k, v in m.items()}

    stats["severity_counts"] = scale_map(stats.get("severity_counts", {}))
    stats["status_counts"] = scale_map(stats.get("status_counts", {}))
    for cat, val in list(stats.get("category_counts", {}).items()):
        if isinstance(val, dict):
            stats["category_counts"][cat] = scale_map(val)
    totals = stats.get("totals", {})
    for k in ("raw_findings", "unique_findings", "consolidated_count"):
        if k in totals:
            totals[k] = round(totals[k] * scale)
    return stats


class MockEngine:
    durable = False  # synchronous simulation; nothing to resume across a restart

    def __init__(self) -> None:
        self.started: list[str] = []

    async def start(self, run: Run, job: Job, repo: Repository) -> None:
        self.started.append(str(run.id))
        deliverables = os.path.join(
            run.data_dir, "repo", ".vigilo", run.session_id, "deliverables"
        )
        os.makedirs(deliverables, exist_ok=True)

        # Per-run scale in [0.2, 1.0] derived deterministically from the run id.
        scale = 0.2 + (int(run.id.hex[:4], 16) % 800) / 1000.0
        stats = _scaled_stats(scale)
        with open(os.path.join(deliverables, "report_stats.json"), "w", encoding="utf-8") as fh:
            json.dump(stats, fh)

        sca_src = os.path.join(_SAMPLE, "sca_findings.json")
        if os.path.isfile(sca_src):
            with open(sca_src, encoding="utf-8") as s:
                sca_body = s.read()
            with open(os.path.join(deliverables, "sca_findings.json"), "w", encoding="utf-8") as d:
                d.write(sca_body)

        report_src = os.path.join(_SAMPLE, "comprehensive_security_assessment_report.md")
        if os.path.isfile(report_src):
            with open(report_src, encoding="utf-8") as s:
                body = s.read()
            with open(
                os.path.join(deliverables, "comprehensive_security_assessment_report.md"),
                "w", encoding="utf-8",
            ) as d:
                d.write(body)

        # Emit the SAME human-readable phase/agent markers the real WorkflowLogger
        # writes (src/audit/workflow_logger.py), so mock runs render correctly in the
        # trace rail / log filter. (Previously wrote JSON-lines, which the text-based
        # UI + engine refresh couldn't parse.)
        log_dir = os.path.join(run.data_dir, "repo", ".vigilo", run.session_id)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        markers = [
            "[PHASE] Starting: preflight",
            "[PHASE] Starting: pre-recon",
            "[AGENT] pre-recon: Completed",
            "[PHASE] Starting: recon",
            "[AGENT] recon: Completed",
            "[PHASE] Starting: vulnerability-exploitation",
            "[AGENT] injection-vuln: Completed",
            "[PHASE] Starting: critique",
            "[AGENT] report-critic: Completed",
            "[PHASE] Starting: reporting",
            "[AGENT] report: Completed",
        ]
        with open(os.path.join(log_dir, "workflow.log"), "w", encoding="utf-8") as fh:
            for mk in markers:
                fh.write(f"[{ts}] {mk}\n")

        run.workflow_id = f"mock-wf-{run.id.hex[:8]}"
        run.current_phase = "report"
        run.total_cost_usd = round(2 + scale * 6, 2)
        run.status = RUN_SUCCEEDED

    async def cancel(self, run: Run) -> None:
        from src.webapi.models import RUN_CANCELLED, RUN_TERMINAL
        if run.status not in RUN_TERMINAL:
            run.status = RUN_CANCELLED

    async def refresh(self, run: Run) -> None:
        return None
