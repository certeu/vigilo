"""Resolve report + artifact paths for a run.

The pipeline writes deliverables under
``{data_dir}/repo/.vigilo/{session_id}/deliverables/``. These helpers locate the
final report and the downloadable artifacts without the API needing to know the
full pipeline internals.
"""
from __future__ import annotations

import os

REPORT_FILENAME = "comprehensive_security_assessment_report.md"

# artifact kind -> relative path under deliverables/
ARTIFACT_PATHS: dict[str, str] = {
    "report_md": REPORT_FILENAME,
    "findings_index": "findings_index.json",
    "findings_critique": "findings_critique.json",
    "report_stats": "report_stats.json",
    "remediation_report": "remediation_report.md",
}


def deliverables_dir(data_dir: str, session_id: str) -> str:
    return os.path.join(data_dir, "repo", ".vigilo", session_id, "deliverables")


def report_path(data_dir: str, session_id: str) -> str:
    return os.path.join(deliverables_dir(data_dir, session_id), REPORT_FILENAME)


def artifact_path(data_dir: str, session_id: str, kind: str) -> str | None:
    rel = ARTIFACT_PATHS.get(kind)
    if rel is None:
        return None
    return os.path.join(deliverables_dir(data_dir, session_id), rel)


def available_artifacts(data_dir: str, session_id: str) -> list[str]:
    """Return the kinds whose files currently exist for this run."""
    base = deliverables_dir(data_dir, session_id)
    found: list[str] = []
    for kind, rel in ARTIFACT_PATHS.items():
        if os.path.isfile(os.path.join(base, rel)):
            found.append(kind)
    # Any exported patch files?
    if os.path.isdir(os.path.join(base, "patches")):
        if any(f.endswith(".patch") for f in os.listdir(os.path.join(base, "patches"))):
            found.append("patches")
    return found


def read_report(data_dir: str, session_id: str) -> str | None:
    path = report_path(data_dir, session_id)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()
