"""Findings guard — deterministic recall backstop over the critique.

The critic's `findings_critique.json` is the single source of truth for the
report, so a finding that is present in `findings_index.json` but missing an
annotation, or a serious+reachable finding the critic marked
`include_in_report=false`, would silently leave the client-facing report. This
guard makes both cases **traceable and loud** instead of silent:

- Reconciliation: every finding ID in the index must have an annotation. Missing
  IDs are reported (a potential silently-dropped true positive).
- Recall floor: no annotation may set `include_in_report=false` while
  `severity_adjusted` is critical/high AND `reachability` is external/authenticated.

It writes `deliverables/findings_critique_audit.json` and logs a WARNING per
issue. It does NOT mutate the critique or drop anything — it surfaces problems so
the report step (and a human) can see them. This is the enforcement half of the
prompt-level rules in critic.txt.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)

_SERIOUS = {"critical", "high"}
_REACHABLE = {"external", "authenticated"}


async def _load(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        async with aiofiles.open(path, mode="r", encoding="utf-8") as f:
            return json.loads(await f.read())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("findings_guard: failed to read %s: %s", path, exc)
        return None


def _index_ids(index: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for vulns in (index.get("by_type") or {}).values():
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if isinstance(v, dict):
                vid = str(v.get("ID") or v.get("id") or "").strip()
                if vid:
                    ids.append(vid)
    return ids


def audit(index: dict[str, Any], critique: dict[str, Any]) -> dict[str, Any]:
    """Pure audit: returns {ok, missing_annotations, floor_violations, counts}."""
    annotations = critique.get("annotations") or {}
    index_ids = _index_ids(index)

    missing = sorted({vid for vid in index_ids if vid not in annotations})

    floor_violations: list[dict[str, Any]] = []
    for vid, ann in annotations.items():
        if not isinstance(ann, dict):
            continue
        sev = str(ann.get("severity_adjusted", "")).lower()
        reach = str(ann.get("reachability", "")).lower()
        include = ann.get("include_in_report", True)
        if include is False and sev in _SERIOUS and reach in _REACHABLE:
            floor_violations.append({
                "id": vid,
                "severity_adjusted": sev,
                "reachability": reach,
            })

    return {
        "ok": not missing and not floor_violations,
        "missing_annotations": missing,
        "floor_violations": floor_violations,
        "counts": {
            "index_findings": len(index_ids),
            "annotations": len(annotations),
            "missing": len(missing),
            "floor_violations": len(floor_violations),
        },
    }


async def audit_critique(repo_path: str) -> dict[str, Any]:
    """Load the index + critique, audit them, write the audit sidecar, log loudly."""
    deliverables = Path(repo_path) / "deliverables"
    index = await _load(deliverables / "findings_index.json")
    critique = await _load(deliverables / "findings_critique.json")

    if not isinstance(index, dict):
        logger.warning("findings_guard: no findings_index.json — nothing to audit")
        index = {"by_type": {}}
    if not isinstance(critique, dict):
        # No critique at all is itself a loud problem: the report has no source of truth.
        logger.error("findings_guard: findings_critique.json missing — the report will "
                     "have no adjudicated inventory")
        critique = {"annotations": {}}

    result = audit(index, critique)

    for vid in result["missing_annotations"]:
        logger.warning(
            "findings_guard: finding %s is in the index but has NO critique annotation — "
            "it would be dropped from the report. Critic must annotate every finding.", vid,
        )
    for v in result["floor_violations"]:
        logger.warning(
            "findings_guard: RECALL FLOOR VIOLATION — %s is %s/%s but include_in_report=false. "
            "A serious, reachable finding must reach the report body.",
            v["id"], v["severity_adjusted"], v["reachability"],
        )
    if result["ok"]:
        logger.info("findings_guard: critique audit clean (%d findings, all annotated, no floor violations)",
                    result["counts"]["index_findings"])

    deliverables.mkdir(parents=True, exist_ok=True)
    target = deliverables / "findings_critique_audit.json"
    tmp = deliverables / f"findings_critique_audit.{os.getpid()}.tmp"
    async with aiofiles.open(tmp, mode="w", encoding="utf-8") as f:
        await f.write(json.dumps(result, indent=2, ensure_ascii=False))
    tmp.replace(target)
    return result
