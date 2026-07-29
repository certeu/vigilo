"""Extract dashboard metrics from a run's deliverables.

Primary source is ``deliverables/findings_critique.json`` — the pipeline's single
source of truth (per-finding adjusted severity/confidence, grouped by ``group_id`` to
match the report body). Falls back to ``findings_index.json``, then to a legacy
``report_stats.json`` (older runs / the demo engine). Returns a normalized dict the
dashboard endpoints and RunMetrics rows share.
"""
from __future__ import annotations

import json
import os

from src.webapi.reports import deliverables_dir

SEVERITIES = ("critical", "high", "medium", "low", "informational")


def _read_json(path: str) -> dict | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return None


def _empty() -> dict:
    return {
        "total_findings": 0,
        "severity_counts": {s: 0 for s in SEVERITIES},
        "status_counts": {"exploited": 0, "unconfirmed": 0},
        "category_counts": {},
        "supply_chain": 0,
        "source": None,
    }


def _supply_chain_packages(base: str) -> list[dict]:
    """Top vulnerable dependencies from sca_findings.json (name/version/severity/cve)."""
    sca = _read_json(os.path.join(base, "sca_findings.json"))
    if not sca:
        return []
    out: list[dict] = []
    for v in sca.get("vulnerabilities", []):
        out.append({
            "package": v.get("package", "?"),
            "version": v.get("version", ""),
            "ecosystem": v.get("ecosystem", ""),
            "severity": str(v.get("severity", "")).lower(),
            "cve": (v.get("cve_ids") or [None])[0],
            "fixed_version": v.get("fixed_version"),
        })
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    out.sort(key=lambda p: rank.get(p["severity"], 5))
    return out


def _from_critique(base: str) -> dict | None:
    """Preferred source on current pipelines: findings_critique.json holds per-finding
    adjusted severity/confidence; findings_index.by_type gives categories. Only counts
    findings the critique keeps in the report (include_in_report), matching the report
    body — so the dashboard and the report agree."""
    crit = _read_json(os.path.join(base, "findings_critique.json"))
    if not crit:
        return None
    anns = crit.get("annotations") or {}
    if isinstance(anns, list):
        anns = {a.get("id") or a.get("canonical_id") or i: a for i, a in enumerate(anns)}
    # id -> category from findings_index by_type
    idx = _read_json(os.path.join(base, "findings_index.json")) or {}
    id2cat: dict[str, str] = {}
    for cat, items in (idx.get("by_type") or {}).items():
        for it in items if isinstance(items, list) else []:
            fid = it.get("ID") or it.get("id") or it.get("canonical_id")
            if fid:
                id2cat[fid] = cat
    # Deduplicate by group_id the SAME way the report does: findings sharing a
    # group_id are one "unique finding" (the report groups duplicate observations
    # of the same root issue). Counting raw annotations made the dashboard
    # over-count vs the report (e.g. 7 High annotations -> 5 High unique findings).
    # Each group takes its highest-severity member's severity/category and is
    # "exploited" if ANY member is confirmed.
    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    groups: dict[str, dict] = {}
    for fid, a in anns.items():
        if a.get("include_in_report") is False:
            continue
        sev = str(a.get("severity_adjusted") or a.get("severity_original") or "").lower()
        confirmed = str(a.get("confidence", "")).lower() == "confirmed"
        cat = id2cat.get(fid, "other")
        gid = a.get("group_id") or fid
        g = groups.get(gid)
        if g is None:
            groups[gid] = {"sev": sev, "cat": cat, "confirmed": confirmed}
        else:
            if _RANK.get(sev, -1) > _RANK.get(g["sev"], -1):
                g["sev"], g["cat"] = sev, cat
            g["confirmed"] = g["confirmed"] or confirmed

    m = _empty()
    cats: dict[str, int] = {}
    for g in groups.values():
        if g["sev"] in m["severity_counts"]:
            m["severity_counts"][g["sev"]] += 1
        m["status_counts"]["exploited" if g["confirmed"] else "unconfirmed"] += 1
        cats[g["cat"]] = cats.get(g["cat"], 0) + 1
    m["category_counts"] = cats
    m["total_findings"] = sum(m["severity_counts"].values())
    m["supply_chain"] = cats.get("supply_chain", 0) or cats.get("sca", 0)
    m["source"] = "critique"
    return m


def extract_run_metrics(data_dir: str, session_id: str) -> dict | None:
    """Return normalized metrics for a run, or None if no deliverables exist yet.

    Source priority: findings_critique.json (source of truth) → findings_index.json →
    report_stats.json (legacy / demo)."""
    base = deliverables_dir(data_dir, session_id)
    # findings_critique.json is the pipeline's single source of truth; prefer it.
    # findings_index.json is a fallback; report_stats.json is a legacy deliverable
    # (older runs / the demo engine) kept only for back-compat.
    m = _from_critique(base)
    if m is None:
        index = _read_json(os.path.join(base, "findings_index.json"))
        if index is not None:
            m = _from_findings_index(index)
    if m is None:
        stats = _read_json(os.path.join(base, "report_stats.json"))
        if stats is not None:
            m = _from_report_stats(stats)
    if m is None:
        return None
    m["supply_chain_packages"] = _supply_chain_packages(base)
    return m


def _from_report_stats(stats: dict) -> dict:
    sev = stats.get("severity_counts", {}) or {}
    status = stats.get("status_counts", {}) or {}
    cats = stats.get("category_counts", {}) or {}
    totals = stats.get("totals", {}) or {}
    m = _empty()
    m["severity_counts"] = {s: int(sev.get(s, 0)) for s in SEVERITIES}
    m["status_counts"] = {
        "exploited": int(status.get("exploited", 0)),
        "unconfirmed": int(status.get("unconfirmed", 0)),
    }
    # category_counts values may be dicts (per-severity + total) or ints.
    cat_out: dict[str, int] = {}
    for name, val in cats.items():
        cat_out[name] = int(val.get("total", 0)) if isinstance(val, dict) else int(val)
    m["category_counts"] = cat_out
    m["supply_chain"] = cat_out.get("supply_chain", 0)
    m["total_findings"] = int(
        totals.get("unique_findings")
        or totals.get("consolidated_count")
        or sum(m["severity_counts"].values())
    )
    m["display_names"] = stats.get("category_display_names", {})
    m["source"] = "report_stats"
    return m


def _from_findings_index(index: dict) -> dict:
    findings = index.get("findings") or index.get("vulnerabilities") or []
    m = _empty()
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in m["severity_counts"]:
            m["severity_counts"][sev] += 1
        cat = f.get("vuln_type") or f.get("category") or "other"
        m["category_counts"][cat] = m["category_counts"].get(cat, 0) + 1
        if str(f.get("status", "")).lower() == "exploited":
            m["status_counts"]["exploited"] += 1
    m["total_findings"] = int(index.get("total_vulnerabilities") or len(findings))
    m["supply_chain"] = m["category_counts"].get("supply_chain", 0)
    m["source"] = "findings_index"
    return m
