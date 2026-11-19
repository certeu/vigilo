"""Resolve report + artifact paths for a run.

The pipeline writes deliverables under
``{data_dir}/repo/.vigilo/{session_id}/deliverables/``. These helpers locate the
final report and the downloadable artifacts without the API needing to know the
full pipeline internals.
"""
from __future__ import annotations

import logging
import mimetypes
import os
import tempfile
import zipfile
from typing import BinaryIO

from src.webapi import safefs

REPORT_FILENAME = "comprehensive_security_assessment_report.md"

# artifact kind -> relative path under deliverables/
ARTIFACT_PATHS: dict[str, str] = {
    "report_md": REPORT_FILENAME,
    "findings_index": "findings_index.json",
    "findings_critique": "findings_critique.json",
    "report_stats": "report_stats.json",
    "remediation_report": "remediation_report.md",
    "remediation_manifest": "remediation_manifest.json",
}

# Virtual artifact kinds (built on demand, not a single file on disk).
PATCHES_KIND = "patches"
PATCHES_ZIP_NAME = "patches.zip"
BUNDLE_KIND = "bundle"
BUNDLE_MAX_BYTES = 200 * 1024 * 1024

log = logging.getLogger(__name__)


def deliverables_dir(data_dir: str, session_id: str) -> str:
    return os.path.join(data_dir, "repo", ".vigilo", session_id, "deliverables")


def report_path(data_dir: str, session_id: str) -> str:
    return os.path.join(deliverables_dir(data_dir, session_id), REPORT_FILENAME)


def artifact_path(data_dir: str, session_id: str, kind: str) -> str | None:
    rel = ARTIFACT_PATHS.get(kind)  # "patches" is virtual: see build_patches_zip
    if rel is None:
        return None
    return os.path.join(deliverables_dir(data_dir, session_id), rel)


def _deliverable_parts(session_id: str, *rel: str) -> tuple[str, ...]:
    return ("repo", ".vigilo", session_id, "deliverables", *rel)


def open_deliverable(data_dir: str, session_id: str, *rel: str) -> BinaryIO | None:
    """Open a regular file under the run's deliverables/, refusing symlinks anywhere
    below ``data_dir`` (agents control the workspace)."""
    return safefs.open_file(data_dir, *_deliverable_parts(session_id, *rel))


def read_deliverable(data_dir: str, session_id: str, rel: str, max_bytes: int | None = None) -> bytes | None:
    return safefs.read_bytes(data_dir, *_deliverable_parts(session_id, rel), max_bytes=max_bytes)


def open_artifact(data_dir: str, session_id: str, kind: str) -> tuple[BinaryIO, str, str] | None:
    """(file object, download name, media type) for an artifact kind, or None."""
    rel = ARTIFACT_PATHS.get(kind)
    if rel is None:
        return None
    fh = open_deliverable(data_dir, session_id, rel)
    if fh is None:
        return None
    return fh, rel, mimetypes.guess_type(rel)[0] or "application/octet-stream"


def resolve_deliverable_file(data_dir: str, session_id: str, rel: str) -> str | None:
    """Resolve a deliverable-relative path (e.g. ``screenshots/x.png``) safely.

    Returns the absolute path if it exists and stays inside deliverables/, else None.
    Used to serve report images (screenshots) that the report references relatively.
    """
    base = os.path.realpath(deliverables_dir(data_dir, session_id))
    candidate = os.path.realpath(os.path.join(base, rel))
    if candidate != base and not candidate.startswith(base + os.sep):
        return None  # path traversal attempt
    if not os.path.isfile(candidate):
        return None
    return candidate


def available_artifacts(data_dir: str, session_id: str) -> list[str]:
    """Return the kinds whose files currently exist for this run."""
    found: list[str] = []
    for kind, rel in ARTIFACT_PATHS.items():
        if safefs.is_safe_file(data_dir, *_deliverable_parts(session_id, rel)):
            found.append(kind)
    if patch_names(data_dir, session_id):
        found.append(PATCHES_KIND)
    if bundle_entries(data_dir, session_id):
        found.append(BUNDLE_KIND)
    return found


def bundle_entries(data_dir: str, session_id: str) -> list[tuple[str, ...]]:
    """Regular files under ``deliverables/`` (recursive) that go into the bundle.
    Symlinks, ``*.lock`` files and dotfiles are excluded."""
    return [
        p for p in safefs.walk_regular(data_dir, *_deliverable_parts(session_id))
        if not any(c.startswith(".") for c in p) and not p[-1].endswith(".lock")
    ]


def build_bundle_zip(data_dir: str, session_id: str) -> BinaryIO | None:
    """Zip of the whole deliverables/ tree (under a top ``deliverables/`` folder) in a
    spooled temp file positioned at 0, or None when there is nothing to bundle."""
    entries = bundle_entries(data_dir, session_id)
    if not entries:
        return None
    tmp = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    total = 0
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in entries:
            fh = open_deliverable(data_dir, session_id, *rel)
            if fh is None:
                continue
            with fh:
                remaining = BUNDLE_MAX_BYTES - total
                data = fh.read(remaining + 1)
            if len(data) > remaining:
                log.warning("deliverables bundle for %s truncated at %d bytes; skipping %s and the rest",
                            session_id, BUNDLE_MAX_BYTES, "/".join(rel))
                break
            total += len(data)
            zf.writestr("deliverables/" + "/".join(rel), data)
    tmp.seek(0)
    return tmp


def patch_names(data_dir: str, session_id: str) -> list[str]:
    """Names of the run's regular ``*.patch`` files directly under ``deliverables/patches/``
    (symlinks and non-regular files are skipped)."""
    return [
        n for n in safefs.list_regular(data_dir, *_deliverable_parts(session_id, "patches"))
        if n.endswith(".patch")
    ]


def build_patches_zip(data_dir: str, session_id: str) -> BinaryIO | None:
    """Zip of ``patches/*.patch`` (+ ``remediation_manifest.json`` when present) in a
    spooled temp file positioned at 0, or None when there are no patches."""
    names = patch_names(data_dir, session_id)
    if not names:
        return None
    tmp = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in names:
            fh = open_deliverable(data_dir, session_id, "patches", name)
            if fh is None:
                continue
            with fh:
                zf.writestr(f"patches/{name}", fh.read())
        manifest = read_deliverable(data_dir, session_id, ARTIFACT_PATHS["remediation_manifest"])
        if manifest is not None:
            zf.writestr("remediation_manifest.json", manifest)
    tmp.seek(0)
    return tmp


def read_report(data_dir: str, session_id: str) -> str | None:
    raw = read_deliverable(data_dir, session_id, REPORT_FILENAME)
    return None if raw is None else raw.decode("utf-8", errors="replace")
