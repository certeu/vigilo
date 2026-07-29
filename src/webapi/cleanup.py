"""Post-run disk cleanup.

A run's workspace is ``{data_dir}/repo`` with pipeline outputs under
``{data_dir}/repo/.vigilo/{session}/``. After a run finishes we reclaim the space
taken by the cloned/uploaded SOURCE while preserving the ``.vigilo`` tree (report,
findings, logs) that the UI/API still serve. Idempotent and defensive: it refuses to
operate outside the configured jobs data dir.
"""
from __future__ import annotations

import logging
import os
import shutil

from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)

_KEEP = ".vigilo"


def cleanup_run_source(data_dir: str) -> bool:
    """Remove the source checkout under ``{data_dir}/repo`` except ``.vigilo``.
    Returns True if anything was cleaned. Safe/idempotent."""
    jobs_root = os.path.abspath(get_settings().jobs_data_dir)
    data_dir = os.path.abspath(data_dir)
    # Defensive: only ever touch paths inside the configured jobs data dir.
    if not data_dir.startswith(jobs_root + os.sep) and data_dir != jobs_root:
        logger.warning("cleanup refused: %s outside %s", data_dir, jobs_root)
        return False
    repo_dir = os.path.join(data_dir, "repo")
    if not os.path.isdir(repo_dir):
        return False
    cleaned = False
    for entry in os.listdir(repo_dir):
        if entry == _KEEP:
            continue
        path = os.path.join(repo_dir, entry)
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            cleaned = True
        except OSError as exc:  # pragma: no cover - best-effort
            logger.warning("cleanup failed for %s: %s", path, exc)
    return cleaned
