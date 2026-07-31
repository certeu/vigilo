"""Persistent, browse-only repository file tree.

Captured at ingest — for GitLab repos that's the ONLY time the checkout exists
(gitlab checkouts are deleted after a run, see cleanup.cleanup_run_source); for
uploads it's captured at upload-validation time. Stored as a flat, sorted list of
repo-relative FILE paths — names only, NEVER file contents — under
``{uploads_dir}/{repo_id}.tree.json`` so the repo detail page can render a
directory tree without a live checkout and without any content-fetch endpoint.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile

from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)

_MAX_ENTRIES = 20000
# __MACOSX is Finder's resource-fork sidecar; drop it like other internal plumbing.
_SKIP_DIRS = {".git", ".vigilo", "__MACOSX"}
_SKIP_FILES = {".vigilo-remote-url"}  # marker written by prepare_repo, not source


def tree_cache_path(repo_id: str) -> str:
    return os.path.join(get_settings().uploads_dir, f"{repo_id}.tree.json")


def _skip(path: str) -> bool:
    segs = path.split("/")
    return any(s in _SKIP_DIRS for s in segs) or segs[-1] in _SKIP_FILES


def _lone_root_prefix(names: list[str]) -> str:
    """Return the single top-level wrapper dir shared by every member (e.g. Finder's
    ``project/`` wrapper), as a ``"prefix/"`` string to strip — or ``""`` if members
    live at more than one top level. Mirrors ingestion._flatten_extracted so the browse
    tree matches the extracted repo root."""
    tops = set()
    kept = 0
    for n in names:
        n = n.replace("\\", "/")
        if not n or _skip(n):
            continue
        kept += 1
        head, sep, _rest = n.partition("/")
        if not sep:  # a file at the archive root -> no lone wrapper dir
            return ""
        tops.add(head)
        if len(tops) > 1:
            return ""
    return next(iter(tops)) + "/" if kept and len(tops) == 1 else ""


def capture_repo_tree(repo_id: str, source_path: str) -> int:
    """Persist the file listing of ``source_path`` (a directory OR a .zip archive).

    Names only — the contents are never read. Returns the number of files captured.
    Best-effort caller: exceptions propagate so the caller can log + continue."""
    paths: list[str] = []
    truncated = False
    if os.path.isfile(source_path) and source_path.endswith(".zip"):
        with zipfile.ZipFile(source_path) as zf:
            names = zf.namelist()
            prefix = _lone_root_prefix(names)  # strip a Finder/tarball wrapper dir
            for n in names:
                if n.endswith("/") or _skip(n):
                    continue
                n = n.replace("\\", "/")
                if prefix and n.startswith(prefix):
                    n = n[len(prefix):]
                paths.append(n)
                if len(paths) >= _MAX_ENTRIES:
                    truncated = True
                    break
    elif os.path.isdir(source_path):
        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            rel_root = os.path.relpath(root, source_path)
            for f in files:
                if f in _SKIP_FILES:
                    continue
                rel = f if rel_root == "." else os.path.join(rel_root, f)
                paths.append(rel.replace("\\", "/"))
            if len(paths) >= _MAX_ENTRIES:
                paths = paths[:_MAX_ENTRIES]
                truncated = True
                break
    else:
        return 0
    paths.sort()
    uploads = get_settings().uploads_dir
    os.makedirs(uploads, exist_ok=True)
    tmp = tree_cache_path(repo_id) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"paths": paths, "truncated": truncated, "count": len(paths)}, fh)
    os.replace(tmp, tree_cache_path(repo_id))  # atomic
    return len(paths)


def _write_cache(repo_id: str, paths: list[str], truncated: bool) -> int:
    paths = sorted(set(paths))
    uploads = get_settings().uploads_dir
    os.makedirs(uploads, exist_ok=True)
    tmp = tree_cache_path(repo_id) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"paths": paths, "truncated": truncated, "count": len(paths)}, fh)
    os.replace(tmp, tree_cache_path(repo_id))
    return len(paths)


def capture_gitlab_tree(repo_id: str, gitlab_url: str, token: str | None) -> int:
    """Capture a GitLab repo's file tree WITHOUT a full checkout — a blobless, no-checkout
    shallow clone (fetches tree objects only, not file contents) + ``git ls-tree``. This
    lets the file browser work before the first scan and after scan checkouts are cleaned,
    independent of the ephemeral scan workspace. Best-effort; raises on failure."""
    from src.webapi.ingestion import GIT_PROTOCOL_ENV, build_clone_url

    clone_url = build_clone_url(gitlab_url, token or "")
    tmp = tempfile.mkdtemp(prefix="vigilo-tree-")
    env = {**os.environ, **GIT_PROTOCOL_ENV}
    try:
        clone = subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", "--depth", "1",
             clone_url, tmp],
            capture_output=True, text=True, timeout=90, env=env,
        )
        if clone.returncode != 0:
            detail = (clone.stderr or "").replace(clone_url, "<clone-url>")
            if token:
                detail = detail.replace(token, "<token>")
            raise RuntimeError(f"tree clone failed: {detail.strip()[:200]}")
        ls = subprocess.run(
            ["git", "-C", tmp, "ls-tree", "-r", "--name-only", "HEAD"],
            capture_output=True, text=True, timeout=60, env=env,
        )
        if ls.returncode != 0:
            raise RuntimeError(f"ls-tree failed: {(ls.stderr or '').strip()[:200]}")
        names = [ln for ln in ls.stdout.splitlines() if ln.strip() and not _skip(ln)]
        truncated = len(names) > _MAX_ENTRIES
        return _write_cache(repo_id, names[:_MAX_ENTRIES], truncated)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def read_repo_tree(repo_id: str) -> dict | None:
    """Return the cached tree ({paths, truncated, count}) or None if not captured yet."""
    p = tree_cache_path(repo_id)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("paths"), list):
            return data
    except (ValueError, OSError):
        pass
    return None
