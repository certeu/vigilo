"""Repository ingestion: materialize a run's source into ``{data_dir}/repo``.

Two sources:
- **upload** — extract a user-provided archive (zip / tar.gz), with path-traversal
  guards (uploads are semi-trusted but we never trust archive member names).
- **gitlab** — shallow ``git clone`` over HTTPS with the owner's token injected into
  the URL. The token is NEVER written to disk or logs: the ``.vigilo-remote-url``
  marker records the CLEAN url (no credentials), and clone errors are scrubbed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import zipfile
from urllib.parse import urlparse, urlunparse

REMOTE_MARKER = ".vigilo-remote-url"
_ARCHIVE_EXTS = (".zip", ".tar.gz", ".tgz", ".tar")


def upload_archive_path(uploads_dir: str, repo_id: str) -> str:
    return os.path.join(uploads_dir, f"{repo_id}.zip")


def upload_tree_dir(uploads_dir: str, repo_id: str) -> str:
    return os.path.join(uploads_dir, repo_id)


def is_archive_name(name: str) -> bool:
    return name.lower().endswith(_ARCHIVE_EXTS)


def copy_tree(src_dir: str, dest_dir: str) -> str:
    """Copy an uncompressed uploaded source tree into the run's repo dir."""
    os.makedirs(dest_dir, exist_ok=True)
    for root, _dirs, files in os.walk(src_dir):
        rel = os.path.relpath(root, src_dir)
        target_root = dest_dir if rel == "." else os.path.join(dest_dir, rel)
        os.makedirs(target_root, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(root, f), os.path.join(target_root, f))
    return dest_dir


def _is_safe_member(name: str) -> bool:
    """Reject absolute paths and parent-directory traversal in archive members."""
    if name.startswith("/") or name.startswith("\\"):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


def extract_archive(archive_path: str, dest_dir: str) -> str:
    """Extract a .zip or .tar(.gz) archive into ``dest_dir`` (created if needed)."""
    os.makedirs(dest_dir, exist_ok=True)
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.namelist():
                if not _is_safe_member(member):
                    raise ValueError(f"unsafe archive member: {member!r}")
            zf.extractall(dest_dir)
    elif archive_path.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path) as tf:
            # filter='data' (py3.12+) strips absolute paths / traversal / special files.
            tf.extractall(dest_dir, filter="data")
    else:
        raise ValueError(f"unsupported archive type: {archive_path!r}")
    return dest_dir


def validate_upload(upload_path: str) -> int:
    """Validate an uploaded source (archive file or uncompressed dir) WITHOUT doing a
    full run checkout. Returns the number of files found. Raises ValueError on an
    unreadable/empty/unsafe archive so the repo can be marked ``failed`` at upload
    time (early feedback) instead of only when a scan is started.

    Reads archive metadata (central directory / member list), not full contents, so
    it stays cheap even for large archives.
    """
    if os.path.isdir(upload_path):
        count = sum(len(files) for _root, _dirs, files in os.walk(upload_path))
        if count == 0:
            raise ValueError("uploaded folder contains no files")
        return count
    if upload_path.endswith(".zip"):
        if not zipfile.is_zipfile(upload_path):
            raise ValueError("not a valid .zip archive")
        with zipfile.ZipFile(upload_path) as zf:
            names = zf.namelist()
            for m in names:
                if not _is_safe_member(m):
                    raise ValueError(f"unsafe archive member: {m!r}")
            files = [n for n in names if not n.endswith("/")]
            if not files:
                raise ValueError("archive contains no files")
            return len(files)
    if upload_path.endswith((".tar.gz", ".tgz", ".tar")):
        try:
            with tarfile.open(upload_path) as tf:
                members = [m for m in tf.getmembers() if m.isfile()]
        except tarfile.TarError as exc:
            raise ValueError(f"not a valid tar archive: {exc}") from exc
        if not members:
            raise ValueError("archive contains no files")
        return len(members)
    raise ValueError(f"unsupported archive type: {os.path.basename(upload_path)!r}")


# Only real network git transports are allowed — never file://, ext::, ssh://, etc.
# Without this an authenticated user could set gitlab_url to file:///... (clone a
# local repo and exfiltrate it via the report/tree) or http://<internal-host> (SSRF).
_ALLOWED_GIT_SCHEMES = ("https", "http")
# git-level transport allowlist enforced on every git subprocess (defense-in-depth,
# incl. any sub-fetches like submodules). Blocks the dangerous transports — ext::
# (remote-helper command execution), ssh, git — while still permitting file (local
# clones in tests/dev); user-supplied file:// URLs are already rejected upstream by
# the scheme allowlist + the RepositoryCreate validator.
GIT_PROTOCOL_ENV = {"GIT_ALLOW_PROTOCOL": "file:http:https", "GIT_TERMINAL_PROMPT": "0"}


def _require_web_scheme(gitlab_url: str) -> str:
    scheme = (urlparse(gitlab_url).scheme or "https").lower()
    if scheme not in _ALLOWED_GIT_SCHEMES:
        raise ValueError(f"unsupported git URL scheme {scheme!r}; only https/http allowed")
    return scheme


def build_clone_url(gitlab_url: str, token: str) -> str:
    """Return an HTTP(S) clone URL with the token injected as oauth2 basic auth.
    Rejects non-web schemes (file://, ext::, ssh://, …)."""
    scheme = _require_web_scheme(gitlab_url)
    p = urlparse(gitlab_url)
    host = p.hostname or ""
    netloc = f"oauth2:{token}@{host}"
    if p.port:
        netloc += f":{p.port}"
    return urlunparse((scheme, netloc, p.path, "", "", ""))


def validate_gitlab_access(gitlab_url: str, token: str | None, runner=subprocess.run) -> int:
    """Verify a GitLab repo is reachable + the token grants access, WITHOUT a full
    clone, via ``git ls-remote``. Returns the number of refs. Raises RuntimeError on
    failure (token scrubbed from the message)."""
    clone_url = build_clone_url(gitlab_url, token or "")
    result = runner(
        ["git", "ls-remote", "--heads", clone_url],
        capture_output=True, text=True, timeout=45,
        env={**os.environ, **GIT_PROTOCOL_ENV},
    )
    if result.returncode != 0:
        detail = (result.stderr or "").replace(clone_url, "<clone-url>")
        if token:
            detail = detail.replace(token, "<token>")
        raise RuntimeError(f"git ls-remote failed: {detail.strip()[:300]}")
    return len([ln for ln in (result.stdout or "").splitlines() if ln.strip()])


def clone_repo(clone_url: str, dest_dir: str, depth: int = 1, runner=subprocess.run) -> str:
    """Shallow-clone ``clone_url`` into ``dest_dir``. Never echoes the URL (may
    contain a token) on failure."""
    result = runner(
        ["git", "clone", "--depth", str(depth), clone_url, dest_dir],
        capture_output=True, text=True,
        env={**os.environ, **GIT_PROTOCOL_ENV},
    )
    if result.returncode != 0:
        # Scrub: report stderr but not the token-bearing URL/command.
        detail = (result.stderr or "").replace(clone_url, "<clone-url>")
        raise RuntimeError(f"git clone failed: {detail.strip()[:400]}")
    return dest_dir


def write_remote_marker(repo_dir: str, remote_url: str) -> str:
    """Write ``.vigilo-remote-url`` (clean URL, no credentials) for rebuild_git."""
    path = os.path.join(repo_dir, REMOTE_MARKER)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(remote_url.strip() + "\n")
    return path


def prepare_repo(
    *,
    source_type: str,
    repo_dir: str,
    upload_path: str | None = None,
    gitlab_url: str | None = None,
    token: str | None = None,
) -> str:
    """Populate ``repo_dir`` from the given source. Returns the repo dir."""
    os.makedirs(repo_dir, exist_ok=True)
    if source_type == "upload":
        # upload_path may be an archive file OR a directory (uncompressed upload).
        if not upload_path:
            raise ValueError("upload source requires upload_path")
        if os.path.isdir(upload_path):
            copy_tree(upload_path, repo_dir)
        else:
            extract_archive(upload_path, repo_dir)
    elif source_type == "gitlab":
        if not gitlab_url:
            raise ValueError("gitlab source requires gitlab_url")
        clone_url = build_clone_url(gitlab_url, token or "")
        clone_repo(clone_url, repo_dir)
        write_remote_marker(repo_dir, gitlab_url)  # clean url, never the token
    else:
        raise ValueError(f"unknown source_type: {source_type!r}")
    return repo_dir
