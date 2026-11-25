"""Repository ingestion: materialize a run's source into ``{data_dir}/repo``.

Two sources:
- **upload** — extract a user-provided archive (zip / tar.gz), with path-traversal
  guards (uploads are semi-trusted but we never trust archive member names).
- **gitlab** — shallow ``git clone`` over HTTPS with the owner's token injected into
  the URL. The token is NEVER left on disk or in logs (``origin`` is reset to the clean URL): the ``.vigilo-remote-url``
  marker records the CLEAN url (no credentials), and clone errors are scrubbed.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import zipfile
from urllib.parse import urlparse, urlunparse

REMOTE_MARKER = ".vigilo-remote-url"
_ARCHIVE_EXTS = (".zip", ".tar.gz", ".tgz", ".tar")


def upload_archive_path(uploads_dir: str, repo_id: str) -> str:
    return os.path.join(uploads_dir, f"{repo_id}.zip")


def upload_tree_dir(uploads_dir: str, repo_id: str) -> str:
    return os.path.join(uploads_dir, repo_id)


def _is_appledouble(name: str) -> bool:
    """macOS AppleDouble sidecar (``._file``), added by a Mac's tar next to every file."""
    return name.rstrip("/").rsplit("/", 1)[-1].startswith("._")


def archive_kind(path: str) -> str | None:
    """``"zip"`` or ``"tar"`` (plain, gzip, bzip2 or xz) from the file's CONTENT, not
    its name: uploads are stored as ``<repo id>.zip`` whatever their format (see
    :func:`upload_archive_path`), so the extension cannot be trusted."""
    if zipfile.is_zipfile(path):
        return "zip"
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except (OSError, tarfile.TarError):
        pass
    return None


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


# Sidecar directory macOS Finder's "Compress" adds alongside the real content;
# it holds resource-fork metadata, never source, so it is dropped on extraction.
_MACOSX_DIR = "__MACOSX"


def _flatten_extracted(staging_dir: str, dest_dir: str) -> None:
    """Move extracted content from ``staging_dir`` into ``dest_dir``, dropping the
    macOS ``__MACOSX`` sidecar and descending a single top-level wrapper directory.

    Finder's "Compress" (and many ``git archive`` / GitHub tarballs) nest all files
    under one wrapper dir, so a bare extract leaves the real source one level too
    deep and the scanner sees an empty root. When the only meaningful entry is a
    lone directory, its contents become the repo root instead."""
    entries = [e for e in os.listdir(staging_dir) if e != _MACOSX_DIR]
    root = staging_dir
    if len(entries) == 1 and os.path.isdir(os.path.join(staging_dir, entries[0])):
        root = os.path.join(staging_dir, entries[0])
    os.makedirs(dest_dir, exist_ok=True)
    for entry in os.listdir(root):
        if root is staging_dir and entry == _MACOSX_DIR:
            continue
        shutil.move(os.path.join(root, entry), os.path.join(dest_dir, entry))


def extract_archive(archive_path: str, dest_dir: str) -> str:
    """Extract a .zip or .tar(.gz) archive into ``dest_dir`` (created if needed).

    Extraction goes to a staging dir first, then :func:`_flatten_extracted` moves the
    real content into ``dest_dir`` — dropping ``__MACOSX`` and descending a single
    wrapper directory so Finder/tarball archives land at the repo root."""
    os.makedirs(dest_dir, exist_ok=True)
    # Stage on the same filesystem as dest_dir so the flatten step is a rename, not a copy.
    staging_dir = tempfile.mkdtemp(prefix=".extract-", dir=dest_dir)
    try:
        kind = archive_kind(archive_path)
        if kind == "zip":
            with zipfile.ZipFile(archive_path) as zf:
                for member in zf.namelist():
                    if not _is_safe_member(member):
                        raise ValueError(f"unsafe archive member: {member!r}")
                zf.extractall(staging_dir, members=[
                    m for m in zf.namelist() if not _is_appledouble(m)])
        elif kind == "tar":
            with tarfile.open(archive_path) as tf:
                # filter='data' (py3.12+) strips absolute paths / traversal / special files.
                tf.extractall(staging_dir, filter="data", members=[
                    m for m in tf.getmembers() if not _is_appledouble(m.name)])
        else:
            raise ValueError("not a .zip or .tar(.gz) archive: "
                             f"{os.path.basename(archive_path)!r}")
        _flatten_extracted(staging_dir, dest_dir)
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)
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
    kind = archive_kind(upload_path)
    if kind == "zip":
        with zipfile.ZipFile(upload_path) as zf:
            names = zf.namelist()
            for m in names:
                if not _is_safe_member(m):
                    raise ValueError(f"unsafe archive member: {m!r}")
            files = [n for n in names if not n.endswith("/")]
            if not files:
                raise ValueError("archive contains no files")
            return len(files)
    if kind == "tar":
        try:
            with tarfile.open(upload_path) as tf:
                members = [m for m in tf.getmembers() if m.isfile()]
        except tarfile.TarError as exc:
            raise ValueError(f"not a valid tar archive: {exc}") from exc
        if not members:
            raise ValueError("archive contains no files")
        return len(members)
    raise ValueError("not a valid .zip or .tar(.gz) archive")


# Only real network git transports are allowed — never file://, ext::, ssh://, etc.
# Without this an authenticated user could set gitlab_url to file:///... (clone a
# local repo and exfiltrate it via the report/tree) or http://<internal-host> (SSRF).
_ALLOWED_GIT_SCHEMES = ("https", "http")
# git-level transport allowlist enforced on every git subprocess (defense-in-depth,
# incl. any sub-fetches like submodules). Blocks the dangerous transports — ext::
# (remote-helper command execution), ssh, git — while still permitting file (local
# clones in tests/dev); user-supplied file:// URLs are already rejected upstream by
# the scheme allowlist + the RepositoryCreate validator.
GIT_PROTOCOL_ENV = {
    "GIT_ALLOW_PROTOCOL": "file:http:https",
    "GIT_TERMINAL_PROMPT": "0",
    # Ignore any ambient git configuration (insteadOf rewrites, credential helpers, ...).
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}


# ---------------------------------------------------------------------------------
# SSRF guard for repository hosts. A user-supplied gitlab_url is fetched server-side
# (git ls-remote / clone), so it must not reach loopback, private, link-local,
# metadata, multicast or reserved addresses unless the host is explicitly allowlisted
# (VIGILO_GITLAB_ALLOWED_HOSTS, or the host of the worker's GITLAB_URL). The policy is
# greybox_web.netguard's classify_ip (shared, not duplicated). The resolved address is
# pinned into git via http.curloptResolve so DNS cannot change between check and use;
# redirects are disabled so a 3xx cannot bounce git to an unchecked host.
# ---------------------------------------------------------------------------------
_getaddrinfo = socket.getaddrinfo   # indirection so tests can stub DNS


def _allowed_git_hosts(settings) -> set[str]:
    hosts = {h.strip().lower().rstrip(".")
             for h in (settings.gitlab_allowed_hosts or "").split(",") if h.strip()}
    env_url = os.environ.get("GITLAB_URL", "").strip()
    if env_url:
        h = (urlparse(env_url if "//" in env_url else "//" + env_url).hostname or "").lower()
        if h:
            hosts.add(h.rstrip("."))
    return hosts


def resolve_git_host(gitlab_url: str, settings=None) -> tuple[str, int, list[str]]:
    """Resolve and vet the host of ``gitlab_url``. Returns ``(host, port, ips)``;
    raises ValueError if the host (or ANY address it resolves to) is not allowed."""
    from src.greybox_web.netguard import ip_denial, parse_ip
    from src.webapi.settings import get_settings
    settings = settings or get_settings()
    p = urlparse(gitlab_url)
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("repository URL has no host")
    scheme = (p.scheme or "https").lower()
    port = p.port or (443 if scheme == "https" else 80)
    allowlisted = host in _allowed_git_hosts(settings)
    # Allowlisted hosts may be private (an internal GitLab); the always-denied classes
    # (metadata, link-local, multicast, reserved, unspecified) are refused regardless.
    allow_private = allowlisted or bool(settings.repo_allow_private_hosts)
    literal = parse_ip(host)
    if literal is not None:
        ips = [str(literal)]
    else:
        try:
            infos = _getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(f"cannot resolve repository host {host!r}") from exc
        ips = sorted({i[4][0] for i in infos})
        if not ips:
            raise ValueError(f"cannot resolve repository host {host!r}")
    for ip in ips:
        reason = ip_denial(ip, allow_private=allow_private)
        if reason:
            raise ValueError(
                f"repository host {host!r} is not allowed ({reason}); ask an admin to "
                "add it to VIGILO_GITLAB_ALLOWED_HOSTS if it is your GitLab"
            )
    return host, port, ips


def guarded_git_env(gitlab_url: str, settings=None) -> dict:
    """Environment for a git subprocess against ``gitlab_url``: vets the host, pins
    the vetted address (no DNS rebinding) and refuses redirects."""
    host, port, ips = resolve_git_host(gitlab_url, settings)
    env = {**os.environ, **GIT_PROTOCOL_ENV}
    cfg = [("http.followRedirects", "false")]
    if parse_ip_literal(host) is None:
        cfg.append(("http.curloptResolve", f"{host}:{port}:{','.join(ips)}"))
    env["GIT_CONFIG_COUNT"] = str(len(cfg))
    for i, (k, v) in enumerate(cfg):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


def parse_ip_literal(host: str):
    from src.greybox_web.netguard import parse_ip
    return parse_ip(host)


def _require_web_scheme(gitlab_url: str) -> str:
    scheme = (urlparse(gitlab_url).scheme or "https").lower()
    if scheme not in _ALLOWED_GIT_SCHEMES:
        raise ValueError(f"unsupported git URL scheme {scheme!r}; only https/http allowed")
    return scheme


def reject_embedded_credentials(url: str) -> None:
    """A repository URL must not carry ``user[:password]@``: credentials belong in the
    encrypted credential store, and the URL is later used as the trusted push/MR target
    and shown in the UI and logs."""
    p = urlparse(url)
    if p.username is not None or p.password is not None or "@" in (p.netloc or ""):
        raise ValueError(
            "the repository URL must not contain credentials (user:password@); "
            "attach a GitLab token as a credential instead"
        )


def build_clone_url(gitlab_url: str, token: str) -> str:
    """Return an HTTP(S) clone URL with the token injected as oauth2 basic auth.
    Rejects non-web schemes (file://, ext::, ssh://, …) and URLs with embedded
    credentials."""
    scheme = _require_web_scheme(gitlab_url)
    if token and scheme != "https":
        # A token sent over cleartext http can be sniffed or redirected: https only.
        raise ValueError("a repository URL that carries a token must use https://")
    reject_embedded_credentials(gitlab_url)
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
    env = guarded_git_env(gitlab_url)   # SSRF guard + DNS pin (raises ValueError)
    result = runner(
        ["git", "ls-remote", "--heads", clone_url],
        capture_output=True, text=True, timeout=45, env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or "").replace(clone_url, "<clone-url>")
        if token:
            detail = detail.replace(token, "<token>")
        raise RuntimeError(f"git ls-remote failed: {detail.strip()[:300]}")
    return len([ln for ln in (result.stdout or "").splitlines() if ln.strip()])


def clone_repo(clone_url: str, dest_dir: str, depth: int = 1, runner=subprocess.run,
               env: dict | None = None) -> str:
    """Shallow-clone ``clone_url`` into ``dest_dir``. Never echoes the URL (may
    contain a token) on failure."""
    result = runner(
        ["git", "clone", "--depth", str(depth), clone_url, dest_dir],
        capture_output=True, text=True,
        env=env or {**os.environ, **GIT_PROTOCOL_ENV},
    )
    if result.returncode != 0:
        # Scrub: report stderr but not the token-bearing URL/command.
        detail = (result.stderr or "").replace(clone_url, "<clone-url>")
        raise RuntimeError(f"git clone failed: {detail.strip()[:400]}")
    return dest_dir


def scrub_origin_credentials(repo_dir: str, clean_url: str, runner=subprocess.run) -> None:
    """Point ``origin`` back at the credential-free URL. ``git clone <url-with-token>``
    stores that URL in ``.git/config`` — inside the working tree, where a later
    commit/push or an agent could pick it up. Pushing uses a per-run credential
    instead (redeemed just in time, see ``src.webapi.secret_store``).

    Raises when scrubbing fails: a checkout still holding the token must not be used."""
    runner(
        ["git", "-C", repo_dir, "remote", "set-url", "origin", clean_url],
        capture_output=True, text=True, timeout=30, check=True,
        env={**os.environ, **GIT_PROTOCOL_ENV},
    )


def ensure_vigilo_excludes(repo_dir: str) -> None:
    """Keep Vigilo-owned files out of every commit (``.git/info/exclude`` is untracked)."""
    from src.services.git_manager import ensure_vigilo_excludes as _ensure
    _ensure(repo_dir)


def write_remote_marker(repo_dir: str, remote_url: str) -> str:
    """Write ``.vigilo-remote-url`` (clean URL, no credentials). Informational only:
    push and merge-request targets come from the repository record, never from this
    file (it lives in the agent-writable checkout)."""
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
        clone_repo(clone_url, repo_dir, env=guarded_git_env(gitlab_url))
        try:
            scrub_origin_credentials(repo_dir, gitlab_url)
        except Exception as exc:
            # The checkout may still carry the token in .git/config: delete it and fail.
            for entry in os.listdir(repo_dir):
                full = os.path.join(repo_dir, entry)
                if os.path.islink(full) or not os.path.isdir(full):
                    os.unlink(full)
                else:
                    shutil.rmtree(full, ignore_errors=True)
            raise RuntimeError("could not scrub credentials from the checkout; ingestion aborted") from exc
        write_remote_marker(repo_dir, gitlab_url)  # clean url, never the token
        ensure_vigilo_excludes(repo_dir)
    else:
        raise ValueError(f"unknown source_type: {source_type!r}")
    return repo_dir
