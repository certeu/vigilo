"""Upstream git operations: rebuild the repo from its remote, deliver fix branches.

Trust model. The push / merge-request target (``source.remote_url``) and the scanned
commit come from the platform's repository record and travel as NON-SECRET workflow
input. Nothing here reads a remote from repo-local files (``.vigilo-remote-url``,
``.git/config``): those live in a checkout the agents can write. ``git push`` goes to
the explicit URL, never to ``origin``.

Secrets. The GitLab token is redeemed just in time (``run_secrets.redeem``) for the
call that needs it, held in memory, and handed to ``git`` only through ``GIT_ASKPASS``:
an askpass script that prints an environment variable set on that one git subprocess.
It is never in argv, a remote URL, ``.git/config``, a file, a log or the manifest.

Rebuild. Before remediation :func:`rebuild_git_from_remote` replaces the checkout's
``.git`` with a shallow clone of the upstream, based on the commit that was actually
scanned when it is available upstream (else the current upstream HEAD, recorded in
``.git/vigilo-rebuild.json`` and the manifest). The swap is atomic (move aside, move
in, delete the old one) and crash-recoverable.

Delivery. :func:`deliver_patches` pushes each ``fix/*`` branch and opens one merge
request per pushed branch (a branch may fix several findings). It is idempotent and
serialized: an overlapping retry waits for the running attempt, skips branches already
pushed at the same commit and never downgrades a recorded success. Progress is kept in
``.git/vigilo-delivery.json`` (outside the agent-visible deliverables) and rendered
into ``remediation_manifest.json`` (``pushed``, ``mr_url``, ``push_error``...), which
is what the report reads to say "Delivered" vs "Patch available (local)".
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.services import run_secrets
from src.services.git_manager import ensure_vigilo_excludes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hardened git environment
# ---------------------------------------------------------------------------
# The checkout is writable by the AI agents, so anything in it (``.git/config`` with
# ``url.<x>.insteadOf``, ``.git/hooks/*``, includes, ...) is hostile. Every git process
# started here therefore gets: no global/system config, no hooks, no credential helper,
# a transport allowlist, and an environment rebuilt from a short allowlist
# (nothing GIT_* is inherited from the worker). Token-bearing commands (clone/fetch in
# the rebuild, push) never run inside the checkout: the push comes from a fresh private
# bare repository, see :func:`_push_from_clean_repo`.

# Tests point this at a trusted gitconfig (e.g. an ``insteadOf`` mapping the trusted
# https remote to a local bare repo) and flip the file transport on. Production leaves
# both alone: global config is /dev/null and only https (http without a token) is allowed.
_TRUSTED_GIT_CONFIG: str | None = None
_ALLOW_FILE_PROTOCOL = False

_ENV_PASSTHROUGH = (
    "PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "CURL_CA_BUNDLE",
    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
    "NO_PROXY", "no_proxy",
)
_GIT_HARDENING_ARGS = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "core.fsmonitor=false",
    "-c", "core.sshCommand=false",
    "-c", "protocol.ext.allow=never",
)


def _hardened_env(protocols: str | None = None, *, with_token: bool = False) -> dict[str, str]:
    """Fresh environment for one git process (see the block comment above)."""
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
    if protocols is None:
        protocols = "https" if with_token else "https:http"
        if _ALLOW_FILE_PROTOCOL:
            protocols += ":file"
    env.update({
        "HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": _TRUSTED_GIT_CONFIG or "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": protocols,
        "GIT_ATTR_NOSYSTEM": "1",
    })
    return env


def _git_cmd(args: list[str]) -> list[str]:
    """``["git", *args]`` with the hardening ``-c`` options right after ``git``."""
    if args and args[0] == "git":
        return ["git", *_GIT_HARDENING_ARGS, *args[1:]]
    return args

GIT_OLD = ".git.vigilo-old"
GIT_NEW = ".git.vigilo-new"
REBUILD_STATE = "vigilo-rebuild.json"
DELIVERY_STATE = "vigilo-delivery.json"
DELIVERY_LOCK = "vigilo-delivery.lock"
LOCK_WAIT_S = 600.0


def _clean_remote_url(remote_url: str) -> str:
    """Credential-free https clone URL for a remote (ssh ``git@host:path`` converted).
    Raises ValueError for a URL carrying credentials or a non-web scheme."""
    from src.services.gitlab_mr import _https_remote

    parsed = urlparse(remote_url.strip())
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("repository URL must not contain credentials")
    clean = _https_remote(remote_url)
    scheme = (urlparse(clean).scheme or "").lower()
    if scheme not in ("https", "http") and not (scheme == "file" and _ALLOW_FILE_PROTOCOL):
        raise ValueError("unsupported repository URL scheme")
    return clean


def _require_https_for_token(url: str) -> None:
    """A token is only ever sent over https (never http, file, ssh)."""
    if (urlparse(url).scheme or "").lower() != "https":
        raise ValueError("a GitLab token is only sent to https:// repository URLs")


# ---------------------------------------------------------------------------
# Git runner (credential-aware, cancellation-safe)
# ---------------------------------------------------------------------------

_ASKPASS = """#!/bin/sh
case "$1" in
  Username*) printf '%s\\n' "${VIGILO_GIT_USER:-oauth2}" ;;
  *) printf '%s\\n' "$VIGILO_GIT_TOKEN" ;;
esac
"""


@contextlib.contextmanager
def git_auth_env(token: str, user: str = "oauth2") -> Iterator[dict[str, str]]:
    """Environment for ONE git subprocess that lets it authenticate over HTTPS.

    ``GIT_ASKPASS`` points at a tiny script (no secret in it) that prints
    ``$VIGILO_GIT_TOKEN``; the token exists only in this subprocess's environment, so it
    is never in argv, a URL, ``.git/config`` or on disk. Credential helpers are
    disabled so nothing persists it.
    """
    tmp = tempfile.mkdtemp(prefix="vigilo-askpass-")
    try:
        script = os.path.join(tmp, "askpass.sh")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(_ASKPASS)
        os.chmod(script, stat.S_IRWXU)
        yield {
            "GIT_ASKPASS": script,
            "VIGILO_GIT_TOKEN": token,
            "VIGILO_GIT_USER": user,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def _run_git(
    args: list[str], cwd: str, token: str | None = None, timeout: float = 300,
    protocols: str | None = None,
) -> tuple[int, str, str]:
    """Run git without a shell. With ``token`` it authenticates through GIT_ASKPASS.
    stderr/stdout are scrubbed of the token. A cancelled caller kills the subprocess.
    Returns (rc, stdout, stderr)."""

    def _scrub(text: str) -> str:
        return text.replace(token, "<token>") if token else text

    env = _hardened_env(protocols, with_token=bool(token))
    ctx = git_auth_env(token, os.environ.get("GIT_PUSH_USER", "oauth2")) if token else None
    proc = None
    try:
        if ctx is not None:
            env.update(ctx.__enter__())
        proc = await asyncio.create_subprocess_exec(
            *_git_cmd(args), cwd=cwd, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return 124, "", f"git timed out after {timeout:.0f}s"
        return (
            proc.returncode or 0,
            _scrub(out.decode("utf-8", errors="replace")),
            _scrub(err.decode("utf-8", errors="replace")).strip(),
        )
    except asyncio.CancelledError:
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        raise
    finally:
        if ctx is not None:
            ctx.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# Rebuild git from upstream
# ---------------------------------------------------------------------------


def _git_dir(repo_path: str) -> Path:
    return Path(repo_path) / ".git"


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def recover_git_dir(repo_path: str) -> bool:
    """Undo an interrupted swap: if ``.git`` is missing but the moved-aside copy
    exists, put it back; always drop a half-staged new directory. True if restored."""
    repo = Path(repo_path)
    restored = False
    if not (repo / ".git").exists() and (repo / GIT_OLD).is_dir():
        os.rename(repo / GIT_OLD, repo / ".git")
        restored = True
        logger.warning("Restored .git from an interrupted rebuild")
    shutil.rmtree(repo / GIT_NEW, ignore_errors=True)
    if (repo / ".git").exists():
        shutil.rmtree(repo / GIT_OLD, ignore_errors=True)
    return restored


def swap_git_dir(repo_path: str, new_git: str) -> None:
    """Atomically replace ``<repo>/.git`` with ``new_git``: stage it inside the repo
    (same filesystem), move the old one aside, rename the new one in, then delete the
    old one. A crash leaves either the old ``.git`` or the aside copy that
    :func:`recover_git_dir` restores; never no ``.git`` at all."""
    repo = Path(repo_path)
    staged, old, current = repo / GIT_NEW, repo / GIT_OLD, repo / ".git"
    shutil.rmtree(staged, ignore_errors=True)
    shutil.rmtree(old, ignore_errors=True)
    shutil.move(new_git, staged)            # rename on the same fs, else copy to a staging name
    had_old = current.exists()
    if had_old:
        os.rename(current, old)
    try:
        os.rename(staged, current)
    except BaseException:
        if had_old:
            with contextlib.suppress(OSError):
                os.rename(old, current)
        raise
    shutil.rmtree(old, ignore_errors=True)


async def rebuild_git_from_remote(
    repo_path: str, *, remote_url: str | None, commit: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Replace the checkout's ``.git`` with a clone of the upstream remote.

    ``remote_url`` and ``commit`` (the commit that was scanned) are the platform's
    non-secret input. With a ``commit`` that exists upstream the new history is based
    on it, so fix branches fork from the code that was scanned; otherwise on the
    current upstream HEAD, and the result says so.

    Returns ``{"ok": bool, "base": "scanned_commit"|"upstream_head"|None,
    "commit": sha|None, "requested_commit": sha|None, "reason": str}``; never raises
    for git failures (the existing ``.git`` is left untouched then).
    """
    result: dict[str, Any] = {
        "ok": False, "base": None, "commit": None,
        "requested_commit": commit or None, "reason": "",
    }
    await asyncio.to_thread(recover_git_dir, repo_path)

    if not remote_url or not remote_url.strip():
        result["reason"] = "no upstream remote (uploaded source)"
        return result
    try:
        clone_url = _clean_remote_url(remote_url)
        if token:
            _require_https_for_token(clone_url)
    except ValueError as exc:
        result["reason"] = str(exc)
        return result

    try:
        clone_dir = tempfile.mkdtemp(prefix=".vigilo-rebuild-", dir=str(Path(repo_path).parent))
    except OSError:
        clone_dir = tempfile.mkdtemp(prefix="vigilo-rebuild-")
    try:
        logger.info("Rebuilding git from upstream %s", clone_url)
        rc, _o, err = await _run_git(
            ["git", "clone", "--depth=1", "--single-branch", "--no-checkout", "--template=",
             clone_url, clone_dir],
            cwd=clone_dir, token=token,
        )
        if rc != 0:
            raise RuntimeError(f"git clone failed: {err[:400]}")
        rc, head, _e = await _run_git(["git", "rev-parse", "HEAD"], cwd=clone_dir)
        head = head.strip()
        _rc, branch, _e = await _run_git(["git", "symbolic-ref", "--short", "HEAD"], cwd=clone_dir)
        branch = branch.strip() or "main"

        target, base, note = head, "upstream_head", ""
        if commit and commit == head:
            base = "scanned_commit"
        elif commit:
            rc, _o, _e = await _run_git(
                ["git", "fetch", "--depth=1", "origin", commit], cwd=clone_dir, token=token,
            )
            rc2, _o, _e = await _run_git(
                ["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=clone_dir,
            )
            if rc == 0 and rc2 == 0:
                target, base = commit, "scanned_commit"
            else:
                note = (f"scanned commit {commit[:12]} is not available upstream; "
                        "based on the current upstream HEAD instead")
                logger.warning("Git rebuild: %s", note)
        if target != head:
            # Point the branch at the scanned commit (no working tree needed: only .git is taken).
            await _run_git(["git", "update-ref", f"refs/heads/{branch}", target], cwd=clone_dir)
            await _run_git(["git", "symbolic-ref", "HEAD", f"refs/heads/{branch}"], cwd=clone_dir)

        await asyncio.to_thread(swap_git_dir, repo_path, os.path.join(clone_dir, ".git"))

        for key, val in (("user.email", "vigilo@example.com"), ("user.name", "Vigilo Security Scanner")):
            await _run_git(["git", "config", key, val], cwd=repo_path)
        # The tree has accumulated changes from earlier phases; fix branches must fork
        # from a clean base or the MR would show unrelated changes.
        rc, _o, err = await _run_git(["git", "reset", "--hard", "HEAD"], cwd=repo_path)
        if rc != 0:
            logger.warning("git reset after rebuild failed: %s", err[:300])
        # Untracked Vigilo files must never be committed (see ensure_vigilo_excludes).
        await asyncio.to_thread(ensure_vigilo_excludes, repo_path)

        result.update(ok=True, base=base, commit=target, reason=note)
        logger.info("Git rebuild complete: based on %s (%s)", base, target[:12])
    except Exception as exc:  # noqa: BLE001 - rebuild is non-fatal
        result["reason"] = str(exc)[:400]
        logger.error("Failed to rebuild git from upstream: %s", result["reason"])
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)

    if _git_dir(repo_path).is_dir():
        with contextlib.suppress(OSError):
            _write_json_atomic(_git_dir(repo_path) / REBUILD_STATE, result)
    return result


# ---------------------------------------------------------------------------
# Deliver fix branches (push + merge requests)
# ---------------------------------------------------------------------------


async def _push_from_clean_repo(
    repo_path: str, tmp_root: str, push_url: str, branch: str, tip: str, token: str,
) -> tuple[int, str]:
    """Push ``branch`` (at ``tip``) to ``push_url`` from a private, freshly created bare
    repository, never from the agent-writable checkout.

    The checkout's ``.git/config`` (``url.*.insteadOf``, ``pushInsteadOf``, includes,
    ``core.hooksPath``) and ``.git/hooks`` are attacker-controlled; the token must not
    meet any of them. So: ``git init --bare`` (no templates) in a private temp dir,
    fetch the branch from the checkout by ref (an untokened, local-only fetch whose
    hooks are disabled), verify it is exactly ``tip``, and only then push to the
    explicit URL from there with the token. Returns ``(rc, stderr)``."""
    bare = os.path.join(tmp_root, "push.git")
    if not os.path.isdir(bare):
        rc, _o, err = await _run_git(["git", "init", "--bare", "--quiet", "--template=", bare], tmp_root)
        if rc != 0:
            return rc, f"could not create the push repository: {err[:200]}"
    ref = f"refs/heads/{branch}"
    src = os.path.join(repo_path, ".git")
    rc, _o, err = await _run_git(
        ["git", "fetch", "--no-tags", "--no-write-fetch-head", src, f"+{ref}:{ref}"],
        bare, protocols="file",
    )
    if rc != 0:
        return rc, f"could not stage {branch} for push: {err[:300]}"
    rc, got, _e = await _run_git(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], bare)
    if rc != 0 or got.strip() != tip:
        return 1, f"{branch} changed while it was being delivered; not pushed"
    return await _push_ref(bare, push_url, ref, token)


async def _push_ref(bare: str, push_url: str, ref: str, token: str) -> tuple[int, str]:
    rc, _o, err = await _run_git(
        ["git", "push", push_url, f"{ref}:{ref}"], bare, token=token,
    )
    return rc, err


async def _base_branch(repo_path: str) -> str | None:
    """The branch fix/* branches were cut from — same order as
    ``patch_export._base_branch`` and ``patch_verify._default_branch``:
    the upstream default (``origin/HEAD``), then the current branch unless it
    is a fix branch, then main/master. Never a ``fix/*`` branch."""
    rc, out, _ = await _run_git(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], repo_path)
    if rc == 0 and out.strip():
        return out.strip().removeprefix("origin/")
    rc, out, _ = await _run_git(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo_path)
    current = out.strip() if rc == 0 else ""
    if current and current != "HEAD" and not current.startswith("fix/"):
        return current
    for name in ("main", "master"):
        rc, _o, _e = await _run_git(["git", "show-ref", "--verify", "--quiet", f"refs/heads/{name}"], repo_path)
        if rc == 0:
            return name
    return None


async def _fix_branches(repo_path: str) -> dict[str, str]:
    """``{branch: tip sha}`` of every local ``fix/*`` branch."""
    rc, out, _ = await _run_git(
        ["git", "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads/fix/"], repo_path,
    )
    tips: dict[str, str] = {}
    if rc == 0:
        for line in out.splitlines():
            name, _, sha = line.strip().partition(" ")
            if name and sha:
                tips[name] = sha
    return dict(sorted(tips.items()))


def _load_state(repo_path: str) -> dict[str, dict[str, Any]]:
    branches = _read_json(_git_dir(repo_path) / DELIVERY_STATE).get("branches")
    return branches if isinstance(branches, dict) else {}


def _save_state(repo_path: str, branches: dict[str, dict[str, Any]]) -> None:
    _write_json_atomic(_git_dir(repo_path) / DELIVERY_STATE, {"branches": branches})


def _effective(state: dict[str, dict[str, Any]], branch: str, tip: str | None) -> dict[str, Any]:
    """The recorded delivery of ``branch`` if it is still about the current tip."""
    st = state.get(branch) or {}
    return st if st.get("pushed") and (tip is None or st.get("commit") == tip) else {}


@contextlib.asynccontextmanager
async def _delivery_lock(repo_path: str, wait_s: float = LOCK_WAIT_S):
    """Exclusive lock serializing delivery attempts on one checkout (flock: works
    between the coroutines of one process and between processes). Yields False when
    the lock could not be had within ``wait_s``."""
    gdir = _git_dir(repo_path)
    if not gdir.is_dir():
        yield True  # nothing to protect; the caller will skip for lack of history
        return
    fd = os.open(gdir / DELIVERY_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    got = False
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got = True
                break
            except BlockingIOError:
                if loop.time() >= deadline:
                    break
                await asyncio.sleep(0.5)
        yield got
    finally:
        if got:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _update_manifest(
    repo_path: str, rows: dict[str, dict[str, Any]], delivery: dict[str, Any],
) -> None:
    """Render per-branch push/MR outcome (and a top-level ``delivery`` + ``git_base``)
    into the manifest. ``rows`` is authoritative for every branch it lists; ``pushed``
    is overwritten with the real outcome for every manifest branch."""
    deliverables = Path(repo_path) / "deliverables"
    path = deliverables / "remediation_manifest.json"
    if not path.is_file():
        return
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("deliver_patches: cannot read manifest: %s", exc)
        return
    if not isinstance(manifest, dict):
        return
    entries = manifest.setdefault("branches", [])
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("branch", "")
        seen.add(name)
        res = rows.get(name) or {}
        entry["pushed"] = bool(res.get("pushed"))
        for key in ("mr_url", "push_error", "mr_error", "pushed_commit"):
            if res.get(key):
                entry[key] = res[key]
            else:
                entry.pop(key, None)
    for name, res in rows.items():
        if name in seen:
            continue
        extra: dict[str, Any] = {
            "branch": name,
            "finding_ids": [name.removeprefix("fix/")],
            "files_changed": [],
            "pushed": bool(res.get("pushed")),
            "diff_nonempty": res.get("diff_nonempty", True),
        }
        for key in ("mr_url", "push_error", "mr_error", "pushed_commit"):
            if res.get(key):
                extra[key] = res[key]
        entries.append(extra)
    manifest["delivery"] = delivery
    rebuild = _read_json(_git_dir(repo_path) / REBUILD_STATE)
    if rebuild:
        manifest["git_base"] = {
            k: rebuild.get(k) for k in ("ok", "base", "commit", "requested_commit", "reason")
        }
    tmp = deliverables / f"remediation_manifest.{os.getpid()}.deliver.tmp"
    try:
        tmp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        logger.warning("deliver_patches: cannot write manifest: %s", exc)


async def deliver_patches(
    repo_path: str,
    session_id: str,
    push: dict[str, Any] | None,
    *,
    source: dict[str, Any] | None = None,
    secrets: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Push fix/* branches to the upstream remote and open one MR per pushed branch.

    Runs only when ``push["enabled"]``, ``source["remote_url"]`` (the repository's
    remote, from the platform) and a ``secrets`` reference are present; otherwise
    nothing is pushed and the manifest records every branch as ``pushed: false`` (the
    report then says the patches are available locally), except for branches an
    earlier attempt already delivered, which stay delivered. Never raises for
    git/GitLab failures; those are recorded per branch.

    Idempotent and serialized: see the module docstring.

    Returns ``{"status": skipped|nothing|delivered|partial|failed|busy, "reason": str,
    "pushed": [...], "already_delivered": [...], "failed": [...],
    "merge_requests": [...]}``.
    """
    async with _delivery_lock(repo_path) as got:
        if not got:
            return {
                "status": "busy", "reason": "another delivery attempt holds the lock",
                "pushed": [], "already_delivered": [], "failed": [], "merge_requests": [],
            }
        return await _deliver_locked(repo_path, session_id, push, source, secrets)


async def _deliver_locked(
    repo_path: str, session_id: str, push: dict[str, Any] | None,
    source: dict[str, Any] | None, secrets: dict[str, Any] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "skipped", "reason": "", "pushed": [], "already_delivered": [],
        "failed": [], "merge_requests": [],
    }
    attempt: dict[str, dict[str, Any]] = {}   # this attempt's errors / flags per branch
    tips: dict[str, str] = {}

    def finish(status: str, reason: str = "") -> dict[str, Any]:
        state = _load_state(repo_path)
        rows: dict[str, dict[str, Any]] = {}
        for name in sorted(set(tips) | set(attempt)):
            eff = _effective(state, name, tips.get(name))
            cur = attempt.get(name, {})
            row: dict[str, Any] = {"pushed": bool(eff)}
            if eff:
                row["pushed_commit"] = eff.get("commit")
                if eff.get("mr_url"):
                    row["mr_url"] = eff["mr_url"]
            for key in ("diff_nonempty", "mr_error"):
                if key in cur and not (key == "mr_error" and row.get("mr_url")):
                    row[key] = cur[key]
            if (state.get(name) or {}).get("empty_at") == tips.get(name) and tips.get(name):
                # an earlier attempt found this tip identical to the base branch
                row["diff_nonempty"] = False
                cur = {**cur, "push_error": cur.get("push_error") or "no changes relative to the base branch; not pushed"}
            if cur.get("push_error") and not eff:
                row["push_error"] = cur["push_error"]
            rows[name] = row
        delivered = [n for n, r in rows.items() if r["pushed"]]
        if delivered and status in ("skipped", "failed", "nothing"):
            # A real earlier success is never downgraded by a later no-op/failed attempt.
            status = "delivered" if len(delivered) == len(
                [n for n, r in rows.items() if r.get("diff_nonempty", True)]
            ) else "partial"
            reason = f"earlier delivery preserved; this attempt: {reason or 'no change'}"
        result["status"], result["reason"] = status, reason
        summary = {
            "status": status, "reason": reason,
            "pushed": len(delivered), "failed": len(result["failed"]),
            "merge_requests": len([r for r in rows.values() if r.get("mr_url")]),
        }
        _update_manifest(repo_path, rows, summary)
        logger.info("Patch delivery: %s%s", status, f" ({reason})" if reason else "")
        return result

    # Current branch tips first: every outcome (including the skips below) is rendered
    # against them, so an earlier success is preserved whatever this attempt does.
    try:
        tips.update(await _fix_branches(repo_path))
    except OSError:
        pass

    if not (push or {}).get("enabled"):
        return finish("skipped", "push not enabled for this run")
    remote_url = ((source or {}).get("remote_url") or "").strip()
    if not remote_url:
        return finish("skipped", "repository has no upstream remote (uploaded source)")
    try:
        push_url = _clean_remote_url(remote_url)
    except ValueError as exc:
        return finish("skipped", f"invalid repository URL: {exc}")
    if not run_secrets.has_reference(secrets):
        return finish("skipped", "no GitLab credential available for this run")

    # Only push history that really descends from upstream: a rebuilt checkout, or the
    # API's clone that still contains the scanned commit.
    rebuild = _read_json(_git_dir(repo_path) / REBUILD_STATE)
    scanned = (source or {}).get("commit")
    has_history = bool(rebuild.get("ok"))
    if not has_history and scanned:
        rc, _o, _e = await _run_git(["git", "cat-file", "-e", f"{scanned}^{{commit}}"], repo_path)
        has_history = rc == 0
    if not has_history:
        return finish("skipped", "no upstream history (git rebuild did not succeed)")

    if not tips:
        return finish("nothing", "no fix branches")
    base = await _base_branch(repo_path)
    state = _load_state(repo_path)

    # Decide the work first, so the token is redeemed only when something needs it.
    to_push: list[str] = []
    for branch, tip in tips.items():
        info = attempt.setdefault(branch, {})
        if _effective(state, branch, tip):
            result["already_delivered"].append(branch)
            continue
        if base:
            rc, _o, _e = await _run_git(["git", "diff", "--quiet", f"{base}..{branch}"], repo_path)
            if rc == 0:
                info["diff_nonempty"] = False
                info["push_error"] = f"no changes relative to {base}; not pushed"
                state = _load_state(repo_path)
                state[branch] = {**state.get(branch, {}), "empty_at": tip}
                _save_state(repo_path, state)
                continue
        to_push.append(branch)
    to_mr = [b for b in result["already_delivered"] if not _effective(state, b, tips[b]).get("mr_url")]

    if not to_push and not to_mr:
        if result["already_delivered"]:
            return finish("delivered", "already delivered")
        return finish("nothing", "no fix branch has changes")

    try:
        # The cookie (when the run had one) is redeemed too, only so that it is
        # registered for masking: evidence write-ups can quote it and must not reach
        # the merge request. It is never used here.
        redeemed = await run_secrets.redeem(secrets, ["forge_token", "cookie_header"])
        token = redeemed.get("forge_token")
        del redeemed
    except run_secrets.RedemptionRefused:
        return finish("skipped", "GitLab credential no longer available (run finished or revoked)")
    except run_secrets.RedemptionUnavailable as exc:
        for b in to_push:
            attempt[b]["push_error"] = f"credential service unavailable: {exc}"
            result["failed"].append(b)
        result["retryable"] = True   # transient: the activity lets Temporal retry (idempotent)
        return finish("failed", "could not redeem the GitLab credential")
    if not token:
        return finish("skipped", "no GitLab credential available for this run")

    try:
        _require_https_for_token(push_url)
    except ValueError as exc:
        for b in to_push:
            attempt[b]["push_error"] = str(exc)
            result["failed"].append(b)
        return finish("failed", str(exc))

    push_tmp = tempfile.mkdtemp(prefix="vigilo-push-")
    try:
        pushed_now: list[str] = []
        for branch in to_push:
            rc, err = await _push_from_clean_repo(
                repo_path, push_tmp, push_url, branch, tips[branch], token,
            )
            if rc == 0:
                state = _load_state(repo_path)   # re-read: never overwrite a concurrent success
                state[branch] = {**state.get(branch, {}), "commit": tips[branch], "pushed": True}
                _save_state(repo_path, state)
                pushed_now.append(branch)
                result["pushed"].append(branch)
                logger.info("Pushed %s", branch)
            else:
                attempt[branch]["push_error"] = (err or f"git push exited {rc}")[:500]
                result["failed"].append(branch)
                logger.warning("Failed to push %s: %s", branch, attempt[branch]["push_error"])

        need_mr = pushed_now + to_mr
        if need_mr:
            try:
                from src.services.gitlab_mr import create_remediation_mrs

                mrs = await create_remediation_mrs(
                    repo_path, session_id, need_mr, token=token, remote_url=push_url,
                )
                state = _load_state(repo_path)
                for mr in mrs.get("created", []):
                    st = state.setdefault(mr["branch"], {"commit": tips.get(mr["branch"]), "pushed": True})
                    st["mr_url"] = mr.get("mr_url", "")
                    st["mr_iid"] = mr.get("mr_iid", 0)
                    result["merge_requests"].append(mr.get("mr_url", ""))
                _save_state(repo_path, state)
                for mr in mrs.get("failed", []):
                    attempt.setdefault(mr["branch"], {})["mr_error"] = str(mr.get("error", ""))[:500]
            except Exception as exc:  # noqa: BLE001 - delivery must never fail the run
                msg = str(exc).replace(token, "<token>")[:500]
                logger.warning("MR creation failed: %s", msg)
                for b in need_mr:
                    attempt.setdefault(b, {})["mr_error"] = msg
    finally:
        shutil.rmtree(push_tmp, ignore_errors=True)
        token = ""  # noqa: F841 - drop the in-memory credential

    if result["failed"] and not result["pushed"] and not result["already_delivered"]:
        return finish("failed", "no branch could be pushed")
    if result["failed"]:
        return finish("partial", "some branches could not be pushed")
    return finish("delivered")
