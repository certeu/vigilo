"""Upstream git operations — rebuild repo from remote and push fix branches.

Before remediation, rebuild_git_from_remote() replaces the preflight-created
.git with a clone of the real upstream. This gives fix branches correct
ancestry so they can be pushed directly after remediation.

After remediation, push_fix_branches() pushes each fix/* branch to origin.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import urllib.parse
from pathlib import Path

from src.services.git_manager import execute_git_command

logger = logging.getLogger(__name__)

REMOTE_URL_FILE = ".vigilo-remote-url"


def _build_auth_url(remote_url: str, user: str, token: str) -> str:
    """Rewrite a remote URL to include token authentication.

    Handles HTTPS URLs directly. For SSH URLs, converts to HTTPS format.
    Result: https://{user}:{token}@{host}/{path}.git
    """
    # SSH format: git@host:path.git -> https://host/path.git
    if remote_url.startswith("git@"):
        host_and_path = remote_url[len("git@"):]
        host, path = host_and_path.split(":", 1)
        remote_url = f"https://{host}/{path}"

    parsed = urllib.parse.urlparse(remote_url)
    path = parsed.path
    if not path.endswith(".git"):
        path = path + ".git"

    return f"{parsed.scheme}://{user}:{token}@{parsed.hostname}{path}"


# ---------------------------------------------------------------------------
# Rebuild git from upstream
# ---------------------------------------------------------------------------


async def rebuild_git_from_remote(repo_path: str) -> bool:
    """Replace the preflight git with a proper clone connected to upstream.

    The Docker image strips .git (via .dockerignore), so preflight creates
    a fresh git init. Fix branches from that synthetic history have unrelated
    ancestry to the real remote, making MRs show every file as changed.

    This function clones the real repo, swaps the .git directory, and
    configures the workspace so that fix branches created from main have
    correct upstream ancestry and can be pushed directly.

    Returns True on success, False if rebuild was skipped or failed.
    """
    # 1. Read remote URL
    remote_url_path = os.path.join(repo_path, REMOTE_URL_FILE)
    try:
        with open(remote_url_path) as f:
            remote_url = f.read().strip()
    except FileNotFoundError:
        logger.info("No %s — skipping git rebuild", REMOTE_URL_FILE)
        return False

    if not remote_url:
        logger.info("Empty %s — skipping git rebuild", REMOTE_URL_FILE)
        return False

    # 2. Build authenticated clone URL if token is available
    token = os.environ.get("GITLAB_TOKEN", "")
    user = os.environ.get("GIT_PUSH_USER", "oauth2")
    clone_url = _build_auth_url(remote_url, user, token) if token else remote_url

    # 3. Clone real repo into temp directory
    clone_dir = tempfile.mkdtemp(prefix="vigilo-rebuild-")

    try:
        logger.info("Rebuilding git from upstream: %s", remote_url)

        await execute_git_command(
            ["git", "clone", "--depth=1", "--single-branch", clone_url, clone_dir],
            cwd="/tmp",
            description="clone upstream for git rebuild",
        )

        # 4. Swap .git directories
        old_git = os.path.join(repo_path, ".git")
        new_git = os.path.join(clone_dir, ".git")

        shutil.rmtree(old_git)
        shutil.move(new_git, old_git)

        # 5. Configure git identity (needed for commits on fix branches)
        await execute_git_command(
            ["git", "config", "user.email", "vigilo@example.com"],
            cwd=repo_path,
            description="set git email after rebuild",
        )
        await execute_git_command(
            ["git", "config", "user.name", "Vigilo Security Scanner"],
            cwd=repo_path,
            description="set git name after rebuild",
        )

        # 6. Reset working tree to match upstream HEAD.
        # After phases 2-5, the working tree has accumulated modifications from
        # vuln/exploit agents. Without this reset, the next checkpoint commit
        # (git add -A) would stage all those changes onto local main, and fix
        # branches created from main would inherit them — causing MRs to show
        # hundreds of unrelated file changes.
        await execute_git_command(
            ["git", "reset", "--hard", "HEAD"],
            cwd=repo_path,
            description="reset working tree to upstream HEAD",
        )

        # 7. Use .git/info/exclude (not .gitignore) for vigilo entries.
        # .git/info/exclude works like .gitignore but is NOT a tracked file,
        # so it won't create a diff against upstream main. This keeps fix
        # branches perfectly clean — only the actual fix shows in the MR.
        exclude_path = os.path.join(repo_path, ".git", "info", "exclude")
        ignore_patterns = [".vigilo/", "deliverables"]
        try:
            existing = ""
            if os.path.isfile(exclude_path):
                with open(exclude_path) as f:
                    existing = f.read()
            existing_lines = existing.splitlines()
            missing = [p for p in ignore_patterns if p not in existing_lines]
            if missing:
                with open(exclude_path, "a") as ex:
                    if existing and not existing.endswith("\n"):
                        ex.write("\n")
                    for pattern in missing:
                        ex.write(f"{pattern}\n")
                logger.info("Added %s to .git/info/exclude", ", ".join(missing))
        except OSError as exc:
            logger.warning("Could not update .git/info/exclude after rebuild: %s", exc)

        # 8. Verify
        stdout, _ = await execute_git_command(
            ["git", "branch", "--show-current"],
            cwd=repo_path,
            description="verify branch after rebuild",
        )
        logger.info("Git rebuild complete. On branch: %s", stdout.strip())

        return True

    except Exception as exc:
        logger.error("Failed to rebuild git from upstream: %s", exc)
        return False
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Push fix branches
# ---------------------------------------------------------------------------


async def push_fix_branches(repo_path: str) -> dict:
    """Push local fix/* branches directly to the upstream remote.

    Requires rebuild_git_from_remote() to have run first so that origin
    is configured and branches have correct ancestry.

    Gated by VIGILO_PUSH_BRANCHES=true (set by ``make scan PUSH=1``).

    Returns:
        {"pushed": ["fix/AUTH-VULN-01", ...], "failed": [...], "skipped": bool}
    """
    # Gate: opt-in check
    if os.environ.get("VIGILO_PUSH_BRANCHES", "").lower() != "true":
        logger.info("VIGILO_PUSH_BRANCHES not set — skipping push")
        return {"pushed": [], "failed": [], "skipped": True}

    # Gate: verify origin remote exists (rebuild_git should have set this up)
    try:
        await execute_git_command(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path,
            description="verify origin remote exists",
        )
    except Exception:
        logger.warning("No origin remote configured — cannot push (did rebuild_git run?)")
        return {"pushed": [], "failed": [], "skipped": True}

    # List fix branches
    stdout, _ = await execute_git_command(
        ["git", "branch", "--list", "fix/*"],
        cwd=repo_path,
        description="list fix branches for push",
    )
    branches: list[str] = []
    for line in stdout.strip().splitlines():
        branch = line.strip().lstrip("* ")
        if branch:
            branches.append(branch)

    if not branches:
        logger.info("No fix/* branches found — nothing to push")
        return {"pushed": [], "failed": [], "skipped": False}

    logger.info("Pushing %d fix branches to upstream", len(branches))

    pushed: list[str] = []
    failed: list[str] = []

    for branch in sorted(branches):
        try:
            await execute_git_command(
                ["git", "push", "origin", branch],
                cwd=repo_path,
                description=f"push {branch}",
            )
            pushed.append(branch)
            logger.info("Pushed %s", branch)
        except Exception as exc:
            failed.append(branch)
            logger.warning("Failed to push %s: %s", branch, exc)

    logger.info(
        "Push complete: %d pushed, %d failed",
        len(pushed), len(failed),
    )
    return {"pushed": pushed, "failed": failed, "skipped": False}
