"""Git manager — checkpoints, rollbacks, and branch management for the pipeline.

Provides:
- Serialized git operations via GitSemaphore (asyncio.Lock)
- Retry with exponential backoff on lock errors
- Checkpoint creation before each agent attempt
- Success commits after agent completion
- Workspace rollback for retries
- Fix branch creation for remediation phase
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

# Patterns that indicate a transient git lock conflict
_GIT_LOCK_ERROR_PATTERNS = (
    "index.lock",
    "unable to lock",
    "Another git process",
    "fatal: Unable to create",
    "fatal: index file",
)


def _is_git_lock_error(message: str) -> bool:
    """Return True if *message* looks like a transient git lock conflict."""
    return any(pattern in message for pattern in _GIT_LOCK_ERROR_PATTERNS)


class GitSemaphore:
    """Serialize git operations to prevent index.lock conflicts during parallel agent execution.

    Wraps an asyncio.Lock so that only one git operation runs at a time within
    a single worker process.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> None:
        await self._lock.acquire()

    async def __aexit__(self, *_exc: object) -> None:
        self._lock.release()


# Module-level semaphore shared across all callers within the same process.
_git_semaphore = GitSemaphore()


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

async def execute_git_command(
    args: list[str],
    cwd: str,
    description: str,
    max_retries: int = 5,
) -> tuple[str, str]:
    """Run a git command with retry on lock errors and exponential backoff.

    Uses ``asyncio.create_subprocess_exec`` (no shell) for safety.

    Parameters
    ----------
    args:
        Full command list, e.g. ``["git", "status", "--porcelain"]``.
    cwd:
        Working directory for the git command.
    description:
        Human-readable description for log messages.
    max_retries:
        Maximum number of attempts before giving up.

    Returns
    -------
    tuple[str, str]
        (stdout, stderr) from the completed process.

    Raises
    ------
    RuntimeError
        If the command fails after all retries.
    """
    async with _git_semaphore:
        last_error: Exception | None = None

        for attempt in range(1, max_retries + 1):
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    cwd=cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await proc.communicate()
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

                if proc.returncode != 0:
                    err_msg = stderr or stdout
                    if _is_git_lock_error(err_msg) and attempt < max_retries:
                        delay = (2 ** (attempt - 1)) * 1.0
                        logger.warning(
                            "Git lock conflict during %s (attempt %d/%d). Retrying in %.1fs...",
                            description, attempt, max_retries, delay,
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise RuntimeError(
                        f"Git command failed ({description}): {err_msg.strip()}"
                    )

                return stdout, stderr

            except RuntimeError:
                raise
            except Exception as exc:
                last_error = exc
                err_msg = str(exc)
                if _is_git_lock_error(err_msg) and attempt < max_retries:
                    delay = (2 ** (attempt - 1)) * 1.0
                    logger.warning(
                        "Git lock conflict during %s (attempt %d/%d). Retrying in %.1fs...",
                        description, attempt, max_retries, delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise

        raise RuntimeError(
            f"Git command failed after {max_retries} retries: {description}"
        ) from last_error


async def _get_changed_files(repo_path: str, description: str) -> list[str]:
    """Return list of changed file lines from ``git status --porcelain``."""
    stdout, _ = await execute_git_command(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        description=description,
    )
    return [line for line in stdout.strip().splitlines() if line]


def _log_change_summary(
    changes: list[str],
    msg_with_changes: str,
    msg_without_changes: str,
    *,
    max_show: int = 5,
) -> None:
    """Log a summary of changed files, truncating long lists."""
    if changes:
        msg = msg_with_changes.replace("{count}", str(len(changes)))
        file_list = ", ".join(c.strip() for c in changes[:max_show])
        suffix = f" ... and {len(changes) - max_show} more files" if len(changes) > max_show else ""
        logger.info("%s %s%s", msg, file_list, suffix)
    else:
        logger.info(msg_without_changes)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def is_git_repository(dir_path: str) -> bool:
    """Return True if *dir_path* is inside a git repository."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "--git-dir",
            cwd=dir_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False


async def create_checkpoint(
    repo_path: str,
    agent_name: str,
    attempt: int,
) -> bool:
    """Create a git checkpoint before an agent attempt.

    On retries (attempt > 1), rolls back the workspace first to prevent
    contamination from the previous attempt.

    Returns True on success, False on failure (non-fatal).
    """
    if not await is_git_repository(repo_path):
        logger.info("Skipping git checkpoint (not a git repository)")
        return True

    description = f"{agent_name} (attempt {attempt})"
    logger.info("Creating checkpoint for %s", description)

    try:
        # On retries, clean workspace first
        if attempt > 1:
            ok = await rollback_workspace(repo_path, f"{agent_name} (retry cleanup)")
            if not ok:
                logger.warning("Workspace cleanup failed, continuing anyway")

        # Detect existing changes for logging
        changes = await _get_changed_files(repo_path, "status check")

        # Stage and commit
        await execute_git_command(
            ["git", "add", "-A"],
            cwd=repo_path,
            description="staging changes",
        )
        await execute_git_command(
            ["git", "commit", "-m", f"Checkpoint: {description}", "--allow-empty", "--no-verify"],
            cwd=repo_path,
            description="creating checkpoint commit",
        )

        if changes:
            logger.info("Checkpoint created with uncommitted changes staged")
        else:
            logger.info("Empty checkpoint created (no workspace changes)")

        return True

    except Exception as exc:
        logger.warning("Checkpoint creation failed: %s", exc)
        return False


async def commit_success(repo_path: str, agent_name: str) -> bool:
    """Commit agent results after successful execution.

    Returns True on success, False on failure (non-fatal).
    """
    if not await is_git_repository(repo_path):
        logger.info("Skipping git commit (not a git repository)")
        return True

    logger.info("Committing successful results for %s", agent_name)

    try:
        changes = await _get_changed_files(repo_path, "status check for success commit")

        await execute_git_command(
            ["git", "add", "-A"],
            cwd=repo_path,
            description="staging changes for success commit",
        )
        await execute_git_command(
            ["git", "commit", "-m", f"{agent_name}: completed successfully", "--allow-empty", "--no-verify"],
            cwd=repo_path,
            description="creating success commit",
        )

        _log_change_summary(
            changes,
            "Success commit created with {count} file changes:",
            "Empty success commit created (agent made no file changes)",
        )
        return True

    except Exception as exc:
        logger.warning("Success commit failed: %s", exc)
        return False


async def rollback_workspace(repo_path: str, reason: str) -> bool:
    """Roll back workspace to HEAD: hard reset tracked files + clean untracked.

    Returns True on success, False on failure (non-fatal).
    """
    if not await is_git_repository(repo_path):
        logger.info("Skipping git rollback (not a git repository)")
        return True

    logger.info("Rolling back workspace for %s", reason)

    try:
        changes = await _get_changed_files(repo_path, "status check for rollback")

        await execute_git_command(
            ["git", "reset", "--hard", "HEAD"],
            cwd=repo_path,
            description="hard reset for rollback",
        )
        await execute_git_command(
            ["git", "clean", "-fd"],
            cwd=repo_path,
            description="cleaning untracked files for rollback",
        )

        _log_change_summary(
            changes,
            "Rollback completed - removed {count} contaminated changes:",
            "Rollback completed - no changes to remove",
            max_show=3,
        )
        return True

    except Exception as exc:
        logger.error("Rollback failed: %s", exc)
        return False


async def get_commit_hash(repo_path: str) -> str | None:
    """Return the current HEAD commit hash, or None if unavailable."""
    if not await is_git_repository(repo_path):
        return None

    try:
        stdout, _ = await execute_git_command(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            description="get commit hash",
        )
        return stdout.strip() or None
    except Exception:
        return None


async def get_branch_name(repo_path: str) -> str | None:
    """Return the current branch name, or None if unavailable or detached."""
    if not await is_git_repository(repo_path):
        return None

    try:
        stdout, _ = await execute_git_command(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            description="get branch name",
        )
        branch = stdout.strip()
        # rev-parse returns "HEAD" when in detached state
        return branch if branch and branch != "HEAD" else None
    except Exception:
        return None


async def create_fix_branch(repo_path: str, vuln_id: str) -> bool:
    """Create a new branch ``fix/{vuln_id}`` for remediation.

    Checks out a new branch from the current HEAD. The remediation agent
    applies its patches there so each fix is isolated.

    Returns True on success, False on failure.
    """
    if not await is_git_repository(repo_path):
        logger.info("Skipping fix branch creation (not a git repository)")
        return False

    branch_name = f"fix/{vuln_id}"
    logger.info("Creating fix branch: %s", branch_name)

    try:
        await execute_git_command(
            ["git", "checkout", "-b", branch_name],
            cwd=repo_path,
            description=f"create fix branch {branch_name}",
        )
        logger.info("Fix branch %s created successfully", branch_name)
        return True
    except Exception as exc:
        logger.error("Failed to create fix branch %s: %s", branch_name, exc)
        return False
