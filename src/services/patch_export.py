"""Export fix/* branches as .patch files into deliverables.

After the remediation agent creates fix branches, this module generates
a unified diff for each branch (relative to main/master) and writes it
to deliverables/patches/<VULN-ID>.patch. These files persist to the host
via the deliverables symlink and can be shared or applied with `git apply`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from src.services.git_manager import execute_git_command

logger = logging.getLogger(__name__)


async def _get_fix_branches(repo_path: str) -> list[str]:
    """List all local fix/* branches."""
    stdout, _ = await execute_git_command(
        ["git", "branch", "--list", "fix/*"],
        cwd=repo_path,
        description="list fix branches",
    )
    branches = []
    for line in stdout.strip().splitlines():
        branch = line.strip().lstrip("* ")
        if branch:
            branches.append(branch)
    return sorted(branches)


async def export_patches(repo_path: str) -> dict:
    """Generate .patch files for all fix/* branches.

    Uses git format-patch to produce self-contained patches that include
    commit messages and can be applied with `git am`.

    Returns:
        {"exported": ["fix/AUTH-VULN-01", ...], "failed": [...]}
    """
    branches = await _get_fix_branches(repo_path)
    if not branches:
        logger.info("No fix/* branches found — nothing to export")
        return {"exported": [], "failed": []}

    patches_dir = Path(repo_path) / "deliverables" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)

    exported: list[str] = []
    failed: list[str] = []

    # Determine the default branch (main or master) for diff base
    default_branch = "main"
    try:
        stdout_check, _ = await execute_git_command(
            ["git", "rev-parse", "--verify", "main"],
            cwd=repo_path,
            description="check if main branch exists",
        )
    except Exception:
        default_branch = "master"

    for branch in branches:
        patch_name = branch.removeprefix("fix/") + ".patch"
        patch_path = patches_dir / patch_name

        try:
            # Show all changes on this branch vs default branch (supports multi-commit branches)
            stdout, _ = await execute_git_command(
                ["git", "diff", f"{default_branch}...{branch}"],
                cwd=repo_path,
                description=f"generate patch for {branch}",
            )
            if stdout.strip():
                patch_path.write_text(stdout)
                exported.append(branch)
                logger.info("Exported %s → %s", branch, patch_path.name)
            else:
                # Diagnose: check if branch has commits ahead of default branch
                try:
                    log_out, _ = await execute_git_command(
                        ["git", "log", f"{default_branch}..{branch}", "--oneline"],
                        cwd=repo_path,
                        description=f"check commits on {branch}",
                    )
                    if log_out.strip():
                        logger.warning(
                            "Empty diff for %s but branch has commits: %s "
                            "— branch was likely merged into %s",
                            branch, log_out.strip(), default_branch,
                        )
                    else:
                        logger.warning(
                            "Empty diff for %s — branch has no commits ahead of %s "
                            "(sub-agent may have failed to commit on the branch)",
                            branch, default_branch,
                        )
                except Exception:
                    logger.warning("Empty diff for %s — skipping", branch)
                failed.append(branch)
        except Exception as exc:
            failed.append(branch)
            logger.warning("Failed to export %s: %s", branch, exc)

    logger.info(
        "Patch export complete: %d exported, %d failed",
        len(exported), len(failed),
    )
    return {"exported": exported, "failed": failed}
