"""Patch verification — deterministic proof that a fix actually fixes the finding.

Closes the "patch verification is prompt-only" gap: instead of trusting the
remediation agent's "tests pass" prose, this re-runs, on each ``fix/*`` branch,
the source-level harness the exploit agent built to confirm the finding. The
harness contract is simple and deterministic:

    exit 0   -> the payload still succeeds  -> the vulnerability is STILL present
    exit !=0 -> the payload is blocked      -> the patch fixed it (VERIFIED)

When a finding has no harness, we fall back to a build/lint check and the repo's
detected test command. Results (``pass`` | ``fail`` | ``not_tested`` + method) are
written back into ``remediation_manifest.json`` per branch; the report badges a
fix "verified" only on ``pass``. This never mutates findings and is non-fatal.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

import aiofiles

logger = logging.getLogger(__name__)

# A branch checker takes (branch, finding_ids, harness_paths) and returns
# {"verified": "pass|fail|not_tested", "method": str, "detail": str}. Injected
# for testability; the default implementation does the real git + subprocess work.
BranchChecker = Callable[[str, list[str], list[str]], dict[str, Any]]


def classify_patch(
    harness_exit_after: int | None,
    build_ok: bool | None,
    tests_ok: bool | None,
) -> tuple[str, str]:
    """Pure decision: (verified, method) from the available signals, in priority order.

    Harness is authoritative (it directly re-tests the vulnerability); build/tests
    are weaker fallbacks that only show the patch didn't break compilation/tests.
    """
    if harness_exit_after is not None:
        # exit 0 == vuln still present == patch did NOT fix it.
        return ("pass" if harness_exit_after != 0 else "fail", "harness")
    if tests_ok is not None:
        return ("pass" if tests_ok else "fail", "tests")
    if build_ok is not None:
        # A passing build does NOT prove the vulnerability is fixed — it only
        # shows the patch didn't break compilation. So build-ok is `not_tested`
        # (never `pass`/"verified"); a build *failure* is a real `fail`.
        return ("not_tested", "build") if build_ok else ("fail", "build")
    return ("not_tested", "none")


def _harness_paths_for(finding_ids: list[str], harness_by_id: dict[str, str]) -> list[str]:
    return [harness_by_id[fid] for fid in finding_ids if fid in harness_by_id]


async def _write_manifest(manifest_path: Path, deliverables: Path, manifest: dict[str, Any]) -> None:
    tmp = deliverables / f"remediation_manifest.{os.getpid()}.tmp"
    async with aiofiles.open(tmp, mode="w", encoding="utf-8") as f:
        await f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
    tmp.replace(manifest_path)


async def verify_patches(
    repo_path: str,
    checker: BranchChecker | None = None,
) -> dict[str, Any]:
    """Verify every branch in remediation_manifest.json; write results back into it.

    Returns a summary dict. Non-fatal: missing manifest yields an empty summary.
    """
    deliverables = Path(repo_path) / "deliverables"
    manifest_path = deliverables / "remediation_manifest.json"
    if not manifest_path.is_file():
        logger.info("verify_patches: no remediation_manifest.json — nothing to verify")
        return {"verified": 0, "failed": 0, "not_tested": 0, "branches": 0}

    try:
        async with aiofiles.open(manifest_path, mode="r", encoding="utf-8") as f:
            manifest = json.loads(await f.read())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("verify_patches: cannot read manifest: %s", exc)
        return {"verified": 0, "failed": 0, "not_tested": 0, "branches": 0}

    # Map finding ID -> harness path from the findings index (set by exploit agents).
    harness_by_id: dict[str, str] = {}
    index_path = deliverables / "findings_index.json"
    if index_path.is_file():
        try:
            async with aiofiles.open(index_path, mode="r", encoding="utf-8") as f:
                index = json.loads(await f.read())
            for vulns in (index.get("by_type") or {}).values():
                for v in (vulns if isinstance(vulns, list) else []):
                    hp = v.get("harness_path")
                    fid = str(v.get("ID") or v.get("id") or "")
                    if hp and fid:
                        harness_by_id[fid] = hp
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("verify_patches: cannot read findings_index: %s", exc)

    if checker is None:
        checker = _make_default_checker(repo_path)

    counts = {"pass": 0, "fail": 0, "not_tested": 0}
    for branch in manifest.get("branches", []):
        if not isinstance(branch, dict):
            continue
        name = str(branch.get("branch", ""))
        fids = [str(x) for x in branch.get("finding_ids", [])]
        hpaths = _harness_paths_for(fids, harness_by_id)
        try:
            result = checker(name, fids, hpaths)
        except Exception as exc:  # never let one branch abort the rest
            logger.warning("verify_patches: checker failed for %s: %s", name, exc)
            result = {"verified": "not_tested", "method": "error", "detail": str(exc)}
        branch["verified"] = result.get("verified", "not_tested")
        branch["verify_method"] = result.get("method", "none")
        if result.get("detail"):
            branch["verify_detail"] = result["detail"]
        counts[branch["verified"]] = counts.get(branch["verified"], 0) + 1
        logger.info("verify_patches: %s -> %s (%s)", name, branch["verified"], branch["verify_method"])
        # Persist after EACH branch so a mid-run timeout still keeps prior results.
        await _write_manifest(manifest_path, deliverables, manifest)

    summary = {
        "branches": len(manifest.get("branches", [])),
        "verified": counts.get("pass", 0),
        "failed": counts.get("fail", 0),
        "not_tested": counts.get("not_tested", 0),
    }
    logger.info("verify_patches summary: %s", summary)
    return summary


def _resolve_harness(repo_path: str, hp: str) -> str | None:
    """Resolve a recorded harness path, tolerating the deliverables/ prefix drift.

    Agents write harnesses under deliverables/harnesses/ but may record the path
    with or without the `deliverables/` prefix. Try both so a path-convention
    slip doesn't silently degrade verification to the weak build-only check.
    """
    for cand in (hp, os.path.join("deliverables", hp)):
        full = os.path.join(repo_path, cand)
        if os.path.isfile(full):
            return full
    return None


def _make_default_checker(repo_path: str) -> BranchChecker:
    """Real checker: checkout each fix branch, re-run its harness (or build), restore."""
    import subprocess

    def _run(cmd: list[str], cwd: str, timeout: int = 180) -> int:
        try:
            return subprocess.run(cmd, cwd=cwd, timeout=timeout,
                                  capture_output=True).returncode
        except Exception:  # noqa: BLE001 — treat any launch failure as "couldn't test"
            return -1

    # Remember where we started so we can always restore the working tree — the
    # report step reads source and must not run against a leftover fix branch.
    try:
        original_ref = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path,
            capture_output=True, text=True, timeout=30).stdout.strip() or "HEAD"
    except Exception:  # noqa: BLE001
        original_ref = "HEAD"

    def checker(branch: str, finding_ids: list[str], harness_paths: list[str]) -> dict[str, Any]:
        if _run(["git", "checkout", branch], repo_path) != 0:
            return {"verified": "not_tested", "method": "checkout_failed", "detail": branch}
        try:
            # Prefer the harness — it directly re-tests the vuln on the patched code.
            for hp in harness_paths:
                full = _resolve_harness(repo_path, hp)
                if full:
                    cmd = (["python3", full] if full.endswith(".py") else ["bash", full])
                    rc = _run(cmd, repo_path)
                    if rc != -1:
                        verified, method = classify_patch(rc, None, None)
                        return {"verified": verified, "method": method, "detail": f"{hp} exit={rc}"}
            # Fallback: build-only. This does NOT prove the fix — classify_patch
            # deliberately maps build-ok to `not_tested`, not `pass`.
            build_ok = _run(["python3", "-m", "compileall", "-q", "."], repo_path) == 0
            verified, method = classify_patch(None, build_ok, None)
            return {"verified": verified, "method": method,
                    "detail": "no runnable harness; build-only (not a fix proof)"}
        finally:
            _run(["git", "checkout", original_ref], repo_path)

    return checker
