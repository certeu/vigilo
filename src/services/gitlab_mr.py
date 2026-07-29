"""GitLab Merge Request creation for remediation patches.

After the remediation agent creates fix/* branches and git_push.py
pushes them to the remote, this service creates one MR per fix branch.
Each MR includes a rich description with vulnerability metadata,
evidence excerpts, and screenshot references from the scan deliverables.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Maps vuln ID prefixes to their vulnerability type and evidence filenames
_VULN_PREFIX_TO_TYPE: dict[str, tuple[str, str]] = {
    "INJ": ("injection", "injection"),
    "XSS": ("xss", "xss"),
    "AUTH": ("auth", "auth"),
    "SSRF": ("ssrf", "ssrf"),
    "AUTHZ": ("authz", "authz"),
    "IDOR": ("authz", "authz"),
    "GQL": ("graphql", "graphql"),
    "WS": ("websocket", "websocket"),
    "CRYPTO": ("crypto", "crypto"),
    "CHAIN": ("chain", "chain"),
}


def _get_gitlab_config() -> tuple[str, str]:
    """Return (gitlab_url, gitlab_token) from environment.

    Raises ValueError if GITLAB_TOKEN is not set.
    """
    token = os.environ.get("GITLAB_TOKEN", "")
    if not token:
        raise ValueError("GITLAB_TOKEN environment variable is required for MR creation")

    url = os.environ.get("GITLAB_URL", "https://gitlab.example.com")
    return url.rstrip("/"), token


def _extract_project_path(remote_url: str) -> str:
    """Extract GitLab project path from remote URL.

    Handles both SSH and HTTPS formats:
      git@gitlab.example.com:group/project.git -> group/project
      https://gitlab.example.com/group/project.git -> group/project
    """
    ssh_match = re.match(r"git@[^:]+:(.+?)(?:\.git)?$", remote_url)
    if ssh_match:
        return ssh_match.group(1)

    parsed = urllib.parse.urlparse(remote_url)
    path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path


def _gitlab_api_request(
    gitlab_url: str,
    token: str,
    method: str,
    endpoint: str,
    data: dict | None = None,
) -> dict:
    """Make a GitLab REST API request."""
    url = f"{gitlab_url}/api/v4{endpoint}"
    headers = {
        "PRIVATE-TOKEN": token,
        "Content-Type": "application/json",
    }

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        logger.error("GitLab API error %d: %s", exc.code, error_body)
        raise RuntimeError(f"GitLab API error {exc.code}: {error_body}") from exc


def _get_default_branch_from_api(
    gitlab_url: str, token: str, project_path_encoded: str
) -> str:
    """Query GitLab API for the project's default branch."""
    try:
        project_info = _gitlab_api_request(
            gitlab_url, token, "GET",
            f"/projects/{project_path_encoded}",
        )
        return project_info.get("default_branch", "main")
    except Exception as exc:
        logger.warning("Could not query default branch from API: %s", exc)
        return "main"


# ---------------------------------------------------------------------------
# Vulnerability context extraction for MR descriptions
# ---------------------------------------------------------------------------


def _vuln_type_from_id(vuln_id: str) -> tuple[str, str]:
    """Derive vulnerability type and evidence file prefix from a vuln ID.

    Returns (vuln_type, file_prefix) e.g. ("injection", "injection").
    """
    prefix = vuln_id.split("-")[0]
    return _VULN_PREFIX_TO_TYPE.get(prefix, ("unknown", "unknown"))


def _load_findings_index(repo_path: str) -> dict[str, Any]:
    """Load findings_index.json if it exists."""
    path = Path(repo_path) / "deliverables" / "findings_index.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _find_vuln_in_index(
    index: dict[str, Any], vuln_id: str
) -> dict[str, Any] | None:
    """Find a specific vulnerability entry in the findings index."""
    for vulns in index.get("by_type", {}).values():
        for vuln in vulns:
            vid = vuln.get("ID", vuln.get("id", ""))
            if vid.upper() == vuln_id.upper():
                return vuln
    return None


def _extract_evidence_section(
    repo_path: str, file_prefix: str, vuln_id: str
) -> str:
    """Extract the evidence section for a specific vuln from the evidence markdown."""
    evidence_path = Path(repo_path) / "deliverables" / f"{file_prefix}_exploitation_evidence.md"
    if not evidence_path.is_file():
        return ""

    try:
        content = evidence_path.read_text(encoding="utf-8")
    except OSError:
        return ""

    # Find the section for this vuln ID (between ### headers or end of file)
    pattern = re.compile(
        rf"(###?\s+.*?{re.escape(vuln_id)}.*?\n)(.*?)(?=\n###?\s|\n---|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(content)
    if match:
        section = match.group(1) + match.group(2)
        # Trim to reasonable length for MR description
        if len(section) > 5000:
            section = section[:5000] + "\n\n... *(truncated)*"
        return section.strip()

    return ""


def _find_screenshots(repo_path: str, vuln_id: str) -> list[Path]:
    """Find screenshot files related to a vulnerability ID."""
    screenshots_dir = Path(repo_path) / "deliverables" / "screenshots"
    if not screenshots_dir.is_dir():
        return []

    # Normalize vuln ID for matching: AUTH-VULN-01 -> auth-vuln-01, also try vuln01
    vuln_lower = vuln_id.lower().replace("-", "_")
    # Also try without the VULN part: AUTH-VULN-01 -> auth_01, vuln01
    parts = vuln_id.lower().split("-")
    short_id = parts[-1] if parts else ""  # e.g. "01"
    # Build patterns: exact match, underscore variant, short numeric
    patterns = [vuln_lower, short_id]

    matches = []
    for img in sorted(screenshots_dir.glob("*.png")):
        name_lower = img.stem.lower()
        if any(p in name_lower for p in patterns if p):
            matches.append(img)

    return matches


def _build_mr_description(
    repo_path: str,
    vuln_id: str,
    session_id: str,
    vuln_data: dict[str, Any] | None,
    vuln_type: str,
    file_prefix: str,
    project_url: str,
    default_branch: str,
) -> str:
    """Build a rich MR description for a single vulnerability fix."""
    sections: list[str] = []

    # Header
    sections.append(f"## Security Fix: `{vuln_id}`\n")
    sections.append(
        f"Automated security patch generated by **Vigilo**.\n\n"
        f"**Session:** `{session_id}`"
    )

    # Vulnerability metadata table
    if vuln_data:
        severity = vuln_data.get("severity", "unknown")
        status = vuln_data.get("status", "unknown")
        vtype = vuln_data.get("vulnerability_type", vuln_type)
        confidence = vuln_data.get("confidence", "—")
        ext_exploitable = vuln_data.get("externally_exploitable", "—")
        source = vuln_data.get("source", "")
        sink = vuln_data.get("sink_call", "")
        defense = vuln_data.get("missing_defense", "")

        severity_badge = {
            "critical": "🔴 Critical",
            "high": "🟠 High",
            "medium": "🟡 Medium",
            "low": "🟢 Low",
        }.get(severity.lower(), severity)

        status_badge = "✅ Exploited" if status == "exploited" else "⚪ Unconfirmed"

        sections.append(
            f"\n| Property | Value |\n"
            f"|----------|-------|\n"
            f"| **Severity** | {severity_badge} |\n"
            f"| **Status** | {status_badge} |\n"
            f"| **Type** | {vtype} |\n"
            f"| **Confidence** | {confidence} |"
        )
        if ext_exploitable and ext_exploitable != "—":
            sections.append(f"| **Externally Exploitable** | {'Yes' if ext_exploitable else 'No'} |")
        if source:
            sections.append(f"| **Source** | `{source}` |")
        if sink:
            sections.append(f"| **Sink** | `{sink}` |")
        if defense:
            sections.append(f"\n### Root Cause\n\n{defense}")
    else:
        sections.append(f"\n**Type:** {vuln_type}")

    # Evidence excerpt
    evidence = _extract_evidence_section(repo_path, file_prefix, vuln_id)
    if evidence:
        sections.append(f"\n### Exploitation Evidence\n\n<details>\n<summary>Click to expand evidence</summary>\n\n{evidence}\n\n</details>")

    # Screenshots
    screenshots = _find_screenshots(repo_path, vuln_id)
    if screenshots:
        sections.append("\n### Screenshots\n")
        for ss in screenshots:
            # Use relative path from repo root for GitLab rendering
            label = ss.stem.replace("_", " ").replace("-", " ").title()
            # Reference as uploaded file path — in the MR diff, these won't render
            # as images, but we include the filenames for reference
            sections.append(f"- **{label}**: `{ss.name}`")

    # Footer
    sections.append(
        f"\n---\n\n"
        f"*Generated by Vigilo security scanner*"
    )

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def create_remediation_mrs(
    repo_path: str,
    session_id: str,
    pushed_branches: list[str],
) -> dict[str, Any]:
    """Create one GitLab MR per pushed fix branch.

    Each MR targets the default branch directly, with a rich description
    containing vulnerability metadata, evidence, and screenshot references.

    Parameters
    ----------
    pushed_branches:
        Branch names successfully pushed (e.g. ["fix/AUTH-VULN-01", "fix/XSS-VULN-02"]).

    Returns:
        {
            "created": [{"branch": str, "mr_url": str, "mr_iid": int, "vuln_id": str}, ...],
            "failed": [{"branch": str, "error": str}, ...],
            "total": int,
        }
    """
    if not pushed_branches:
        logger.info("No pushed branches — skipping MR creation")
        return {"created": [], "failed": [], "total": 0}

    gitlab_url, token = _get_gitlab_config()

    # Read remote URL for project path
    remote_url_path = os.path.join(repo_path, ".vigilo-remote-url")
    try:
        with open(remote_url_path) as f:
            remote_url = f.read().strip()
    except FileNotFoundError:
        raise RuntimeError("No .vigilo-remote-url — cannot determine GitLab project")

    project_path = _extract_project_path(remote_url)
    project_path_encoded = urllib.parse.quote(project_path, safe="")
    project_url = f"{gitlab_url}/{project_path}"

    # Get default branch from API
    default_branch = _get_default_branch_from_api(gitlab_url, token, project_path_encoded)

    # Load findings index for vulnerability metadata
    index = _load_findings_index(repo_path)

    created: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for branch in pushed_branches:
        # Extract vuln ID from branch name: fix/AUTH-VULN-01 -> AUTH-VULN-01
        vuln_id = branch.removeprefix("fix/")
        vuln_type, file_prefix = _vuln_type_from_id(vuln_id)
        vuln_data = _find_vuln_in_index(index, vuln_id)

        # Build severity tag for title
        severity = ""
        if vuln_data:
            sev = vuln_data.get("severity", "").lower()
            if sev in ("critical", "high", "medium", "low"):
                severity = f"[{sev.upper()}] "

        title = f"{severity}Fix {vuln_id}: {vuln_type.replace('_', ' ').title()} vulnerability"
        if len(title) > 200:
            title = title[:197] + "..."

        description = _build_mr_description(
            repo_path=repo_path,
            vuln_id=vuln_id,
            session_id=session_id,
            vuln_data=vuln_data,
            vuln_type=vuln_type,
            file_prefix=file_prefix,
            project_url=project_url,
            default_branch=default_branch,
        )

        try:
            mr_data = _gitlab_api_request(
                gitlab_url, token, "POST",
                f"/projects/{project_path_encoded}/merge_requests",
                data={
                    "source_branch": branch,
                    "target_branch": default_branch,
                    "title": title,
                    "description": description,
                    "remove_source_branch": True,
                    "labels": "security,vigilo,automated",
                },
            )

            mr_url = mr_data.get("web_url", "")
            mr_iid = mr_data.get("iid", 0)

            created.append({
                "branch": branch,
                "vuln_id": vuln_id,
                "mr_url": mr_url,
                "mr_iid": mr_iid,
            })
            logger.info("Created MR !%d for %s: %s", mr_iid, vuln_id, mr_url)

        except Exception as exc:
            failed.append({
                "branch": branch,
                "vuln_id": vuln_id,
                "error": str(exc)[:500],
            })
            logger.warning("Failed to create MR for %s: %s", vuln_id, exc)

    logger.info(
        "MR creation complete: %d created, %d failed out of %d branches",
        len(created), len(failed), len(pushed_branches),
    )

    return {
        "created": created,
        "failed": failed,
        "total": len(pushed_branches),
    }
