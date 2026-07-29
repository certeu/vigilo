"""Reporting service — assembles a structured security report from specialist deliverables.

Parses exploitation evidence files into individual findings, deduplicates them,
cross-references remediation info, and builds a complete markdown report with
title, TOC, findings tables, per-category sections, and remediation cross-refs.
The report agent (LLM) then does an editorial pass to fill placeholder sections.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeliverableFile:
    """Describes an exploitation evidence file to include in the final report."""
    name: str
    filename: str
    required: bool


# Exploitation evidence files only — remediation is read separately by the
# report agent and integrated per-vulnerability, not appended as a block.
DELIVERABLE_FILES: tuple[DeliverableFile, ...] = (
    DeliverableFile("Injection", "injection_exploitation_evidence.md", required=False),
    DeliverableFile("XSS", "xss_exploitation_evidence.md", required=False),
    DeliverableFile("Authentication", "auth_exploitation_evidence.md", required=False),
    DeliverableFile("SSRF", "ssrf_exploitation_evidence.md", required=False),
    DeliverableFile("Authorization", "authz_exploitation_evidence.md", required=False),
    DeliverableFile("GraphQL", "graphql_exploitation_evidence.md", required=False),
    DeliverableFile("WebSocket", "websocket_exploitation_evidence.md", required=False),
    DeliverableFile("Chain", "chain_exploitation_evidence.md", required=False),
)


# ---------------------------------------------------------------------------
# Constants & mappings
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}

_CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    "injection": "Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "auth": "Authentication",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "authz": "Authorization",
    "graphql": "GraphQL",
    "websocket": "WebSocket",
    "crypto": "Cryptography",
    "chain": "Attack Chains",
    "integrity": "Code Integrity",
}

# Ordered list of regular (non-chain) categories for section ordering.
_CATEGORY_ORDER: list[str] = [
    "injection", "xss", "auth", "ssrf", "authz", "graphql", "websocket", "crypto", "integrity",
]

# Regex for VULN-ID headers: ### INJ-VULN-01: Title  or  ### CHAIN-001: Title
_VULN_HEADER_RE = re.compile(
    r"^### ([A-Z]+-(?:VULN-?\d+|\d+))\s*:\s*(.+)$", re.MULTILINE,
)

# Regex for ## parent headings (used for status detection)
_PARENT_HEADING_RE = re.compile(r"^## (.+)$", re.MULTILINE)

# Regex for severity extraction — permissive to handle formatting variations
# Matches: **Severity:** Critical, **Severity**: Critical, **Severity: Critical**
_SEVERITY_RE = re.compile(
    r"\*\*Severity\*?\*?:?\*?\*?\s*:?\s*(Critical|High|Medium|Low|Informational)",
    re.IGNORECASE,
)

# Regex for explicit status markers — same permissive pattern
_STATUS_RE = re.compile(
    r"\*\*Status\*?\*?:?\*?\*?\s*:?\s*(Exploited|Confirmed|Potential|Unconfirmed)",
    re.IGNORECASE,
)

# Regex for fix branch references in remediation report
_FIX_BRANCH_RE = re.compile(r"fix/([A-Z]+-(?:VULN-?\d+|\d+))")

# Regex for files changed section — matches backtick-wrapped and bare paths
_FILES_CHANGED_RE = re.compile(
    r"^\s*[-*]\s+`([^`]+)`"   # `path/to/file.py`
    r"|"
    r"^\s*[-*]\s+([\w/][\w./:-]+\.\w+)",  # path/to/file.py (bare)
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Data classes for parsed findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single vulnerability extracted from evidence files."""
    vuln_id: str
    title: str
    category: str
    severity: str
    status: str  # "Exploited", "Confirmed", "Potential", "Unconfirmed"
    evidence_markdown: str
    fix_branch: str | None = None
    fix_description: str | None = None
    fix_files: list[str] = field(default_factory=list)


@dataclass
class RemediationInfo:
    """Parsed remediation info for a single vulnerability."""
    vuln_id: str
    branch: str | None = None
    description: str | None = None
    files_changed: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing functions
# ---------------------------------------------------------------------------

def _detect_category_from_filename(filename: str) -> str:
    """Extract category key from an evidence filename.

    Examples:
        "injection_exploitation_evidence.md" -> "injection"
        "chain_exploitation_evidence.md"     -> "chain"
    """
    # Strip "_exploitation_evidence.md" suffix and return the prefix
    stem = filename.replace("_exploitation_evidence.md", "")
    return stem


def _extract_severity(section: str) -> str:
    """Extract severity from a finding section, default 'Medium'."""
    match = _SEVERITY_RE.search(section)
    if match:
        return match.group(1).capitalize()
    return "Medium"


def _extract_status(section: str, parent_heading: str) -> str:
    """Determine finding status from parent heading and explicit markers.

    Priority:
    1. Parent ``## Successfully Exploited`` heading -> "Exploited"
    2. Parent ``## Potential`` or ``## Validation Blocked`` -> "Unconfirmed"
    3. Explicit ``**Status:**`` marker in section text
    4. Default: "Confirmed"
    """
    heading_lower = parent_heading.lower().strip()

    if "successfully exploited" in heading_lower:
        return "Exploited"
    if "potential" in heading_lower or "validation blocked" in heading_lower:
        return "Unconfirmed"

    match = _STATUS_RE.search(section)
    if match:
        return match.group(1).capitalize()

    return "Confirmed"


def _parse_evidence_file(content: str, category: str) -> list[Finding]:
    """Parse an evidence markdown file into individual Finding objects.

    Splits on ``### VULN-ID: Title`` headers. Tracks the current ``## ``
    parent heading for status detection.
    """
    findings: list[Finding] = []
    if not content.strip():
        return findings

    # Find all ## parent headings and ### vuln headers with their positions
    parent_headings: list[tuple[int, str]] = []
    for match in _PARENT_HEADING_RE.finditer(content):
        parent_headings.append((match.start(), match.group(1)))

    vuln_headers: list[tuple[int, int, str, str]] = []
    for match in _VULN_HEADER_RE.finditer(content):
        vuln_headers.append((match.start(), match.end(), match.group(1), match.group(2)))

    if not vuln_headers:
        return findings

    for idx, (h_start, h_end, vuln_id, title) in enumerate(vuln_headers):
        # Determine section end: next ### header or end of file
        if idx + 1 < len(vuln_headers):
            section_end = vuln_headers[idx + 1][0]
        else:
            section_end = len(content)

        section_text = content[h_start:section_end]

        # Determine current parent heading (last ## before this ###)
        current_parent = ""
        for pos, heading_text in parent_headings:
            if pos < h_start:
                current_parent = heading_text
            else:
                break

        severity = _extract_severity(section_text)
        status = _extract_status(section_text, current_parent)

        findings.append(Finding(
            vuln_id=vuln_id,
            title=title.strip(),
            category=category,
            severity=severity,
            status=status,
            evidence_markdown=section_text,
        ))

    return findings


def _parse_remediation_report(content: str) -> dict[str, RemediationInfo]:
    """Parse remediation_report.md into per-vuln RemediationInfo.

    Looks for ``fix/VULN-ID`` branch references and extracts descriptions
    and file lists from surrounding context.
    """
    remediation: dict[str, RemediationInfo] = {}
    if not content.strip():
        return remediation

    # Split into sections by ## or ### headings that contain a fix/ branch ref
    # Strategy: find all fix/VULN-ID references, then extract surrounding context
    sections = re.split(r"(?=^##+ )", content, flags=re.MULTILINE)

    for section in sections:
        branch_matches = list(_FIX_BRANCH_RE.finditer(section))
        if not branch_matches:
            continue

        for branch_match in branch_matches:
            vuln_id = branch_match.group(1)
            branch_name = f"fix/{vuln_id}"

            # Extract description: lines between the heading and any files list
            lines = section.strip().splitlines()
            desc_lines: list[str] = []
            for line in lines[1:]:  # skip heading
                if line.strip().startswith(("-", "*")) and "`" in line:
                    break
                if line.strip():
                    desc_lines.append(line.strip())

            description = " ".join(desc_lines) if desc_lines else None

            # Extract files changed (regex has two groups: backtick-wrapped | bare)
            raw_matches = _FILES_CHANGED_RE.findall(section)
            files = [g1 or g2 for g1, g2 in raw_matches if g1 or g2]

            remediation[vuln_id] = RemediationInfo(
                vuln_id=vuln_id,
                branch=branch_name,
                description=description,
                files_changed=files,
            )

    return remediation


def _create_stub_findings_from_index(
    index_content: str,
    existing_vuln_ids: set[str],
) -> list[Finding]:
    """Create stub Finding objects from findings_index.json for types without evidence files.

    This covers vulnerability types like crypto that have analysis findings
    (in the exploitation queue) but no dedicated exploit agent to produce
    evidence files. These appear as "Unconfirmed" in the report.
    """
    stubs: list[Finding] = []
    try:
        data = json.loads(index_content)
        by_type: dict[str, list[dict[str, Any]]] = data.get("by_type", {})
    except (json.JSONDecodeError, TypeError):
        return stubs

    for vuln_type, vulns in by_type.items():
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            # Queue formats vary: older prompts use uppercase "ID",
            # newer ones (graphql, websocket) use lowercase "id".
            vuln_id = v.get("id") or v.get("ID", "")
            if not vuln_id or vuln_id in existing_vuln_ids:
                continue

            # Build a minimal evidence section from queue data
            title = v.get("type", v.get("vulnerability_type", "Unknown"))
            confidence = v.get("confidence", "unknown")
            endpoint = v.get("endpoint", "")
            reason = v.get("reason", v.get("mismatch_reason", ""))

            evidence_lines = [f"### {vuln_id}: {title}"]
            evidence_lines.append("")
            evidence_lines.append("**Summary:**")
            if endpoint:
                evidence_lines.append(f"- **Endpoint:** {endpoint}")
            evidence_lines.append(f"- **Confidence:** {confidence}")
            evidence_lines.append(f"- **Status:** Unconfirmed (analysis only — no exploitation attempted)")
            if reason:
                evidence_lines.append(f"- **Details:** {reason}")

            stubs.append(Finding(
                vuln_id=vuln_id,
                title=title,
                category=vuln_type,
                severity="Medium",
                status="Unconfirmed",
                evidence_markdown="\n".join(evidence_lines),
            ))

    return stubs


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by VULN-ID, keeping the version with longest evidence."""
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.vuln_id not in seen:
            seen[f.vuln_id] = f
        elif len(f.evidence_markdown) > len(seen[f.vuln_id].evidence_markdown):
            seen[f.vuln_id] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# Builder functions
# ---------------------------------------------------------------------------

def _current_date() -> str:
    """Return today's date in ISO format."""
    return date.today().isoformat()


def _severity_sort_key(finding: Finding) -> int:
    """Return sort key from _SEVERITY_ORDER (lower = more critical)."""
    return _SEVERITY_ORDER.get(finding.severity.lower(), 99)


def _anchor(heading: str) -> str:
    """Generate a markdown TOC anchor from a heading string.

    Lowercases, replaces spaces with hyphens, removes parentheses.
    """
    anchor = heading.lower()
    anchor = anchor.replace("(", "").replace(")", "")
    anchor = anchor.replace(" ", "-")
    # Remove any characters that aren't alphanumeric, hyphens, or underscores
    anchor = re.sub(r"[^a-z0-9_-]", "", anchor)
    return anchor


def _build_title_section(
    web_url: str,
    description: str | None,
    branch: str | None,
    commit: str | None,
    repo_path: str,
) -> str:
    """Build the report title block with metadata."""
    lines: list[str] = ["# Comprehensive Security Assessment Report"]

    if description:
        lines.append(f"\n{description}")

    lines.append(f"\n**Assessment Date:** {_current_date()}")
    lines.append(f"**Target:** {web_url}")
    lines.append(f"**Repository:** {repo_path}")

    git_line_parts: list[str] = []
    if branch:
        git_line_parts.append(f"**Branch:** {branch}")
    if commit:
        short_hash = commit[:8] if len(commit) > 8 else commit
        git_line_parts.append(f"**Commit:** {short_hash}")
    if git_line_parts:
        lines.append(" | ".join(git_line_parts))

    return "\n".join(lines)


def _build_toc(
    category_findings: dict[str, list[Finding]],
    has_chains: bool,
) -> str:
    """Build Table of Contents with anchor links and finding counts."""
    lines: list[str] = ["## Table of Contents", ""]

    lines.append(f"- [Executive Summary](#{_anchor('Executive Summary')})")
    lines.append(f"- [Findings Overview](#{_anchor('Findings Overview')})")

    for cat_key in _CATEGORY_ORDER:
        if cat_key not in category_findings or not category_findings[cat_key]:
            continue
        display = _CATEGORY_DISPLAY_NAMES.get(cat_key, cat_key.title())
        count = len(category_findings[cat_key])
        heading = f"{display} Vulnerabilities"
        lines.append(f"- [{heading} ({count})](#{_anchor(heading)})")

    if has_chains:
        lines.append(f"- [Attack Chains](#{_anchor('Attack Chains')})")

    lines.append(f"- [Unpatched Vulnerabilities](#{_anchor('Unpatched Vulnerabilities')})")

    return "\n".join(lines)


def _build_findings_overview(all_findings: list[Finding]) -> str:
    """Build the Findings Overview section with master table and category summary."""
    lines: list[str] = ["## Findings Overview"]

    # --- Master findings table sorted by severity ---
    sorted_findings = sorted(all_findings, key=_severity_sort_key)

    lines.append("")
    lines.append("### All Findings")
    lines.append("")
    lines.append("| # | ID | Category | Severity | Title | Status | Fix |")
    lines.append("|---|-----|----------|----------|-------|--------|-----|")

    for idx, f in enumerate(sorted_findings, 1):
        display_cat = _CATEGORY_DISPLAY_NAMES.get(f.category, f.category.title())
        fix_marker = f"`{f.fix_branch}`" if f.fix_branch else "-"
        lines.append(
            f"| {idx} | {f.vuln_id} | {display_cat} | {f.severity} "
            f"| {f.title} | {f.status} | {fix_marker} |"
        )

    # --- Category summary table ---
    lines.append("")
    lines.append("### Findings by Category")
    lines.append("")
    lines.append("| Category | Critical | High | Medium | Low | Total |")
    lines.append("|----------|----------|------|--------|-----|-------|")

    for cat_key in _CATEGORY_ORDER:
        cat_findings = [f for f in all_findings if f.category == cat_key]
        if not cat_findings:
            continue
        display = _CATEGORY_DISPLAY_NAMES.get(cat_key, cat_key.title())
        counts = {sev: 0 for sev in ("critical", "high", "medium", "low")}
        for f in cat_findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        total = sum(counts.values())
        lines.append(
            f"| {display} | {counts['critical']} | {counts['high']} "
            f"| {counts['medium']} | {counts['low']} | {total} |"
        )

    # Also include chain findings in the summary if present
    chain_findings = [f for f in all_findings if f.category == "chain"]
    if chain_findings:
        display = _CATEGORY_DISPLAY_NAMES.get("chain", "Attack Chains")
        counts = {sev: 0 for sev in ("critical", "high", "medium", "low")}
        for f in chain_findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        total = sum(counts.values())
        lines.append(
            f"| {display} | {counts['critical']} | {counts['high']} "
            f"| {counts['medium']} | {counts['low']} | {total} |"
        )

    return "\n".join(lines)


def _build_category_section(category: str, findings: list[Finding]) -> str:
    """Build a per-category section with summary table, evidence, and remediation."""
    display = _CATEGORY_DISPLAY_NAMES.get(category, category.title())
    lines: list[str] = [f"## {display} Vulnerabilities"]

    # Per-category summary table
    sorted_findings = sorted(findings, key=_severity_sort_key)
    lines.append("")
    lines.append("| ID | Severity | Title | Status |")
    lines.append("|----|----------|-------|--------|")
    for f in sorted_findings:
        lines.append(f"| {f.vuln_id} | {f.severity} | {f.title} | {f.status} |")

    # LLM placeholder for category intro
    lines.append("")
    lines.append(f"<!-- CATEGORY_INTRO:{category} -->")

    # Individual finding evidence (verbatim)
    for f in sorted_findings:
        lines.append("")
        lines.append(f.evidence_markdown)

        # Remediation subsection
        lines.append("")
        lines.append(f"#### Remediation: {f.vuln_id}")
        lines.append("")
        if f.fix_branch:
            lines.append(f"**Fix Branch:** `{f.fix_branch}`")
            if f.fix_description:
                lines.append(f"\n{f.fix_description}")
            if f.fix_files:
                lines.append("\n**Files Changed:**")
                for fname in f.fix_files:
                    lines.append(f"- `{fname}`")
        else:
            lines.append("*No automated fix available. See [Unpatched Vulnerabilities]"
                         f"(#{_anchor('Unpatched Vulnerabilities')}) for details.*")

    return "\n".join(lines)


def _build_chain_section(chain_content: str, chain_findings: list[Finding]) -> str:
    """Build the Attack Chains section with placeholder and evidence."""
    lines: list[str] = ["## Attack Chains"]
    lines.append("")
    lines.append("<!-- CATEGORY_INTRO:chain -->")
    lines.append("")

    lines.append("*Note: Attack chains are remediated by fixing their component "
                 "vulnerabilities. Patching any link in the chain breaks the "
                 "full attack path.*")
    lines.append("")

    if chain_findings:
        # Summary table for parsed chain findings
        lines.append("| ID | Severity | Title | Status |")
        lines.append("|----|----------|-------|--------|")
        for f in sorted(chain_findings, key=_severity_sort_key):
            lines.append(f"| {f.vuln_id} | {f.severity} | {f.title} | {f.status} |")
        lines.append("")

        # Individual chain finding evidence
        for f in sorted(chain_findings, key=_severity_sort_key):
            lines.append(f.evidence_markdown)
            lines.append("")
    else:
        # Fallback: include raw chain content if no parseable findings
        lines.append(chain_content)

    return "\n".join(lines)


def _build_unpatched_section(findings: list[Finding]) -> str:
    """Build the Unpatched Vulnerabilities section listing findings without fix branches.

    Chain findings are excluded — chains are fixed by patching their
    component vulnerabilities, not by a dedicated fix branch.
    """
    unpatched = [f for f in findings if not f.fix_branch and f.category != "chain"]
    lines: list[str] = ["## Unpatched Vulnerabilities"]

    if not unpatched:
        lines.append("")
        lines.append("All identified vulnerabilities have associated fix branches.")
        return "\n".join(lines)

    sorted_unpatched = sorted(unpatched, key=_severity_sort_key)
    lines.append("")
    lines.append("| # | ID | Category | Severity | Title | Status |")
    lines.append("|---|-----|----------|----------|-------|--------|")
    for idx, f in enumerate(sorted_unpatched, 1):
        display_cat = _CATEGORY_DISPLAY_NAMES.get(f.category, f.category.title())
        lines.append(
            f"| {idx} | {f.vuln_id} | {display_cat} | {f.severity} "
            f"| {f.title} | {f.status} |"
        )

    return "\n".join(lines)



# ---------------------------------------------------------------------------
# Main assembler
# ---------------------------------------------------------------------------

async def assemble_structured_report(
    repo_path: str,
    web_url: str,
    description: str | None = None,
) -> str:
    """Build a complete structured markdown report from pipeline deliverables.

    Parses all evidence files into findings, deduplicates, cross-references
    remediation info, and assembles a skeleton with TOC, tables, evidence
    sections, and LLM placeholders.

    Writes the result to ``deliverables/comprehensive_security_assessment_report.md``.

    Returns the assembled report content.
    """
    from src.services.git_manager import get_branch_name, get_commit_hash

    deliverables_dir = Path(repo_path) / "deliverables"

    # 1. Git metadata
    branch = await get_branch_name(repo_path)
    commit = await get_commit_hash(repo_path)

    # 2. Read and parse all evidence files
    all_findings: list[Finding] = []
    chain_raw_content: str = ""

    for df in DELIVERABLE_FILES:
        file_path = deliverables_dir / df.filename

        try:
            if not file_path.is_file():
                if df.required:
                    raise FileNotFoundError(
                        f"Required deliverable file not found: {df.filename}"
                    )
                logger.info("No %s deliverable found", df.name)
                continue

            async with aiofiles.open(file_path, mode="r", encoding="utf-8") as f:
                content = await f.read()

            category = _detect_category_from_filename(df.filename)

            if category == "chain":
                chain_raw_content = content

            parsed = _parse_evidence_file(content, category)
            all_findings.extend(parsed)
            logger.info("Parsed %d findings from %s", len(parsed), df.filename)

        except FileNotFoundError:
            raise
        except OSError as exc:
            if df.required:
                raise
            logger.warning("Could not read %s: %s", df.filename, exc)

    # 3. Supplement with findings_index.json for types without evidence files
    #    (e.g., crypto has analysis-only findings — no exploit agent)
    index_path = deliverables_dir / "findings_index.json"
    if index_path.is_file():
        try:
            async with aiofiles.open(index_path, mode="r", encoding="utf-8") as f:
                index_content = await f.read()
            existing_ids = {f.vuln_id for f in all_findings}
            stubs = _create_stub_findings_from_index(index_content, existing_ids)
            if stubs:
                all_findings.extend(stubs)
                logger.info("Added %d stub findings from findings_index.json", len(stubs))
        except OSError as exc:
            logger.warning("Could not read findings_index.json: %s", exc)

    # 4. Read and parse remediation report
    remediation_map: dict[str, RemediationInfo] = {}
    remediation_path = deliverables_dir / "remediation_report.md"
    if remediation_path.is_file():
        try:
            async with aiofiles.open(remediation_path, mode="r", encoding="utf-8") as f:
                remediation_content = await f.read()
            remediation_map = _parse_remediation_report(remediation_content)
            logger.info("Parsed remediation info for %d vulnerabilities", len(remediation_map))
        except OSError as exc:
            logger.warning("Could not read remediation_report.md: %s", exc)

    # 5. Deduplicate findings by VULN-ID
    all_findings = _deduplicate_findings(all_findings)
    logger.info("Total unique findings after dedup: %d", len(all_findings))

    # 6. Cross-reference remediation info into findings
    for finding in all_findings:
        rinfo = remediation_map.get(finding.vuln_id)
        if rinfo:
            finding.fix_branch = rinfo.branch
            finding.fix_description = rinfo.description
            finding.fix_files = rinfo.files_changed

    # 7. Group findings by category (ordered)
    category_findings: dict[str, list[Finding]] = {}
    for cat_key in _CATEGORY_ORDER:
        cat_list = [f for f in all_findings if f.category == cat_key]
        if cat_list:
            category_findings[cat_key] = cat_list

    chain_findings = [f for f in all_findings if f.category == "chain"]
    has_chains = bool(chain_findings) or bool(chain_raw_content.strip())

    # 8. Assemble sections
    report_parts: list[str] = []

    # Title
    report_parts.append(_build_title_section(web_url, description, branch, commit, repo_path))
    report_parts.append("---")

    # TOC
    report_parts.append(_build_toc(category_findings, has_chains))
    report_parts.append("---")

    # Executive Summary placeholder
    report_parts.append("## Executive Summary")
    report_parts.append("")
    report_parts.append("<!-- EXECUTIVE_SUMMARY -->")
    report_parts.append("---")

    # Findings Overview
    report_parts.append(_build_findings_overview(all_findings))
    report_parts.append("---")

    # Per-category sections
    for cat_key in _CATEGORY_ORDER:
        if cat_key not in category_findings:
            continue
        report_parts.append(_build_category_section(cat_key, category_findings[cat_key]))
        report_parts.append("---")

    # Attack Chains
    if has_chains:
        report_parts.append(_build_chain_section(chain_raw_content, chain_findings))
        report_parts.append("---")

    # Unpatched Vulnerabilities
    report_parts.append(_build_unpatched_section(all_findings))

    final_content = "\n\n".join(report_parts)

    # 9. Convert screenshot references
    final_content = _render_screenshot_references(final_content, deliverables_dir)

    # 10. Write report
    deliverables_dir.mkdir(parents=True, exist_ok=True)
    report_path = deliverables_dir / "comprehensive_security_assessment_report.md"

    async with aiofiles.open(report_path, mode="w", encoding="utf-8") as f:
        await f.write(final_content)

    logger.info("Structured report assembled at %s (%d findings)", report_path, len(all_findings))

    # 11. Return content
    return final_content


async def assemble_final_report(
    repo_path: str,
    web_url: str = "",
    description: str | None = None,
) -> str:
    """Legacy entry point — delegates to assemble_structured_report."""
    return await assemble_structured_report(repo_path, web_url, description)


def _render_screenshot_references(content: str, deliverables_dir: Path) -> str:
    """Convert backtick screenshot references to rendered markdown images inline.

    Exploit agents write references in three formats:
        `deliverables/screenshots/auth-exploit_AUTH-VULN-01_before.png`  (full path)
        `screenshots/xss-exploit_vuln01_before.png`                      (relative path)
        `authz-exploit_16_before.png`                                    (bare filename)

    All are converted to rendered images within their vulnerability section:
        ![auth exploit AUTH VULN 01 before](screenshots/auth-exploit_AUTH-VULN-01_before.png)

    Only converts references to files that actually exist on disk.
    """
    screenshots_dir = deliverables_dir / "screenshots"
    if not screenshots_dir.is_dir():
        return content

    existing_files = {
        p.name for p in screenshots_dir.iterdir()
        if p.is_file() and p.suffix.lower() in (".png", ".jpg", ".jpeg")
    }

    def _make_image(filename: str) -> str:
        label = Path(filename).stem.replace("_", " ").replace("-", " ")
        return f"![{label}](screenshots/{filename})"

    def _replace_with_path(match: re.Match[str]) -> str:
        filename = match.group(1)
        if filename not in existing_files:
            return match.group(0)
        return _make_image(filename)

    def _replace_bare(match: re.Match[str]) -> str:
        filename = match.group(1)
        if filename not in existing_files:
            return match.group(0)
        return _make_image(filename)

    # Pattern 1: `deliverables/screenshots/filename.png` (full path from repo root)
    # Exploit agents commonly write this format in evidence files.
    content = re.sub(
        r"`deliverables/screenshots/([^`]+\.(?:png|jpg|jpeg))`",
        _replace_with_path,
        content,
    )

    # Pattern 2: `screenshots/filename.png` (relative to deliverables/)
    content = re.sub(
        r"`screenshots/([^`]+\.(?:png|jpg|jpeg))`",
        _replace_with_path,
        content,
    )

    # Pattern 3: `filename.png` (bare filename, no path prefix)
    # Only match filenames that look like screenshot names (contain a hyphen)
    # to avoid false positives on other .png references.
    content = re.sub(
        r"`(\w[\w-]*\.(?:png|jpg|jpeg))`",
        _replace_bare,
        content,
    )

    return content


async def inject_model_into_report(repo_path: str, output_path: str) -> None:
    """Inject model information into the final security report.

    Reads ``session.json`` from *output_path* to extract unique model names
    from all agents, then injects a ``**Models:** ...`` line after the
    Assessment Date metadata in the structured report at *repo_path*.

    Parameters
    ----------
    repo_path:
        Path to the repository containing ``deliverables/``.
    output_path:
        Path to the workspace directory containing ``session.json``.
    """
    session_json_path = Path(output_path) / "session.json"

    if not session_json_path.is_file():
        logger.warning("session.json not found at %s, skipping model injection", session_json_path)
        return

    # 1. Read session.json and extract unique models
    try:
        async with aiofiles.open(session_json_path, mode="r", encoding="utf-8") as f:
            content = await f.read()
        session_data: dict[str, Any] = json.loads(content)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read session.json: %s", exc)
        return

    models: set[str] = set()
    agents_metrics = session_data.get("metrics", {}).get("agents", {})
    for agent_data in agents_metrics.values():
        if isinstance(agent_data, dict) and agent_data.get("model"):
            models.add(agent_data["model"])

    if not models:
        logger.warning("No model information found in session.json")
        return

    model_str = ", ".join(sorted(models))
    logger.info("Injecting model info into report: %s", model_str)

    # 2. Read the final report
    report_path = Path(repo_path) / "deliverables" / "comprehensive_security_assessment_report.md"

    if not report_path.is_file():
        logger.warning("Final report not found at %s, skipping model injection", report_path)
        return

    async with aiofiles.open(report_path, mode="r", encoding="utf-8") as f:
        report_content = await f.read()

    # 3. Inject model line after "Assessment Date" in structured report.
    # New format: "**Assessment Date:** ..." (bold, no bullet prefix)
    assessment_date_pattern = re.compile(
        r"^(\*\*Assessment Date:\*\* .+)$", re.MULTILINE
    )
    match = assessment_date_pattern.search(report_content)

    if match:
        model_line = f"**Models:** {model_str}"
        report_content = assessment_date_pattern.sub(
            rf"\1\n{model_line}", report_content
        )
        logger.info("Model info injected after Assessment Date line")
    else:
        # Fallback: inject after the title
        title_pattern = re.compile(
            r"^(# Comprehensive Security Assessment Report)$", re.MULTILINE
        )
        if title_pattern.search(report_content):
            report_content = title_pattern.sub(
                rf"\1\n\n**Models:** {model_str}", report_content
            )
            logger.info("Model info added after report title")
        else:
            logger.warning("Could not find injection point for model info")
            return

    # 4. Write modified report
    async with aiofiles.open(report_path, mode="w", encoding="utf-8") as f:
        await f.write(report_content)
