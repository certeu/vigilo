"""Validator context builder for finding re-validation.

Builds minimal context for the validator agent, deliberately excluding
the original evidence to prevent confirmation bias.
"""
from __future__ import annotations


def build_validator_context(finding: dict) -> str:
    """Build minimal context for re-validating a finding.

    Includes: finding ID, vuln type, severity, target URL, CWE, PoC payload, title.
    Deliberately excludes: evidence_file, original reasoning, screenshots.
    This forces the validator to independently reproduce the finding.
    """
    finding_id = finding.get("id", "unknown")
    vuln_type = finding.get("vuln_type", "unknown")
    severity = finding.get("severity", "unknown")
    target = finding.get("url", finding.get("target", "unknown"))
    cwe = finding.get("cwe", "")
    poc_payload = finding.get("poc_payload", finding.get("payload", ""))
    title = finding.get("title", finding.get("name", ""))

    lines = [
        "## Finding to Validate",
        "",
        f"- **ID**: {finding_id}",
        f"- **Title**: {title}" if title else None,
        f"- **Type**: {vuln_type}",
        f"- **Severity**: {severity}",
        f"- **Target**: {target}",
        f"- **CWE**: {cwe}" if cwe else None,
        f"- **PoC Payload**: `{poc_payload}`" if poc_payload else None,
        "",
        "Your task: independently reproduce this finding. "
        "Do NOT rely on prior evidence — test from scratch.",
    ]

    return "\n".join(line for line in lines if line is not None)
