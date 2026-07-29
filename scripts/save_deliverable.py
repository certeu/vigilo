#!/usr/bin/env python3
"""
save-deliverable — Agent-callable CLI for saving structured deliverables.

Usage:
    save-deliverable --type CODE_ANALYSIS --file-path /tmp/report.md
    save-deliverable --type INJECTION_QUEUE --content '{"vulnerabilities": [...]}'

Output: JSON to stdout
    {"status": "success", "filepath": "deliverables/code_analysis_deliverable.md", "validated": true}
"""

import argparse
import json
import os
import shutil
import sys

# Inline the deliverable mappings to avoid import issues when script is on PATH
DELIVERABLE_FILENAMES = {
    "CODE_ANALYSIS": "code_analysis_deliverable.md",
    "RECON": "recon_deliverable.md",
    "INJECTION_ANALYSIS": "injection_analysis_deliverable.md",
    "INJECTION_QUEUE": "injection_exploitation_queue.json",
    "XSS_ANALYSIS": "xss_analysis_deliverable.md",
    "XSS_QUEUE": "xss_exploitation_queue.json",
    "AUTH_ANALYSIS": "auth_analysis_deliverable.md",
    "AUTH_QUEUE": "auth_exploitation_queue.json",
    "SSRF_ANALYSIS": "ssrf_analysis_deliverable.md",
    "SSRF_QUEUE": "ssrf_exploitation_queue.json",
    "AUTHZ_ANALYSIS": "authz_analysis_deliverable.md",
    "AUTHZ_QUEUE": "authz_exploitation_queue.json",
    "GRAPHQL_ANALYSIS": "graphql_analysis_deliverable.md",
    "GRAPHQL_QUEUE": "graphql_exploitation_queue.json",
    "WEBSOCKET_ANALYSIS": "websocket_analysis_deliverable.md",
    "WEBSOCKET_QUEUE": "websocket_exploitation_queue.json",
    "CRYPTO_ANALYSIS": "crypto_analysis_deliverable.md",
    "CRYPTO_QUEUE": "crypto_exploitation_queue.json",
    "INJECTION_EVIDENCE": "injection_exploitation_evidence.md",
    "XSS_EVIDENCE": "xss_exploitation_evidence.md",
    "AUTH_EVIDENCE": "auth_exploitation_evidence.md",
    "SSRF_EVIDENCE": "ssrf_exploitation_evidence.md",
    "AUTHZ_EVIDENCE": "authz_exploitation_evidence.md",
    "GRAPHQL_EVIDENCE": "graphql_exploitation_evidence.md",
    "WEBSOCKET_EVIDENCE": "websocket_exploitation_evidence.md",
    "INJECTION_VERDICTS": "injection_exploitation_verdicts.json",
    "XSS_VERDICTS": "xss_exploitation_verdicts.json",
    "AUTH_VERDICTS": "auth_exploitation_verdicts.json",
    "SSRF_VERDICTS": "ssrf_exploitation_verdicts.json",
    "AUTHZ_VERDICTS": "authz_exploitation_verdicts.json",
    "GRAPHQL_VERDICTS": "graphql_exploitation_verdicts.json",
    "WEBSOCKET_VERDICTS": "websocket_exploitation_verdicts.json",
    "CHAIN_EVIDENCE": "chain_exploitation_evidence.md",
    "CHAIN_FINDINGS": "chain_findings.json",
    "SCA_FINDINGS": "sca_findings.json",
    "INTEGRITY_ANALYSIS": "integrity_analysis.json",
    "FINDINGS_CRITIQUE": "findings_critique.json",
    "REPORT": "comprehensive_security_assessment_report.md",
    "REMEDIATION_REPORT": "remediation_report.md",
    "REMEDIATION_MANIFEST": "remediation_manifest.json",
}

QUEUE_TYPES = {
    "INJECTION_QUEUE",
    "XSS_QUEUE",
    "AUTH_QUEUE",
    "SSRF_QUEUE",
    "AUTHZ_QUEUE",
    "GRAPHQL_QUEUE",
    "WEBSOCKET_QUEUE",
    "CRYPTO_QUEUE",
}

# Structured exploit verdicts: {"verdicts": [{"id", "verdict", ...}]}
VERDICT_TYPES = {
    "INJECTION_VERDICTS",
    "XSS_VERDICTS",
    "AUTH_VERDICTS",
    "SSRF_VERDICTS",
    "AUTHZ_VERDICTS",
    "GRAPHQL_VERDICTS",
    "WEBSOCKET_VERDICTS",
}


def _error(message: str, *, retryable: bool = False) -> None:
    """Print JSON error and exit."""
    print(json.dumps({"status": "error", "message": message, "retryable": retryable}))
    sys.exit(1)


def _validate_queue_json(content: str) -> None:
    """Validate that queue content is well-formed JSON with a vulnerabilities array."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON: {exc}", retryable=True)

    if not isinstance(data, dict):
        _error(
            f"Invalid queue structure: Expected an object. Got: {type(data).__name__}",
            retryable=True,
        )

    if "vulnerabilities" not in data:
        _error(
            "Invalid queue structure: Missing 'vulnerabilities' property. "
            'Expected: {"vulnerabilities": [...]}',
            retryable=True,
        )

    if not isinstance(data["vulnerabilities"], list):
        _error(
            "Invalid queue structure: 'vulnerabilities' must be an array. "
            'Expected: {"vulnerabilities": [...]}',
            retryable=True,
        )


def _validate_list_json(content: str, key: str) -> None:
    """Validate JSON with a required top-level array property named *key*."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON: {exc}", retryable=True)

    if not isinstance(data, dict) or key not in data or not isinstance(data[key], list):
        _error(
            f"Invalid structure: expected an object with a '{key}' array. "
            f'Expected: {{"{key}": [...]}}',
            retryable=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Save agent deliverable")
    parser.add_argument("--type", required=True, help="Deliverable type")
    parser.add_argument("--file-path", help="Path to source file")
    parser.add_argument("--content", help="Direct content string")
    args = parser.parse_args()

    dtype = args.type.upper()

    # 1. Validate --type
    if dtype not in DELIVERABLE_FILENAMES:
        _error(f"Unknown deliverable type: {dtype}", retryable=False)

    filename = DELIVERABLE_FILENAMES[dtype]

    # 2. Resolve content from --content or --file-path
    content: str
    if args.content:
        content = args.content
    elif args.file_path:
        # Path traversal protection: must resolve inside cwd
        cwd = os.getcwd()
        resolved = os.path.realpath(os.path.join(cwd, args.file_path))
        if not resolved.startswith(cwd + os.sep) and resolved != cwd:
            _error(f"Path traversal detected: {args.file_path}", retryable=False)
        try:
            with open(resolved, "r") as f:
                content = f.read()
        except OSError as exc:
            _error(f"Failed to read file: {exc}", retryable=True)
    else:
        _error("Either --content or --file-path is required", retryable=False)

    # 3. Validate content is non-empty
    if not content.strip():
        _error("Content is empty", retryable=True)

    # 4. Validate structured JSON types
    validated = False
    if dtype in QUEUE_TYPES:
        _validate_queue_json(content)
        validated = True
    elif dtype in VERDICT_TYPES:
        _validate_list_json(content, "verdicts")
        validated = True
    elif dtype == "CHAIN_FINDINGS":
        _validate_list_json(content, "chains")
        validated = True
    elif dtype == "REMEDIATION_MANIFEST":
        _validate_list_json(content, "branches")
        validated = True

    # 5. Save the file
    try:
        deliverables_dir = os.path.join(os.getcwd(), "deliverables")
        os.makedirs(deliverables_dir, exist_ok=True)
        # Also ensure screenshots directory exists for exploit agents
        os.makedirs(os.path.join(deliverables_dir, "screenshots"), exist_ok=True)

        dest = os.path.join(deliverables_dir, filename)
        with open(dest, "w") as f:
            f.write(content)

        print(json.dumps({"status": "success", "filepath": dest, "validated": validated}))
    except OSError as exc:
        _error(f"Failed to save: {exc}", retryable=True)


if __name__ == "__main__":
    main()
