"""Deliverable type definitions and filename mappings.

Extends Shannon's 5-type system with GraphQL, WebSocket, Crypto, and
Remediation deliverables (26 total types).
"""

from __future__ import annotations

from typing import Literal


# ---------------------------------------------------------------------------
# Deliverable type — every artifact the pipeline can produce
# ---------------------------------------------------------------------------

DeliverableType = Literal[
    # Pre-recon
    "CODE_ANALYSIS",
    # Recon
    "RECON",
    # Vulnerability analysis (8 types x analysis + queue)
    "INJECTION_ANALYSIS",
    "INJECTION_QUEUE",
    "XSS_ANALYSIS",
    "XSS_QUEUE",
    "AUTH_ANALYSIS",
    "AUTH_QUEUE",
    "SSRF_ANALYSIS",
    "SSRF_QUEUE",
    "AUTHZ_ANALYSIS",
    "AUTHZ_QUEUE",
    "GRAPHQL_ANALYSIS",
    "GRAPHQL_QUEUE",
    "WEBSOCKET_ANALYSIS",
    "WEBSOCKET_QUEUE",
    "CRYPTO_ANALYSIS",
    "CRYPTO_QUEUE",
    # Exploitation evidence (7 types — crypto has no exploit agent)
    "INJECTION_EVIDENCE",
    "XSS_EVIDENCE",
    "AUTH_EVIDENCE",
    "SSRF_EVIDENCE",
    "AUTHZ_EVIDENCE",
    "GRAPHQL_EVIDENCE",
    "WEBSOCKET_EVIDENCE",
    # Exploitation verdicts (structured, consumed by findings_aggregator — one
    # per finding: exploited | blocked | unreachable | false_positive)
    "INJECTION_VERDICTS",
    "XSS_VERDICTS",
    "AUTH_VERDICTS",
    "SSRF_VERDICTS",
    "AUTHZ_VERDICTS",
    "GRAPHQL_VERDICTS",
    "WEBSOCKET_VERDICTS",
    # Chain exploitation
    "CHAIN_EVIDENCE",
    # Chain findings (structured, consumed by findings_aggregator)
    "CHAIN_FINDINGS",
    # SCA (supply chain analysis)
    "SCA_FINDINGS",
    # Integrity (malicious code detection)
    "INTEGRITY_ANALYSIS",
    # Critique (post-aggregation, pre-remediation)
    "FINDINGS_CRITIQUE",
    # Reporting and remediation
    "REPORT",
    "REMEDIATION_REPORT",
    # Structured remediation manifest (consumed by the report author)
    "REMEDIATION_MANIFEST",
]


# ---------------------------------------------------------------------------
# Filename mappings — hard-coded from agent prompts
# ---------------------------------------------------------------------------

DELIVERABLE_FILENAMES: dict[DeliverableType, str] = {
    # Pre-recon
    "CODE_ANALYSIS": "code_analysis_deliverable.md",
    # Recon
    "RECON": "recon_deliverable.md",
    # Vulnerability analysis
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
    # Exploitation evidence
    "INJECTION_EVIDENCE": "injection_exploitation_evidence.md",
    "XSS_EVIDENCE": "xss_exploitation_evidence.md",
    "AUTH_EVIDENCE": "auth_exploitation_evidence.md",
    "SSRF_EVIDENCE": "ssrf_exploitation_evidence.md",
    "AUTHZ_EVIDENCE": "authz_exploitation_evidence.md",
    "GRAPHQL_EVIDENCE": "graphql_exploitation_evidence.md",
    "WEBSOCKET_EVIDENCE": "websocket_exploitation_evidence.md",
    # Exploitation verdicts (structured)
    "INJECTION_VERDICTS": "injection_exploitation_verdicts.json",
    "XSS_VERDICTS": "xss_exploitation_verdicts.json",
    "AUTH_VERDICTS": "auth_exploitation_verdicts.json",
    "SSRF_VERDICTS": "ssrf_exploitation_verdicts.json",
    "AUTHZ_VERDICTS": "authz_exploitation_verdicts.json",
    "GRAPHQL_VERDICTS": "graphql_exploitation_verdicts.json",
    "WEBSOCKET_VERDICTS": "websocket_exploitation_verdicts.json",
    # Chain exploitation
    "CHAIN_EVIDENCE": "chain_exploitation_evidence.md",
    # Chain findings (structured)
    "CHAIN_FINDINGS": "chain_findings.json",
    # SCA
    "SCA_FINDINGS": "sca_findings.json",
    # Integrity
    "INTEGRITY_ANALYSIS": "integrity_analysis.json",
    # Critique
    "FINDINGS_CRITIQUE": "findings_critique.json",
    # Reporting and remediation
    "REPORT": "comprehensive_security_assessment_report.md",
    "REMEDIATION_REPORT": "remediation_report.md",
    "REMEDIATION_MANIFEST": "remediation_manifest.json",
}


# ---------------------------------------------------------------------------
# Queue types — the subset that requires JSON validation
# ---------------------------------------------------------------------------

QUEUE_TYPES: list[DeliverableType] = [
    "INJECTION_QUEUE",
    "XSS_QUEUE",
    "AUTH_QUEUE",
    "SSRF_QUEUE",
    "AUTHZ_QUEUE",
    "GRAPHQL_QUEUE",
    "WEBSOCKET_QUEUE",
    "CRYPTO_QUEUE",
]


def is_queue_type(dtype: str) -> bool:
    """Return True if *dtype* is a queue deliverable that needs JSON validation."""
    return dtype in QUEUE_TYPES
