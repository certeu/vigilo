"""Rule-based chain pre-filter and known pattern matcher.

Computes candidate pairs from confirmed findings where
A.grants ∩ B.requires != empty. Matches against 7 known chain patterns.
"""
from __future__ import annotations

from typing import Any


def find_chain_candidates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find finding pairs where one's grants satisfy another's requires."""
    candidates = []
    for a in findings:
        a_id = a.get("id", "")
        grants_a = set(a.get("grants", []))
        if not grants_a or not a_id:
            continue
        for b in findings:
            b_id = b.get("id", "")
            if not b_id or a_id == b_id:
                continue
            requires_b = set(b.get("requires", []))
            overlap = grants_a & requires_b
            if overlap:
                candidates.append({
                    "finding_a": a_id,
                    "finding_b": b_id,
                    "capability_overlap": sorted(overlap),
                    "expected_impact": f"{a.get('vuln_type', '?')} + {b.get('vuln_type', '?')}",
                })
    return candidates


KNOWN_CHAIN_PATTERNS = [
    {
        "name": "SSRF + Cloud Metadata",
        "a_vuln_types": {"ssrf"},
        "capability_trigger": {"internal_network", "cloud_metadata"},
        "combined_impact": "Data breach via cloud credential extraction",
        "steps": [
            "SSRF reads internal metadata endpoint (169.254.169.254)",
            "Extract IAM credentials from metadata response",
            "Use IAM credentials to access cloud storage/services",
        ],
    },
    {
        "name": "XSS + CSRF Bypass",
        "a_vuln_types": {"reflection"},
        "capability_trigger": {"csrf_bypass", "session_hijack"},
        "combined_impact": "Account takeover via CSRF chain",
        "steps": [
            "Reflection/XSS steals CSRF token or session cookie",
            "CSRF changes victim email/password",
            "Password reset to attacker-controlled email",
        ],
    },
    {
        "name": "SQLi + File Read",
        "a_vuln_types": {"injection"},
        "capability_trigger": {"file_read", "db_read"},
        "combined_impact": "Credential extraction via config file read",
        "steps": [
            "SQLi reads config files (LOAD_FILE or similar)",
            "Extract database credentials or API keys",
            "Use extracted secrets for lateral access",
        ],
    },
    {
        "name": "Auth Bypass + SSRF",
        "a_vuln_types": {"authorization"},
        "capability_trigger": {"admin_access"},
        "combined_impact": "Internal network pivot via admin SSRF",
        "steps": [
            "Bypass authentication to reach admin panel",
            "Use admin-only SSRF functionality to hit internal services",
            "Enumerate and exploit internal network services",
        ],
    },
    {
        "name": "Info Disclosure + Injection",
        "a_vuln_types": {"authorization", "graphql"},
        "capability_trigger": {"info_disclosure"},
        "combined_impact": "Precision exploitation using leaked internals",
        "steps": [
            "Information leak reveals internal schema/structure",
            "Use leaked info to craft targeted injection payloads",
            "Exploit with higher success rate due to schema knowledge",
        ],
    },
    {
        "name": "GraphQL Introspection + AuthZ",
        "a_vuln_types": {"graphql"},
        "capability_trigger": {"info_disclosure"},
        "combined_impact": "Unauthorized mutations via hidden GraphQL operations",
        "steps": [
            "GraphQL introspection reveals hidden mutations",
            "AuthZ flaw allows calling admin-only mutations as regular user",
            "Execute unauthorized state changes",
        ],
    },
    {
        "name": "Crypto Weakness + Auth",
        "a_vuln_types": {"reflection"},
        "capability_trigger": {"session_hijack", "user_impersonation"},
        "combined_impact": "Full account takeover via token forgery",
        "steps": [
            "Weak JWT signing key or algorithm confusion (reflection domain)",
            "Forge token with arbitrary user claims",
            "Impersonate any user including admins",
        ],
    },
]


class ChainDetector:
    """Rule-based chain candidate detection."""

    def compute_candidates(self, findings: list[dict]) -> list[dict]:
        """Find finding pairs where A.grants intersect B.requires."""
        candidates = []
        for a in findings:
            a_id = a.get("id", "")
            if not a_id:
                continue
            for b in findings:
                b_id = b.get("id", "")
                if not b_id or a_id == b_id:
                    continue
                overlap = set(a.get("grants", [])) & set(b.get("requires", []))
                overlap -= {"authenticated"}  # Filter trivially common
                if overlap:
                    candidates.append({
                        "finding_a": a_id,
                        "finding_b": b_id,
                        "a_vuln_type": a.get("vuln_type", ""),
                        "b_vuln_type": b.get("vuln_type", ""),
                        "a_grants": a.get("grants", []),
                        "b_requires": b.get("requires", []),
                        "capability_overlap": list(overlap),
                    })
        return candidates

    def match_known_patterns(self, candidates: list[dict]) -> list[dict]:
        """Match candidates against KNOWN_CHAIN_PATTERNS."""
        matched = []
        for candidate in candidates:
            for pattern in KNOWN_CHAIN_PATTERNS:
                a_type = candidate.get("a_vuln_type", "")
                if a_type not in pattern["a_vuln_types"]:
                    continue
                overlap = set(candidate.get("capability_overlap", []))
                if not overlap & pattern["capability_trigger"]:
                    continue
                matched.append({
                    "pattern_name": pattern["name"],
                    "finding_a": candidate["finding_a"],
                    "finding_b": candidate["finding_b"],
                    "combined_impact": pattern["combined_impact"],
                    "steps": pattern["steps"],
                    "capability_overlap": candidate["capability_overlap"],
                })
        return matched

    def build_chain_context(self, matched_patterns: list[dict]) -> str:
        """Build text context for the chain exploitation agent prompt."""
        if not matched_patterns:
            return "No chain candidates identified from current findings."
        lines = ["## Chain Exploitation Candidates", ""]
        for i, m in enumerate(matched_patterns, 1):
            lines.append(f"### Candidate {i}: {m['pattern_name']}")
            lines.append(f"- **Finding A**: {m['finding_a']}")
            lines.append(f"- **Finding B**: {m['finding_b']}")
            lines.append(f"- **Shared Capabilities**: {', '.join(m['capability_overlap'])}")
            lines.append(f"- **Expected Impact**: {m['combined_impact']}")
            lines.append("- **Chain Steps**:")
            for step in m["steps"]:
                lines.append(f"  1. {step}")
            lines.append("")
        return "\n".join(lines)
