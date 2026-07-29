"""Security header analysis scanner."""
from __future__ import annotations

import logging

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# Security headers that should be present on all web applications
REQUIRED_HEADERS = {
    "strict-transport-security": {
        "description": "HSTS not set — browser may allow HTTP downgrade",
        "severity": "medium",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "description": "CSP not set — no XSS mitigation via policy",
        "severity": "medium",
        "cwe": "CWE-79",
    },
    "x-content-type-options": {
        "description": "X-Content-Type-Options not set — MIME sniffing possible",
        "severity": "low",
        "cwe": "CWE-16",
    },
    "x-frame-options": {
        "description": "X-Frame-Options not set — clickjacking possible",
        "severity": "medium",
        "cwe": "CWE-1021",
    },
    "referrer-policy": {
        "description": "Referrer-Policy not set — referrer leakage possible",
        "severity": "low",
        "cwe": "CWE-200",
    },
    "permissions-policy": {
        "description": "Permissions-Policy not set — browser features unrestricted",
        "severity": "low",
        "cwe": "CWE-16",
    },
    "x-xss-protection": {
        "description": "X-XSS-Protection not set",
        "severity": "info",
        "cwe": "CWE-79",
    },
}


class HeadersScanner(BaseScanner):
    """Analyze HTTP response headers for missing security headers."""

    def build_command(self) -> list[str]:
        cmd = [
            "curl", "-sS", "-D", "-",
            "-o", "/dev/null",
            "--max-time", "10",
        ]
        if self.cookie_header:
            cmd.extend(["-H", f"Cookie: {self.cookie_header}"])
        cmd.append(self.target_url)
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        headers = _parse_response_headers(raw_output)
        return analyze_headers(headers, self.target_url)


def _parse_response_headers(raw: str) -> dict[str, str]:
    """Parse curl -D - output into a lowercase header dict."""
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def analyze_headers(headers: dict[str, str], target_url: str = "") -> ScanResult:
    """Check response headers against REQUIRED_HEADERS."""
    findings: list[dict] = []
    present_lower = {k.lower() for k in headers}

    for header_name, info in REQUIRED_HEADERS.items():
        if header_name not in present_lower:
            findings.append({
                "tool": "header_analysis",
                "vuln_type": "headers",
                "header": header_name,
                "severity": info["severity"],
                "cwe": info["cwe"],
                "description": info["description"],
                "url": target_url,
            })

    return ScanResult(
        scan_type="header_analysis",
        findings=findings,
        items_found=len(findings),
    )
