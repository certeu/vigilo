"""CORS misconfiguration scanner."""
from __future__ import annotations

import logging

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


class CorsScanner(BaseScanner):
    """Check for CORS misconfigurations via curl probing."""

    def build_command(self) -> list[str]:
        origin = self.options.get("test_origin", "https://evil.example.com")
        cmd = [
            "curl", "-sS", "-D", "-",
            "-o", "/dev/null",
            "--max-time", "10",
            "-H", f"Origin: {origin}",
        ]
        if self.cookie_header:
            cmd.extend(["-H", f"Cookie: {self.cookie_header}"])
        cmd.append(self.target_url)
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        headers = _parse_headers(raw_output)
        origin = str(self.options.get("test_origin", "https://evil.example.com"))
        return analyze_cors(headers, origin, self.target_url)


def _parse_headers(raw: str) -> dict[str, str]:
    """Parse curl header output into lowercase dict."""
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def analyze_cors(
    headers: dict[str, str],
    test_origin: str = "https://evil.example.com",
    target_url: str = "",
) -> ScanResult:
    """Analyze CORS headers for misconfigurations."""
    findings: list[dict] = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if not acao:
        # No CORS headers — not misconfigured, nothing to report
        return ScanResult(scan_type="cors_check", items_found=0)

    # Wildcard origin
    if acao == "*":
        severity = "high" if acac == "true" else "medium"
        findings.append({
            "tool": "cors_check",
            "vuln_type": "cors",
            "severity": severity,
            "cwe": "CWE-942",
            "description": (
                "CORS allows wildcard origin (*)"
                + (" with credentials" if acac == "true" else "")
            ),
            "url": target_url,
            "acao": acao,
            "acac": acac,
        })

    # Reflects arbitrary origin
    elif acao.lower() == test_origin.lower():
        severity = "high" if acac == "true" else "medium"
        findings.append({
            "tool": "cors_check",
            "vuln_type": "cors",
            "severity": severity,
            "cwe": "CWE-942",
            "description": (
                f"CORS reflects arbitrary origin ({test_origin})"
                + (" with credentials" if acac == "true" else "")
            ),
            "url": target_url,
            "acao": acao,
            "acac": acac,
        })

    # Null origin allowed
    elif acao.lower() == "null":
        findings.append({
            "tool": "cors_check",
            "vuln_type": "cors",
            "severity": "medium",
            "cwe": "CWE-942",
            "description": "CORS allows null origin",
            "url": target_url,
            "acao": acao,
            "acac": acac,
        })

    return ScanResult(
        scan_type="cors_check",
        findings=findings,
        items_found=len(findings),
    )
