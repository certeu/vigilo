"""SSL/TLS analysis scanner wrapping testssl.sh."""
from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# testssl severity mapping
TESTSSL_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
    "INFO": "info",
    "OK": "info",
}


class SslScanner(BaseScanner):
    """Wrapper for testssl.sh SSL/TLS analysis."""

    def build_command(self) -> list[str]:
        # Extract host:port from URL
        parsed = urlparse(self.target_url)
        host = parsed.hostname or self.target_url
        port = parsed.port or 443
        target = f"{host}:{port}"

        cmd = [
            "testssl",
            "--jsonfile", "/dev/stdout",  # JSON to stdout
            "--quiet",
            "--color", "0",
        ]
        if self.options.get("fast"):
            cmd.append("--fast")
        cmd.append(target)
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        findings: list[dict] = []
        leads: list[dict] = []

        # testssl.sh outputs a JSON array when using --jsonfile -
        try:
            entries = json.loads(raw_output)
            if not isinstance(entries, list):
                entries = [entries]
        except json.JSONDecodeError:
            # Try line-by-line JSON
            entries = []
            for line in raw_output.strip().splitlines():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for entry in entries:
            severity_raw = entry.get("severity", "INFO")
            severity = TESTSSL_SEVERITY_MAP.get(severity_raw, "info")
            test_id = entry.get("id", "unknown")
            finding_text = entry.get("finding", "")

            if severity == "info":
                continue

            item = {
                "tool": "ssl_analysis",
                "vuln_type": "ssl",
                "test_id": test_id,
                "severity": severity,
                "description": finding_text,
                "url": self.target_url,
                "raw_severity": severity_raw,
            }

            if severity in ("critical", "high", "medium"):
                findings.append(item)
            else:
                leads.append(item)

        return ScanResult(
            scan_type="ssl_analysis",
            findings=findings,
            leads=leads,
            items_found=len(findings) + len(leads),
        )
