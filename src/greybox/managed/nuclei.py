"""Nuclei vulnerability scanner wrapper."""
from __future__ import annotations

import json
import logging

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# Nuclei severity to our severity mapping
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class NucleiScanner(BaseScanner):
    """Wrapper for ProjectDiscovery Nuclei scanner."""

    def build_command(self) -> list[str]:
        cmd = [
            "nuclei",
            "-u", self.target_url,
            "-jsonl",
            "-silent",
        ]
        if templates := self.options.get("templates"):
            cmd.extend(["-t", str(templates)])
        if severity := self.options.get("severity"):
            cmd.extend(["-severity", str(severity)])
        if rate_limit := self.options.get("rate_limit"):
            cmd.extend(["-rl", str(rate_limit)])
        if self.cookie_header:
            cmd.extend(["-H", f"Cookie: {self.cookie_header}"])
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        findings: list[dict] = []
        leads: list[dict] = []

        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON nuclei line: %s", line[:80])
                continue

            severity = SEVERITY_MAP.get(
                entry.get("info", {}).get("severity", "info"), "info"
            )
            template_id = entry.get("template-id", entry.get("templateID", "unknown"))
            matched_url = entry.get("matched-at", entry.get("matched_at", self.target_url))
            name = entry.get("info", {}).get("name", template_id)
            tags = entry.get("info", {}).get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            finding = {
                "tool": "nuclei",
                "template_id": template_id,
                "name": name,
                "severity": severity,
                "url": matched_url,
                "tags": tags,
                "description": entry.get("info", {}).get("description", ""),
                "matcher_name": entry.get("matcher-name", ""),
                "raw": entry,
            }

            if severity in ("critical", "high", "medium"):
                findings.append(finding)
            else:
                leads.append(finding)

        return ScanResult(
            scan_type="nuclei",
            findings=findings,
            leads=leads,
            items_found=len(findings) + len(leads),
        )
