"""Feroxbuster content discovery wrapper."""
from __future__ import annotations

import json
import logging

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

# Status codes that indicate interesting content
INTERESTING_STATUSES = {200, 201, 301, 302, 307, 308, 401, 403, 405, 500}


class FeroxbusterScanner(BaseScanner):
    """Wrapper for feroxbuster directory/content discovery."""

    def build_command(self) -> list[str]:
        cmd = [
            "feroxbuster",
            "-u", self.target_url,
            "--json",
            "--quiet",
            "--no-state",
            "--output", "/dev/stdout",
        ]
        if wordlist := self.options.get("wordlist"):
            cmd.extend(["-w", str(wordlist)])
        if threads := self.options.get("threads"):
            cmd.extend(["-t", str(threads)])
        if depth := self.options.get("depth"):
            cmd.extend(["-d", str(depth)])
        if extensions := self.options.get("extensions"):
            cmd.extend(["-x", str(extensions)])
        if self.cookie_header:
            cmd.extend(["-H", f"Cookie: {self.cookie_header}"])
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        endpoints: list[dict] = []
        leads: list[dict] = []

        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON feroxbuster line: %s", line[:80])
                continue

            # feroxbuster JSON has type field: "response" entries are what we want
            entry_type = entry.get("type", "response")
            if entry_type != "response":
                continue

            status = entry.get("status", 0)
            url = entry.get("url", "")
            content_length = entry.get("content_length", entry.get("content-length", 0))
            path = entry.get("path", url)

            if status not in INTERESTING_STATUSES:
                continue

            endpoint = {
                "url": url,
                "path": path,
                "status": status,
                "content_length": content_length,
                "method": entry.get("method", "GET"),
            }
            endpoints.append(endpoint)

            # 401/403 are leads for auth bypass testing
            if status in (401, 403):
                leads.append({
                    "tool": "feroxbuster",
                    "signal_type": "access_control_anomaly",
                    "url": url,
                    "status": status,
                    "hypothesis": f"Endpoint {path} returns {status} — potential auth bypass target",
                })
            # 500 errors are leads for injection testing
            elif status == 500:
                leads.append({
                    "tool": "feroxbuster",
                    "signal_type": "error_response",
                    "url": url,
                    "status": status,
                    "hypothesis": f"Endpoint {path} returns 500 — potential injection point",
                })

        return ScanResult(
            scan_type="feroxbuster",
            new_endpoints=endpoints,
            leads=leads,
            items_found=len(endpoints),
        )
