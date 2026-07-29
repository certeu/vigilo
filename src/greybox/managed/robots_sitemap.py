"""Robots.txt and sitemap.xml discovery scanner."""
from __future__ import annotations

import logging
import re

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


class RobotsSitemapScanner(BaseScanner):
    """Fetch and parse robots.txt and sitemap.xml for endpoint discovery."""

    def build_command(self) -> list[str]:
        # Fetch robots.txt first; sitemap is parsed from it or fetched separately
        base = self.target_url.rstrip("/")
        cmd = [
            "curl", "-sS",
            "--max-time", "10",
            "-o", "-",
        ]
        if self.cookie_header:
            cmd.extend(["-H", f"Cookie: {self.cookie_header}"])
        cmd.append(f"{base}/robots.txt")
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        endpoints: list[dict] = []
        leads: list[dict] = []
        base = self.target_url.rstrip("/")

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Disallow / Allow directives contain paths
            match = re.match(r"^(Disallow|Allow):\s*(.+)", line, re.IGNORECASE)
            if match:
                directive = match.group(1).lower()
                path = match.group(2).strip()
                if path and path != "/":
                    endpoint = {
                        "url": f"{base}{path}",
                        "path": path,
                        "source": "robots.txt",
                        "directive": directive,
                    }
                    endpoints.append(endpoint)

                    # Disallowed paths are interesting leads
                    if directive == "disallow":
                        leads.append({
                            "tool": "robots_sitemap",
                            "signal_type": "hidden_path",
                            "url": f"{base}{path}",
                            "path": path,
                            "hypothesis": f"Disallowed path {path} may contain sensitive content",
                        })

            # Sitemap directive
            sitemap_match = re.match(r"^Sitemap:\s*(.+)", line, re.IGNORECASE)
            if sitemap_match:
                sitemap_url = sitemap_match.group(1).strip()
                endpoints.append({
                    "url": sitemap_url,
                    "path": sitemap_url,
                    "source": "robots.txt",
                    "directive": "sitemap",
                })

        return ScanResult(
            scan_type="robots_sitemap",
            new_endpoints=endpoints,
            leads=leads,
            items_found=len(endpoints),
        )
