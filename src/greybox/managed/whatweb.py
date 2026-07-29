"""WhatWeb technology fingerprinting scanner."""
from __future__ import annotations

import json
import logging

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


class WhatwebScanner(BaseScanner):
    """Wrapper for WhatWeb technology fingerprinting."""

    def build_command(self) -> list[str]:
        aggression = str(self.options.get("aggression", "1"))
        cmd = [
            "whatweb",
            "--log-json=-",
            "--quiet",
            f"--aggression={aggression}",
        ]
        if self.cookie_header:
            cmd.append(f"--cookie={self.cookie_header}")
        cmd.append(self.target_url)
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        technologies: list[dict] = []

        # WhatWeb JSON output is one JSON object per line
        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON whatweb line: %s", line[:80])
                continue

            # WhatWeb JSON structure: {"target": ..., "plugins": {...}}
            plugins = entry.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                # Skip generic plugins
                if plugin_name in ("HTTPServer", "IP", "Country"):
                    continue

                version = ""
                if isinstance(plugin_data, dict):
                    version_list = plugin_data.get("version", [])
                    if version_list:
                        version = str(version_list[0]) if isinstance(version_list, list) else str(version_list)

                tech = {
                    "tool": "whatweb",
                    "name": plugin_name,
                    "version": version,
                    "url": entry.get("target", self.target_url),
                }
                technologies.append(tech)

        return ScanResult(
            scan_type="tech_fingerprint",
            technologies=technologies,
            items_found=len(technologies),
        )
