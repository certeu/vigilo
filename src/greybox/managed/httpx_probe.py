"""httpx (projectdiscovery) ALPN/HTTP2/HTTP3 fingerprint probe.

Active recon — opt-in via ``GreyBoxConfig.active_recon_enabled``. Issues
a single high-fidelity request per target to capture protocol-level
metadata that the standard discovery crawler does not surface:

  - ALPN-negotiated protocol (h2, h3, http/1.1)
  - TLS version
  - HTTP/2 or HTTP/3 support
  - Server fingerprint via JARM / favicon hash

Cheap (one HEAD/GET per target) and informs the websocket / streaming /
chain specialists about which protocols are reachable.
"""
from __future__ import annotations

import json
import logging

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


class HttpxProbeScanner(BaseScanner):
    """Wrapper for projectdiscovery httpx protocol fingerprinting."""

    def build_command(self) -> list[str]:
        cmd = [
            "httpx",
            "-u", self.target_url,
            "-json",
            "-silent",
            "-tls-grab",
            "-http2",
            "-pipeline",
            "-alpn",
            "-jarm",
            "-tech-detect",
            "-favicon",
            "-no-color",
        ]
        if self.cookie_header:
            cmd.extend(["-H", f"Cookie: {self.cookie_header}"])
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        technologies: list[dict] = []
        leads: list[dict] = []

        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON httpx line: %s", line[:80])
                continue

            url = entry.get("url", self.target_url)
            tls = entry.get("tls", {}) or {}
            tls_version = tls.get("tls_version", "")
            alpn = entry.get("alpn", "") or tls.get("alpn", "")
            http2 = entry.get("http2", False)
            pipeline = entry.get("pipeline", False)
            jarm = entry.get("jarm", "")
            favicon_hash = entry.get("favicon", "")

            for tech_name in entry.get("tech", []) or []:
                technologies.append({
                    "tool": "httpx",
                    "name": tech_name,
                    "version": "",
                    "category": "framework",
                    "source": "httpx_tech_detect",
                })

            transport_summary = (
                f"tls={tls_version or 'unknown'} alpn={alpn or 'none'} "
                f"http2={bool(http2)} pipelining={bool(pipeline)} "
                f"jarm={jarm[:16] + '…' if jarm else 'none'} "
                f"favicon={favicon_hash or 'none'}"
            )

            if http2:
                leads.append({
                    "tool": "httpx",
                    "signal": "http2_supported",
                    "signal_type": "http2_supported",
                    "url": url,
                    "hypothesis": (
                        f"HTTP/2 negotiated via ALPN at {url} — request smuggling, "
                        f"stream cancellation, and h2c upgrade vectors apply. "
                        f"Transport: {transport_summary}"
                    ),
                    "signal_strength": "medium",
                })
            if pipeline:
                leads.append({
                    "tool": "httpx",
                    "signal": "http_pipelining_enabled",
                    "signal_type": "http_pipelining_enabled",
                    "url": url,
                    "hypothesis": (
                        f"HTTP/1.1 pipelining accepted at {url} — request smuggling "
                        f"via desync between front-end and origin is plausible. "
                        f"Transport: {transport_summary}"
                    ),
                    "signal_strength": "medium",
                })

        return ScanResult(
            scan_type="httpx_probe",
            technologies=technologies,
            leads=leads,
            items_found=len(technologies),
        )
