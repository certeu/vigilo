"""nmap port and service discovery scanner.

Active recon — opt-in via ``GreyBoxConfig.active_recon_enabled``. The
workflow filters this scanner out when the flag is False, so by the
time ``run()`` is called the operator has already authorised it.

Scope is single-host: nmap is invoked against the hostname extracted
from ``target_url``. Top-1000 TCP, ``-sT -sV`` (TCP connect + service
banner), bounded by ``preflight_scan_deadline_s`` via
``--host-timeout``.

Output: every open port surfaces as a ``technology`` row (so the
service banner is captured) plus a ``lead`` for non-standard ports,
which gives discovery / specialists a hook to investigate sibling
admin services on 8080, 3306, 6379, etc. Ports are NOT emitted as
``new_endpoints`` because the existing managed-scan→graph bridge maps
those into HTTP ``EndpointNode`` rows that expect method/path shape.
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from src.greybox.managed.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)


class NmapScanner(BaseScanner):
    """Wrapper for nmap top-1000 TCP service discovery."""

    def build_command(self) -> list[str]:
        parsed = urlparse(self.target_url)
        host = parsed.hostname or self.target_url

        deadline_s = int(self.options.get("host_timeout_s", 600))
        min_rate = int(self.options.get("min_rate", 100))
        max_rate = int(self.options.get("max_rate", 500))
        top_ports = int(self.options.get("top_ports", 1000))

        cmd = [
            "nmap",
            "-sT", "-sV",
            "--top-ports", str(top_ports),
            "--min-rate", str(min_rate),
            "--max-rate", str(max_rate),
            "--host-timeout", f"{deadline_s}s",
            "-oX", "-",
            host,
        ]
        return cmd

    def parse_output(self, raw_output: str) -> ScanResult:
        leads: list[dict] = []
        technologies: list[dict] = []
        open_ports = 0

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as exc:
            logger.warning("nmap output is not valid XML: %s", exc)
            return ScanResult(scan_type="nmap", items_found=0)

        target_host = urlparse(self.target_url).hostname or ""

        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host_addr = addr_el.get("addr", target_host) if addr_el is not None else target_host

            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                open_ports += 1
                port_num = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                service_product = service_el.get("product", "") if service_el is not None else ""
                service_version = service_el.get("version", "") if service_el is not None else ""

                if service_product:
                    technologies.append({
                        "tool": "nmap",
                        "name": service_product,
                        "version": service_version,
                        "category": "server",
                        "source": f"nmap:{host_addr}:{port_num}",
                    })

                # Sibling services on non-standard ports are leads — discovery
                # may not have crawled them, and they often expose admin
                # interfaces (e.g. 8080, 9090, 3306, 6379).
                if port_num not in (80, 443):
                    leads.append({
                        "tool": "nmap",
                        "signal_type": "sibling_service",
                        "host": host_addr,
                        "port": port_num,
                        "service": service_name,
                        "signal": "sibling_service",
                        "hypothesis": (
                            f"Port {port_num}/{protocol} ({service_name or 'unknown'}) "
                            f"open on {host_addr} — sibling service may expose admin or "
                            f"unauthenticated surface not covered by HTTP discovery"
                        ),
                        "signal_strength": "medium",
                    })

        return ScanResult(
            scan_type="nmap",
            technologies=technologies,
            leads=leads,
            items_found=open_ports,
        )
