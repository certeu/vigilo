"""Managed scan wrappers for grey-box pipeline."""
from __future__ import annotations

from src.greybox.managed.base import BaseScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {}


def _register_scanners() -> None:
    """Lazily populate the scanner registry on first access."""
    if SCANNER_REGISTRY:
        return
    from src.greybox.managed.nuclei import NucleiScanner
    from src.greybox.managed.feroxbuster import FeroxbusterScanner
    from src.greybox.managed.headers import HeadersScanner
    from src.greybox.managed.cors import CorsScanner
    from src.greybox.managed.ssl_analysis import SslScanner
    from src.greybox.managed.default_creds import DefaultCredsScanner
    from src.greybox.managed.whatweb import WhatwebScanner
    from src.greybox.managed.robots_sitemap import RobotsSitemapScanner
    from src.greybox.managed.nmap import NmapScanner
    from src.greybox.managed.httpx_probe import HttpxProbeScanner

    SCANNER_REGISTRY.update({
        "nuclei": NucleiScanner,
        "feroxbuster": FeroxbusterScanner,
        "header_analysis": HeadersScanner,
        "cors_check": CorsScanner,
        "ssl_analysis": SslScanner,
        "default_creds": DefaultCredsScanner,
        "tech_fingerprint": WhatwebScanner,
        "robots_sitemap": RobotsSitemapScanner,
        "nmap": NmapScanner,
        "httpx_probe": HttpxProbeScanner,
    })


# Active-recon scanners that are gated by ``GreyBoxConfig.active_recon_enabled``.
# The workflow drops these from the dispatch list when the flag is False even
# if their per-scanner toggle in ``managed_scans`` is True.
ACTIVE_RECON_SCANNERS: frozenset[str] = frozenset({"nmap", "httpx_probe"})


def get_scanner(scan_type: str, target_url: str, **kwargs: object) -> BaseScanner:
    """Get a scanner instance by type name."""
    _register_scanners()
    cls = SCANNER_REGISTRY.get(scan_type)
    if cls is None:
        raise ValueError(f"Unknown scan type: {scan_type}. Available: {list(SCANNER_REGISTRY.keys())}")
    return cls(target_url, **kwargs)
