"""Base scanner abstraction and scan result model."""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Unified result from any managed scan."""

    scan_type: str
    new_endpoints: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    leads: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    items_found: int = 0


class BaseScanner(ABC):
    """Abstract base for all managed scan wrappers."""

    def __init__(self, target_url: str, **kwargs: object) -> None:
        self.target_url = target_url
        # Extract auth context up-front so subclasses can rely on attributes
        # rather than rummaging through kwargs in build_command().
        self.cookie_header: str = str(kwargs.pop("cookie_header", "") or "")
        self.identity_name: str = str(kwargs.pop("identity_name", "") or "")
        self.options = kwargs

    @property
    def is_authenticated(self) -> bool:
        """True if an auth context (cookie header) was supplied."""
        return bool(self.cookie_header)

    @abstractmethod
    def build_command(self) -> list[str]:
        """Return the CLI command to execute."""
        ...

    @abstractmethod
    def parse_output(self, raw_output: str) -> ScanResult:
        """Parse tool stdout into a ScanResult."""
        ...

    async def run(self) -> ScanResult:
        """Execute the scan tool and parse its output."""
        cmd = self.build_command()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"Scanner binary not found: {cmd[0]}. "
                f"Ensure it is installed in the container."
            ) from None
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.warning(
                "%s exited with code %d: %s",
                cmd[0], proc.returncode, stderr.decode(errors="replace")[:500],
            )
        return self.parse_output(stdout.decode(errors="replace"))
