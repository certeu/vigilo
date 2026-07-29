"""Shared context manager — inter-agent communication via shared_context.json.

Enables agents to share progressive knowledge:
- Pre-recon writes detected_technologies
- Recon enriches with API info, auth info
- Vuln/exploit agents append new discoveries (credentials, endpoints, etc.)

All operations use an asyncio.Lock for concurrent write safety within a
single worker process, plus atomic file writes for crash safety.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import aiofiles

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SharedContext(BaseModel):
    """Schema for deliverables/shared_context.json.

    All fields are dicts so agents can freely add nested keys without schema
    changes. The model provides a typed baseline; actual contents grow as
    agents populate them.
    """
    tech_stack: dict[str, Any] = Field(default_factory=dict)
    auth: dict[str, Any] = Field(default_factory=dict)
    api: dict[str, Any] = Field(default_factory=dict)
    custom: dict[str, Any] = Field(default_factory=dict)


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *updates* into *base*, returning the merged dict.

    - Dicts are merged recursively.
    - Lists are concatenated (updates appended to base).
    - Scalars in *updates* overwrite those in *base*.
    """
    merged = dict(base)
    for key, value in updates.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        elif key in merged and isinstance(merged[key], list) and isinstance(value, list):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged


class SharedContextManager:
    """Thread-safe read/write for deliverables/shared_context.json."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    def _context_path(self, repo_path: str) -> Path:
        return Path(repo_path) / "deliverables" / "shared_context.json"

    async def read(self, repo_path: str) -> dict[str, Any]:
        """Read current shared context.

        Returns an empty dict if the file does not exist or is malformed.
        """
        ctx_path = self._context_path(repo_path)

        if not ctx_path.is_file():
            # Downstream agents (critic reachability analysis, conditional
            # graphql/websocket pipelines) depend on this context. A missing
            # file after pre-recon is a real problem, not a debug detail —
            # surface it so a silent skip is visible in the logs.
            logger.warning(
                "shared_context.json not found at %s — downstream context "
                "(tech stack, auth model, deployment) will be unavailable",
                ctx_path,
            )
            return {}

        try:
            async with aiofiles.open(ctx_path, mode="r", encoding="utf-8") as f:
                content = await f.read()
            data = json.loads(content)
            if not isinstance(data, dict):
                logger.warning("shared_context.json is not a JSON object, returning empty dict")
                return {}
            if not data:
                logger.warning("shared_context.json is empty — no accumulated context to read")
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read shared_context.json: %s", exc)
            return {}

    async def update(self, repo_path: str, updates: dict[str, Any]) -> None:
        """Merge *updates* into shared_context.json with locking.

        Performs a deep merge: nested dicts are merged recursively, lists are
        concatenated, scalars are overwritten.
        """
        async with self._lock:
            current = await self.read(repo_path)
            merged = _deep_merge(current, updates)
            await self._write_atomic(repo_path, merged)
            logger.info("Updated shared_context.json with keys: %s", list(updates.keys()))

    async def initialize(self, repo_path: str, initial: dict[str, Any]) -> None:
        """Create the initial shared_context.json.

        Typically called by the recon agent after mapping the attack surface.
        If the file already exists, this deep-merges *initial* on top of
        existing content (preserving anything pre-recon already wrote).
        """
        async with self._lock:
            ctx_path = self._context_path(repo_path)

            if ctx_path.is_file():
                current = await self.read(repo_path)
                merged = _deep_merge(current, initial)
            else:
                merged = initial

            await self._write_atomic(repo_path, merged)
            logger.info("Initialized shared_context.json at %s", ctx_path)

    async def _write_atomic(self, repo_path: str, data: dict[str, Any]) -> None:
        """Write *data* to shared_context.json atomically.

        Writes to a temp file first, then renames for crash safety.
        """
        ctx_path = self._context_path(repo_path)
        tmp_path = ctx_path.with_suffix(".json.tmp")

        # Ensure deliverables directory exists
        ctx_path.parent.mkdir(parents=True, exist_ok=True)

        content = json.dumps(data, indent=2, ensure_ascii=False)
        async with aiofiles.open(tmp_path, mode="w", encoding="utf-8") as f:
            await f.write(content)

        # Atomic rename (POSIX guarantees this is atomic on same filesystem)
        tmp_path.rename(ctx_path)
