"""Tests for the Claude subprocess executor."""
from __future__ import annotations

import pytest

from src.ai.claude_executor import execute


@pytest.mark.asyncio
async def test_execute_idle_timeout_kills_subprocess(tmp_path, monkeypatch):
    """A subprocess that produces no output within idle_timeout_s is killed.

    Protects against hung tool calls (e.g. curl against a WebSocket endpoint
    that never closes) stalling the whole activity indefinitely.
    """
    # Use a fake 'claude' binary that sleeps forever without writing anything.
    fake = tmp_path / "claude"
    fake.write_text("#!/bin/sh\nexec sleep 60\n")
    fake.chmod(0o755)

    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    result = await execute(
        prompt="hello",
        agent_name="test",
        model_tier="medium",
        cwd=str(tmp_path),
        idle_timeout_s=0.3,
    )

    assert result.success is False
    assert "idle timeout" in (result.error or "").lower()
    assert result.duration_ms < 5_000  # killed quickly, not after sleep 60
