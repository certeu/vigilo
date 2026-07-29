"""Tests for the Codex CLI executor (src/ai/codex_executor.py)."""
from __future__ import annotations

import json

import pytest

from src.ai import codex_executor as cx


class TestResolveModel:
    def test_default_tiers(self, monkeypatch):
        for v in cx._TIER_ENV_MAP.values():
            monkeypatch.delenv(v, raising=False)
        assert cx.resolve_model("small") == cx.MODEL_DEFAULTS["small"]
        assert cx.resolve_model("medium") == cx.MODEL_DEFAULTS["medium"]
        assert cx.resolve_model("large") == cx.MODEL_DEFAULTS["large"]

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("CODEX_LARGE_MODEL", "gpt-5.2-codex")
        assert cx.resolve_model("large") == "gpt-5.2-codex"

    def test_unknown_tier_passthrough(self, monkeypatch):
        # A concrete deployment name is returned unchanged (no provider prefix).
        assert cx.resolve_model("my-azure-deployment") == "my-azure-deployment"


class TestEstimateCost:
    def test_env_prices(self, monkeypatch):
        monkeypatch.setenv("CODEX_PRICE_INPUT_PER_MTOK", "10")   # $10 / 1M
        monkeypatch.setenv("CODEX_PRICE_OUTPUT_PER_MTOK", "30")  # $30 / 1M
        cost = cx._estimate_cost("gpt-5-codex", 1_000_000, 1_000_000)
        assert cost == pytest.approx(40.0)

    def test_unknown_model_zero_and_warns(self, monkeypatch, caplog):
        for v in ("CODEX_PRICE_INPUT_PER_MTOK", "CODEX_PRICE_OUTPUT_PER_MTOK"):
            monkeypatch.delenv(v, raising=False)
        with caplog.at_level("WARNING"):
            cost = cx._estimate_cost("totally-unknown-model", 1000, 1000)
        assert cost == 0.0
        assert any("cost" in r.message.lower() for r in caplog.records)


class _FakeStdout:
    """Minimal async stdout yielding pre-baked JSONL lines then EOF."""

    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)

    async def readline(self) -> bytes:
        return self._lines.pop(0) if self._lines else b""

    async def read(self) -> bytes:
        out, self._lines = b"".join(self._lines), []
        return out


class _FakeProc:
    def __init__(self, lines: list[bytes], returncode: int = 0) -> None:
        self.stdout = _FakeStdout(lines)
        self.stderr = _FakeStdout([])
        self._returncode = returncode

    def kill(self):  # pragma: no cover
        pass

    async def wait(self) -> int:
        return self._returncode


CODEX_JSONL = [
    b'{"type":"thread.started","thread_id":"t_123"}\n',
    b'{"type":"turn.started"}\n',
    b'{"type":"item.started","item":{"type":"command_execution","command":"cat app.py"}}\n',
    b'{"type":"item.completed","item":{"type":"reasoning","text":"thinking hard"}}\n',
    b'{"type":"item.completed","item":{"type":"assistant_message","text":"Found an issue."}}\n',
    b'{"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":20,'
    b'"output_tokens":50,"reasoning_output_tokens":10}}\n',
]


@pytest.mark.asyncio
async def test_execute_parses_stream(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_PRICE_INPUT_PER_MTOK", "1")
    monkeypatch.setenv("CODEX_PRICE_OUTPUT_PER_MTOK", "1")

    async def fake_exec(*args, **kwargs):
        return _FakeProc(list(CODEX_JSONL), returncode=0)

    monkeypatch.setattr(cx.asyncio, "create_subprocess_exec", fake_exec)

    events: list[tuple[int, str]] = []

    async def on_stream(name, turn, content):
        events.append((turn, content))

    res = await cx.execute(
        prompt="review", agent_name="tester", model_tier="large",
        cwd=str(tmp_path), on_stream=on_stream,
    )

    assert res.success is True
    assert res.num_turns == 1
    assert res.input_tokens == 120          # input + cached
    assert res.output_tokens == 60          # output + reasoning
    assert res.result_text == "Found an issue."
    assert res.cost_usd == pytest.approx((120 + 60) / 1_000_000)
    # Logging parity: tool + thinking arrive as JSON blocks, text as raw str.
    contents = [c for _, c in events]
    assert any(json.loads(c).get("type") == "tool_use" for c in contents
               if c.startswith("{"))
    assert any(json.loads(c).get("type") == "thinking" for c in contents
               if c.startswith("{"))
    assert "Found an issue." in contents


@pytest.mark.asyncio
async def test_execute_nonzero_exit_is_failure(monkeypatch, tmp_path):
    async def fake_exec(*args, **kwargs):
        return _FakeProc(
            [b'{"type":"turn.failed","error":{"message":"boom"}}\n'], returncode=1
        )

    monkeypatch.setattr(cx.asyncio, "create_subprocess_exec", fake_exec)

    res = await cx.execute(
        prompt="x", agent_name="tester", model_tier="large", cwd=str(tmp_path),
    )
    assert res.success is False
    assert "boom" in (res.error or "")
