"""Log tailing for runs.

The pipeline writes a human-readable text log (not JSON) to
``{data_dir}/repo/.vigilo/{session_id}/workflow.log`` — lines look like
``[2026-07-11 22:34:41] [PHASE] Starting: recon``. These helpers read it
incrementally (byte-offset based) so the API can paginate or stream new lines.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator, Awaitable, Callable


def log_path_for(data_dir: str, session_id: str) -> str:
    return os.path.join(data_dir, "repo", ".vigilo", session_id, "workflow.log")


def read_from(path: str, offset: int = 0) -> tuple[list[str], int]:
    """Return (new non-empty lines since ``offset``, new byte offset)."""
    if not os.path.exists(path):
        return [], offset
    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        data = fh.read()
        new_offset = fh.tell()
    lines = [ln for ln in data.splitlines() if ln.strip()]
    return lines, new_offset


async def stream_lines(
    path: str,
    is_done: Callable[[], Awaitable[bool]],
    poll_seconds: float = 0.5,
    max_ticks: int = 100_000,
) -> AsyncGenerator[str, None]:
    """Yield SSE-formatted lines as they appear; stop once ``is_done()`` resolves
    true (after a final drain). ``max_ticks`` is a safety backstop."""
    offset = 0
    ticks = 0
    while True:
        lines, offset = read_from(path, offset)
        for ln in lines:
            yield f"data: {ln}\n\n"
        ticks += 1
        if await is_done() or ticks >= max_ticks:
            # Final drain to catch lines written just before completion.
            lines, offset = read_from(path, offset)
            for ln in lines:
                yield f"data: {ln}\n\n"
            yield "event: end\ndata: {}\n\n"
            return
        await asyncio.sleep(poll_seconds)
