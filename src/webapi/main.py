"""Uvicorn entrypoint: python -m src.webapi.main

Runs two listeners in one process: the public API (:8080, reached only through the
UI's nginx /api proxy) and the internal secret-redemption API (:8081, never proxied or
published; see ``internal.py``).
"""
from __future__ import annotations

import asyncio
import contextlib

import uvicorn

from src.webapi.app import create_app
from src.webapi.internal import create_internal_app
from src.webapi.settings import get_settings

app = create_app()


async def serve() -> None:
    s = get_settings()
    public = uvicorn.Server(uvicorn.Config(app, host=s.api_host, port=s.api_port))
    internal = uvicorn.Server(uvicorn.Config(
        create_internal_app(), host=s.internal_host, port=s.internal_port, log_level="info",
    ))
    # Only the public server owns SIGINT/SIGTERM; the internal one is stopped with it.
    internal.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    internal.capture_signals = contextlib.nullcontext  # type: ignore[method-assign]
    task = asyncio.create_task(internal.serve())
    try:
        await public.serve()
    finally:
        internal.should_exit = True
        await task


if __name__ == "__main__":
    asyncio.run(serve())
