"""Health/version endpoints (unauthenticated)."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from fastapi import APIRouter

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/version")
async def get_version() -> dict[str, str]:
    try:
        v = version("vigilo")
    except PackageNotFoundError:
        v = "0.0.0"
    return {"version": v}


@router.get("/pipeline/trace-rail")
async def get_trace_rail() -> dict:
    """Canonical rail steps + pipeline phase/agent → step mapping for the UI.

    Static metadata derived from the pipeline enums (see src/webapi/trace_rail.py);
    the frontend consumes this so step labels and log filtering never guess names."""
    from src.webapi.trace_rail import trace_rail_config
    return trace_rail_config()
