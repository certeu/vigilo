"""Grey-box API router assembly.

* ``config_router``: ``GET /greybox/config``, always mounted (reports ``enabled``).
* ``greybox_router``: every other ``/greybox/*`` route, 404 when the feature flag
  ``VIGILO_GREYBOX_WEB_ENABLED`` is off.
* ``analyses_router``: ``GET /analyses``, always mounted; white-box only when off.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from src.greybox_web import settings as gb_settings
from src.greybox_web.acl import NOT_FOUND


def require_greybox_enabled() -> None:
    if not gb_settings.enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)


def build_routers() -> list[APIRouter]:
    from src.greybox_web.api import (
        analyses, config, defenses, egress_proxies, events, findings, graph, hints, runs, targets, traffic)

    greybox_router = APIRouter(dependencies=[Depends(require_greybox_enabled)])
    greybox_router.include_router(egress_proxies.router)
    greybox_router.include_router(targets.router)
    greybox_router.include_router(runs.router)
    greybox_router.include_router(events.router)
    greybox_router.include_router(graph.router)
    greybox_router.include_router(hints.router)
    greybox_router.include_router(defenses.router)
    greybox_router.include_router(findings.router)
    greybox_router.include_router(traffic.router)
    return [config.router, greybox_router, analyses.router]
