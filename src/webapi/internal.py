"""Internal-only API: per-run secret redemption for workers.

Served by a SEPARATE uvicorn listener (``VIGILO_INTERNAL_PORT``, default 8081) that is
never published and never routed: Traefik has no router for it and the UI's nginx only
proxies ``/api`` to the public listener on :8080. This app is not mounted on the public
app, so ``/api/internal/...`` does not exist. See ``main.py``.
"""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi import secret_store
from src.webapi.db import get_async_session

router = APIRouter(prefix="/internal/v1", tags=["internal"])


class RedeemRequest(BaseModel):
    key: str = Field(min_length=16, max_length=256)
    # gitlab_token: earlier name of forge_token, still accepted
    want: list[Literal["forge_token", "gitlab_token", "cookie_header"]] = Field(
        min_length=1, max_length=2)


class RedeemResponse(BaseModel):
    secrets: dict[str, str]


@router.post("/runs/{run_id}/secrets", response_model=RedeemResponse)
async def redeem_secrets(
    run_id: uuid.UUID,
    body: RedeemRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_async_session),
) -> RedeemResponse:
    response.headers["Cache-Control"] = "no-store"
    client = request.client.host if request.client else "?"
    try:
        out = await secret_store.redeem(session, run_id, body.key, list(body.want), client)
    except secret_store.RedemptionRateLimited:
        raise HTTPException(status_code=429, detail="too many redemption attempts")
    except secret_store.RedemptionRefused:
        raise HTTPException(status_code=403, detail="refused")
    return RedeemResponse(secrets=out)


def create_internal_app() -> FastAPI:
    app = FastAPI(title="Vigilo internal API", docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(router)
    return app
