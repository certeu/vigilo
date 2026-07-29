"""Uvicorn entrypoint: python -m src.webapi.main"""
from __future__ import annotations

import uvicorn

from src.webapi.app import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run("src.webapi.main:app", host="0.0.0.0", port=8080)
