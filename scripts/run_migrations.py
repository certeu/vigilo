"""Alembic migration runner (no alembic.ini needed).

Builds an in-memory Alembic Config, injects the DB URL from settings (sync driver),
and runs upgrade/downgrade/stamp/current. Used both as the deploy command and by the
API on startup.

Deploy command:
    python -m scripts.run_migrations upgrade        # apply all pending migrations
Other:
    python -m scripts.run_migrations current
    python -m scripts.run_migrations downgrade 0001_baseline
    python -m scripts.run_migrations stamp head
"""
from __future__ import annotations

import os
import sys

from alembic import command
from alembic.config import Config


def _sync_url() -> str:
    from src.webapi.settings import get_settings
    return (
        get_settings().database_url
        .replace("+asyncpg", "").replace("+aiosqlite", "")
    )


def build_config(url: str | None = None) -> Config:
    cfg = Config()  # no ini file — configure programmatically
    here = os.path.dirname(os.path.abspath(__file__))
    script_location = os.path.join(os.path.dirname(here), "src", "webapi", "alembic")
    cfg.set_main_option("script_location", script_location)
    cfg.set_main_option("sqlalchemy.url", url or _sync_url())
    return cfg


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    action = argv[0] if argv else "upgrade"
    cfg = build_config()
    if action == "upgrade":
        command.upgrade(cfg, argv[1] if len(argv) > 1 else "head")
    elif action == "downgrade":
        command.downgrade(cfg, argv[1])
    elif action == "stamp":
        command.stamp(cfg, argv[1] if len(argv) > 1 else "head")
    elif action == "current":
        command.current(cfg)
    else:
        raise SystemExit(f"unknown action: {action}")


if __name__ == "__main__":
    main()
