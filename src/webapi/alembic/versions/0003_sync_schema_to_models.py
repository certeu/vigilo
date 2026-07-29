"""sync schema to models (add any missing columns/tables)

The create_all -> Alembic transition migration. Historically the app used create_all(),
which creates missing TABLES but never adds missing COLUMNS, so an existing DB drifts
behind the models as columns are added. This reconciles every table to its model:
adds any missing column (with a safe server_default so NOT NULL adds work on populated
tables) and creates any missing table. Additive + idempotent; Postgres + SQLite safe.

Revision ID: 0003_sync_schema_to_models
"""
import sqlalchemy as sa
from alembic import op

import src.webapi.models  # noqa: F401  register all tables
from src.webapi.db import Base

revision = "0003_sync_schema_to_models"
down_revision = "0002_add_repository_archived"
branch_labels = None
depends_on = None


def _server_default(col: sa.Column):
    if col.nullable:
        return None
    t = col.type
    if isinstance(t, sa.Boolean):
        return sa.text("false")
    if isinstance(t, (sa.Integer, sa.Float)):
        return sa.text("0")
    if isinstance(t, sa.JSON):
        return sa.text("'{}'")
    return sa.text("''")


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = set(insp.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in tables:
            table.create(bind, checkfirst=True)
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            op.add_column(
                table.name,
                sa.Column(col.name, col.type, nullable=col.nullable,
                          server_default=_server_default(col)),
            )


def downgrade() -> None:
    # Additive reconciliation has no safe automatic reverse.
    pass
