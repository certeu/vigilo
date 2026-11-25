"""greybox_model_choice: per-target and per-run model backend/model for exploration

``greybox_targets.model_backend`` / ``model`` (the user's choice; empty = platform
default) and the same two columns on ``greybox_runs`` (snapshot at start).

Portable and idempotent via the inspector (migration 0003 may already have created the
tables from the current models); the alters run in a batch for SQLite.

Revision ID: 0017_greybox_model_choice
"""
import sqlalchemy as sa
from alembic import op

revision = "0017_greybox_model_choice"       # <=32 chars
down_revision = "0016_greybox_egress_proxies"
branch_labels = None
depends_on = None

TABLES = ("greybox_targets", "greybox_runs")
COLUMNS = (("model_backend", 16), ("model", 100))


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    for table in TABLES:
        if table not in insp.get_table_names():
            continue
        have = {c["name"] for c in insp.get_columns(table)}
        todo = [(n, l) for n, l in COLUMNS if n not in have]
        if not todo:
            continue
        with op.batch_alter_table(table) as batch:
            for name, length in todo:
                batch.add_column(sa.Column(name, sa.String(length=length),
                                           nullable=False, server_default=""))


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    for table in TABLES:
        if table not in insp.get_table_names():
            continue
        have = {c["name"] for c in insp.get_columns(table)}
        todo = [n for n, _ in COLUMNS if n in have]
        if not todo:
            continue
        with op.batch_alter_table(table) as batch:
            for name in todo:
                batch.drop_column(name)
