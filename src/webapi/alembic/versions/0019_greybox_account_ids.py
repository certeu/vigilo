"""greybox_account_ids: optional login accounts on greybox targets and runs

``account_ids`` (JSON list of credential ids, no FK — SQLite has no FK pragma) on
``greybox_targets`` and snapshotted onto ``greybox_runs`` at start. The ids point at
owner-owned ``login_account`` credentials; secrets never leave the vault and are
decrypted only at run start by the supervisor.

Portable and idempotent via the inspector (migration 0003 may already have created
the tables from the current models); the alters run in a batch for SQLite.

Revision ID: 0019_greybox_account_ids
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_greybox_account_ids"       # <=32 chars
down_revision = "0018_greybox_hint_replies"
branch_labels = None
depends_on = None

TABLES = ("greybox_targets", "greybox_runs")


def _columns() -> list[sa.Column]:
    return [sa.Column("account_ids", sa.JSON(), nullable=False,
                      server_default="[]")]


def _todo(insp: sa.Inspector, table: str) -> list[sa.Column]:
    have = {c["name"] for c in insp.get_columns(table)}
    return [c for c in _columns() if c.name not in have]


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    for table in TABLES:
        if table not in insp.get_table_names():
            continue
        todo = _todo(insp, table)
        if not todo:
            continue
        with op.batch_alter_table(table) as batch:
            for col in todo:
                batch.add_column(col)


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    for table in TABLES:
        if table not in insp.get_table_names():
            continue
        present = {c["name"] for c in insp.get_columns(table)} & {
            c.name for c in _columns()}
        if not present:
            continue
        with op.batch_alter_table(table) as batch:
            for name in present:
                batch.drop_column(name)
