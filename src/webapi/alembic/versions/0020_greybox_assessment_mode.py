"""greybox_assessment_mode: what kind of target a grey-box target is

``assessment_mode`` ('web' | 'network' | 'artifact') and ``disabled_capabilities``
(JSON list) on ``greybox_targets``. The mode decides which capabilities a run may
use (``src/greybox_web/modes.py``); the scope still decides what is reachable.
Existing targets default to 'web', exactly their previous behaviour.

Portable and idempotent via the inspector (migration 0003 may already have created
the tables from the current models); the alters run in a batch for SQLite.

Revision ID: 0020_greybox_assessment_mode
"""
import sqlalchemy as sa
from alembic import op

revision = "0020_greybox_assessment_mode"       # <=32 chars
down_revision = "0019_greybox_account_ids"
branch_labels = None
depends_on = None

TABLES = ("greybox_targets",)


def _columns() -> list[sa.Column]:
    return [sa.Column("assessment_mode", sa.String(16), nullable=False,
                      server_default="web"),
            sa.Column("disabled_capabilities", sa.JSON(), nullable=False,
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
