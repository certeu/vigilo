"""greybox_hint_replies: the exploration agent's reply to an operator message

Nullable ``reply`` / ``replied_at`` / ``reply_cycle`` / ``seen_cycle`` on
``greybox_hints`` (the run chat). No new status values: replies are orthogonal to
the planner's open/addressed/rejected lifecycle.

Portable and idempotent via the inspector (migration 0003 may already have created
the table from the current models); the alters run in a batch for SQLite.

Revision ID: 0018_greybox_hint_replies
"""
import sqlalchemy as sa
from alembic import op

revision = "0018_greybox_hint_replies"       # <=32 chars
down_revision = "0017_greybox_model_choice"
branch_labels = None
depends_on = None

TABLE = "greybox_hints"


def _columns() -> list[sa.Column]:
    return [sa.Column("reply", sa.Text(), nullable=True),
            sa.Column("replied_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("reply_cycle", sa.Integer(), nullable=True),
            sa.Column("seen_cycle", sa.Integer(), nullable=True)]


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if TABLE not in insp.get_table_names():
        return
    have = {c["name"] for c in insp.get_columns(TABLE)}
    todo = [c for c in _columns() if c.name not in have]
    if not todo:
        return
    with op.batch_alter_table(TABLE) as batch:
        for col in todo:
            batch.add_column(col)


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if TABLE not in insp.get_table_names():
        return
    have = {c["name"] for c in insp.get_columns(TABLE)}
    todo = [c.name for c in _columns() if c.name in have]
    if not todo:
        return
    with op.batch_alter_table(TABLE) as batch:
        for name in todo:
            batch.drop_column(name)
