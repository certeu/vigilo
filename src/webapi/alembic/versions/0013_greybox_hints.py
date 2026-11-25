"""greybox_hints: analyst steering for running scans

One row per hint posted to a run. The planner processes each open hint once and
records its outcome here; the hint is also an exploration-graph node
(``kind="hint"``) linked to what it guided.

Portable + idempotent via the inspector (migration 0003 may already have created
the table from the current models on a fresh database).

Revision ID: 0013_greybox_hints
"""
import sqlalchemy as sa
from alembic import op

revision = "0013_greybox_hints"  # <=32 chars
down_revision = "0012_greybox_one_active_run"
branch_labels = None
depends_on = None

TABLE = "greybox_hints"
INDEX = "ix_greybox_hints_run_status"


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if TABLE in _tables():
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(),
                  sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("target", sa.String(2048), nullable=True),
        sa.Column("about_node_id", sa.Uuid(), nullable=True),
        sa.Column("node_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("result", sa.String(500), nullable=True),
        sa.Column("work_order_ids", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_by_name", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("addressed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(INDEX, TABLE, ["run_id", "status", "created_at"])


def downgrade() -> None:
    if TABLE in _tables():
        op.drop_table(TABLE)
