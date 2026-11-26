"""greybox_defenses: defensive recommendations generated from findings

One row per detection rule, WAF rule or configuration suggestion generated in the
reporting phase of a run; each is also an exploration-graph node (``kind="defense"``)
linked to its finding by a ``mitigates`` edge.

Portable + idempotent via the inspector (migration 0003 may already have created
the table from the current models on a fresh database).

Revision ID: 0014_greybox_defenses
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_greybox_defenses"  # <=32 chars
down_revision = "0013_greybox_hints"
branch_labels = None
depends_on = None

TABLE = "greybox_defenses"
INDEX = "ix_greybox_defenses_run_finding"


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
        sa.Column("finding_id", sa.Uuid(),
                  sa.ForeignKey("greybox_findings.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("node_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(INDEX, TABLE, ["run_id", "finding_id", "created_at"])


def downgrade() -> None:
    if TABLE in _tables():
        op.drop_table(TABLE)
