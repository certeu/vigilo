"""add repositories.archived

First incremental migration (kept as a small, explicit example of add-column on a
possibly-populated table). Portable + idempotent via the inspector.

Revision ID: 0002_add_repository_archived
"""
import sqlalchemy as sa
from alembic import op

revision = "0002_add_repository_archived"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("repositories", "archived"):
        op.add_column(
            "repositories",
            sa.Column("archived", sa.Boolean(), nullable=False,
                      server_default=sa.false()),
        )


def downgrade() -> None:
    if _has_column("repositories", "archived"):
        op.drop_column("repositories", "archived")
