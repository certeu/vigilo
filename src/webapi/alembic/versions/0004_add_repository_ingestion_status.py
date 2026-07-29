"""add repositories.ingestion_status + ingestion_error

Background ingestion state for uploads (idle → importing → ready/failed) so the UI
can show a per-repo status while a large archive validates off the request path.

Portable + idempotent via the inspector (safe on an already-synced DB).

Revision ID: 0004_add_repository_ingestion_status
"""
import sqlalchemy as sa
from alembic import op

revision = "0004_repo_ingestion"  # keep <=32 chars (alembic_version.version_num width)
down_revision = "0003_sync_schema_to_models"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("repositories", "ingestion_status"):
        op.add_column(
            "repositories",
            sa.Column("ingestion_status", sa.String(16), nullable=False,
                      server_default="idle"),
        )
    if not _has_column("repositories", "ingestion_error"):
        op.add_column(
            "repositories",
            sa.Column("ingestion_error", sa.String(500), nullable=True),
        )


def downgrade() -> None:
    for col in ("ingestion_error", "ingestion_status"):
        if _has_column("repositories", col):
            op.drop_column("repositories", col)
