"""add jobs.notify_email

Per-job opt-in to email the report on run completion. Off by default.
Portable + idempotent via the inspector.

Revision ID: 0007_job_notify_email
"""
import sqlalchemy as sa
from alembic import op

revision = "0007_job_notify_email"  # <=32 chars (alembic_version.version_num width)
down_revision = "0006_user_session_epoch"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("jobs", "notify_email"):
        op.add_column(
            "jobs",
            sa.Column("notify_email", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    if _has_column("jobs", "notify_email"):
        op.drop_column("jobs", "notify_email")
