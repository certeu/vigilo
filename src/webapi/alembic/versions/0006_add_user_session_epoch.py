"""add users.session_epoch

Per-user token epoch for session invalidation on password change/reset.
Portable + idempotent via the inspector.

Revision ID: 0006_user_session_epoch
"""
import sqlalchemy as sa
from alembic import op

revision = "0006_user_session_epoch"  # <=32 chars (alembic_version.version_num width)
down_revision = "0005_run_commit_sha"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("users", "session_epoch"):
        op.add_column(
            "users",
            sa.Column("session_epoch", sa.Integer(), nullable=False, server_default="0"),
        )


def downgrade() -> None:
    if _has_column("users", "session_epoch"):
        op.drop_column("users", "session_epoch")
