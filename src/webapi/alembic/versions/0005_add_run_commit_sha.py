"""add runs.commit_sha

Records the git commit SHA a run scanned (GitLab repos), for reproducibility.
Portable + idempotent via the inspector.

Revision ID: 0005_run_commit_sha
"""
import sqlalchemy as sa
from alembic import op

revision = "0005_run_commit_sha"  # keep <=32 chars (alembic_version.version_num width)
down_revision = "0004_repo_ingestion"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("runs", "commit_sha"):
        op.add_column("runs", sa.Column("commit_sha", sa.String(40), nullable=True))


def downgrade() -> None:
    if _has_column("runs", "commit_sha"):
        op.drop_column("runs", "commit_sha")
