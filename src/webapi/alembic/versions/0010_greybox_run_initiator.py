"""greybox_runs.initiated_by (who started the run)

Run visibility follows the target owner (``greybox_runs.owner_id`` = target owner), so a
target owner always sees runs an admin started on their target. The user who actually
started the run is recorded separately in ``initiated_by`` (no FK, like
``cancel_requested_by``: an audit snapshot that must not block user deletion).

Portable + idempotent via the inspector (migration 0003 may already have created the
column from the current models on a fresh database).

Revision ID: 0010_greybox_run_initiator
"""
import sqlalchemy as sa
from alembic import op

revision = "0010_greybox_run_initiator"  # <=32 chars
down_revision = "0009_greybox_web"
branch_labels = None
depends_on = None


def _cols() -> set[str]:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" not in insp.get_table_names():
        return set()
    return {c["name"] for c in insp.get_columns("greybox_runs")}


def upgrade() -> None:
    cols = _cols()
    if cols and "initiated_by" not in cols:
        with op.batch_alter_table("greybox_runs") as batch:
            batch.add_column(sa.Column("initiated_by", sa.Uuid(), nullable=True))


def downgrade() -> None:
    if "initiated_by" in _cols():
        with op.batch_alter_table("greybox_runs") as batch:
            batch.drop_column("initiated_by")
