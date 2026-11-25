"""greybox_runs: at most one non-terminal run per target

``service.start_run`` checks "is there an active run for this target" with a
select followed by an insert, which races on Postgres. This partial unique index
is the database-level guard: a concurrent second start fails with an
IntegrityError that the service maps to the same 409 + run_id response.

Portable (``sqlite_where`` / ``postgresql_where``) and idempotent via the
inspector (migration 0003 may already have created it from the current models).
Pre-existing duplicates (should not exist) are resolved by failing the older
extra active runs so the index can be built.

Revision ID: 0012_greybox_one_active_run
"""
import sqlalchemy as sa
from alembic import op

revision = "0012_greybox_one_active_run"  # <=32 chars
down_revision = "0011_greybox_graph_fields"
branch_labels = None
depends_on = None

INDEX = "ux_greybox_runs_one_active_per_target"
PREDICATE = "status NOT IN ('succeeded', 'failed', 'cancelled')"


def _has_index() -> bool:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" not in insp.get_table_names():
        return True                      # nothing to do (no table)
    return INDEX in {i["name"] for i in insp.get_indexes("greybox_runs")}


def upgrade() -> None:
    if _has_index():
        return
    # Keep the newest active run per target; fail the rest so the index can build.
    op.execute(sa.text(
        "UPDATE greybox_runs SET status='failed', end_reason='superseded', "
        "lease_owner=NULL, lease_expires_at=NULL "
        f"WHERE {PREDICATE} AND EXISTS (SELECT 1 FROM greybox_runs r2 "
        "WHERE r2.target_id = greybox_runs.target_id "
        f"AND r2.{PREDICATE} "
        "AND (r2.created_at > greybox_runs.created_at "
        "OR (r2.created_at = greybox_runs.created_at AND r2.id > greybox_runs.id)))"))
    op.create_index(INDEX, "greybox_runs", ["target_id"], unique=True,
                    sqlite_where=sa.text(PREDICATE),
                    postgresql_where=sa.text(PREDICATE))


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" in insp.get_table_names() and \
            INDEX in {i["name"] for i in insp.get_indexes("greybox_runs")}:
        op.drop_index(INDEX, table_name="greybox_runs")
