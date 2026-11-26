"""greybox_run_auth_states: what a run met at the authentication boundary

``auth_states`` (JSON list of states: "identity_provider", "expired", "missing") on
``greybox_runs``. Written when a response shows the run was not looking at the
application (a redirect to an IdP, a 401, a login screen); read by the completion
verdict so a stale session ends as ``blocked`` instead of ``completed``
(field-assessment defect F5).

Portable and idempotent via the inspector; existing runs default to an empty list.

Revision ID: 0021_greybox_run_auth_states
"""
import sqlalchemy as sa
from alembic import op

revision = "0021_greybox_run_auth_states"       # <=32 chars
down_revision = "0020_greybox_assessment_mode"
branch_labels = None
depends_on = None


def _columns() -> list[sa.Column]:
    return [sa.Column("auth_states", sa.JSON(), nullable=False,
                      server_default="[]"),
            sa.Column("coverage_verdict", sa.JSON(), nullable=True)]


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" not in insp.get_table_names():
        return
    have = {c["name"] for c in insp.get_columns("greybox_runs")}
    todo = [c for c in _columns() if c.name not in have]
    if not todo:
        return
    with op.batch_alter_table("greybox_runs") as batch:
        for col in todo:
            batch.add_column(col)


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" not in insp.get_table_names():
        return
    have = {c["name"] for c in insp.get_columns("greybox_runs")}
    present = [c.name for c in _columns() if c.name in have]
    if not present:
        return
    with op.batch_alter_table("greybox_runs") as batch:
        for name in present:
            batch.drop_column(name)
