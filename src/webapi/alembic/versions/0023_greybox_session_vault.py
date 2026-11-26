"""greybox_session_vault: encrypted identity state of a run, for resume

``session_vault`` (LargeBinary, nullable) on ``greybox_runs``: the sessions the run
established (auth.login) and the browser identities' cookie jars, encrypted with the
platform's Fernet vault. Written when an identity changes; read only when the run is
resumed, and only within ``VIGILO_GREYBOX_SESSION_MAX_AGE_S``. Deleted with the run.

Revision ID: 0023_greybox_session_vault
"""
import sqlalchemy as sa
from alembic import op

revision = "0023_greybox_session_vault"        # <=32 chars
down_revision = "0022_greybox_finding_class"
branch_labels = None
depends_on = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" not in insp.get_table_names():
        return
    if "session_vault" in {c["name"] for c in insp.get_columns("greybox_runs")}:
        return
    with op.batch_alter_table("greybox_runs") as batch:
        batch.add_column(sa.Column("session_vault", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_runs" not in insp.get_table_names():
        return
    if "session_vault" not in {c["name"] for c in insp.get_columns("greybox_runs")}:
        return
    with op.batch_alter_table("greybox_runs") as batch:
        batch.drop_column("session_vault")
