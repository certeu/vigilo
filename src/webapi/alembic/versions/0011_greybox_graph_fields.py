"""greybox_graph_nodes: M4 delta/UX columns (graph UX study)

Added columns:

* ``parent_id``         – the spawning node (incremental placement, collapse)
* ``created_version``   – graph_version at creation (upsert deltas: new vs changed)
* ``last_event_seq``    – the event that last changed status (Live Activity link)
* ``severity``          – on finding nodes (card badge without a second fetch)
* ``outcome``           – on work_order/lead nodes (coverage-ledger vocabulary)

Portable + idempotent via the inspector (migration 0003 may already have created
the columns from the current models on a fresh database).

Revision ID: 0011_greybox_graph_fields
"""
import sqlalchemy as sa
from alembic import op

revision = "0011_greybox_graph_fields"  # <=32 chars
down_revision = "0010_greybox_run_initiator"
branch_labels = None
depends_on = None


def _cols() -> set[str]:
    insp = sa.inspect(op.get_bind())
    if "greybox_graph_nodes" not in insp.get_table_names():
        return set()
    return {c["name"] for c in insp.get_columns("greybox_graph_nodes")}


_COLS = (
    sa.Column("parent_id", sa.Uuid(), nullable=True),
    sa.Column("created_version", sa.BigInteger().with_variant(sa.Integer, "sqlite"),
              nullable=True),
    sa.Column("last_event_seq", sa.BigInteger(), nullable=True),
    sa.Column("severity", sa.String(16), nullable=True),
    sa.Column("outcome", sa.String(24), nullable=True),
)
_NAMES = ("parent_id", "created_version", "last_event_seq", "severity", "outcome")


def upgrade() -> None:
    cols = _cols()
    missing = [c for c in _COLS if c.name not in cols]
    if missing:
        with op.batch_alter_table("greybox_graph_nodes") as batch:
            for col in missing:
                batch.add_column(col)


def downgrade() -> None:
    cols = _cols()
    present = [n for n in _NAMES if n in cols]
    if present:
        with op.batch_alter_table("greybox_graph_nodes") as batch:
            for name in present:
                batch.drop_column(name)
