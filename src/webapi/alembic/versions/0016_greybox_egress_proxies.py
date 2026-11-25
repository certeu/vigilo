"""greybox egress proxies: admin-defined forward proxies a target may opt into

Adds the ``greybox_egress_proxies`` table, ``greybox_targets.egress_proxy_id`` (the
selected proxy, no FK: deleting a proxy clears it explicitly), ``greybox_runs.egress_proxy``
(JSON snapshot ``{id, name, url}`` taken at run start, never any credential) and
``greybox_http_exchanges.via_proxy`` (the request went through the proxy).

Portable and idempotent via the inspector (migration 0003 may already have created all
of it from the current models on a fresh database); column adds run in batches so SQLite
can do them.

Revision ID: 0016_greybox_egress_proxies
"""
import sqlalchemy as sa
from alembic import op

revision = "0016_greybox_egress_proxies"  # <=32 chars
down_revision = "0015_greybox_network_defenses"
branch_labels = None
depends_on = None

PROXY_TABLE = "greybox_egress_proxies"
COLUMNS = (
    ("greybox_targets", "egress_proxy_id",
     lambda: sa.Column("egress_proxy_id", sa.Uuid(), nullable=True)),
    ("greybox_runs", "egress_proxy",
     lambda: sa.Column("egress_proxy", sa.JSON(), nullable=True)),
    ("greybox_http_exchanges", "via_proxy",
     lambda: sa.Column("via_proxy", sa.Boolean(), nullable=False,
                       server_default=sa.false())),
)


def _insp():
    return sa.inspect(op.get_bind())


def _has_column(table: str, column: str) -> bool:
    insp = _insp()
    return table in insp.get_table_names() and \
        column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    if PROXY_TABLE not in _insp().get_table_names():
        op.create_table(
            PROXY_TABLE,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("name", sa.String(200), nullable=False, unique=True),
            sa.Column("url", sa.String(500), nullable=False),
            sa.Column("credentials_enc", sa.LargeBinary(), nullable=True),
            sa.Column("allowed_hosts", sa.JSON(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("created_by", sa.Uuid(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    for table, column, make in COLUMNS:
        if table in _insp().get_table_names() and not _has_column(table, column):
            with op.batch_alter_table(table) as batch:
                batch.add_column(make())


def downgrade() -> None:
    for table, column, _ in reversed(COLUMNS):
        if _has_column(table, column):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column)
    if PROXY_TABLE in _insp().get_table_names():
        op.drop_table(PROXY_TABLE)
