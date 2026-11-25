"""greybox_defenses: asset-scoped (network) recommendations

Adds ``asset_id`` (the protected host/service/endpoint asset), ``scope``
("finding" | "asset") and ``finding_ids`` (every finding a recommendation addresses),
and makes ``finding_id`` nullable (asset-scoped recommendations have none). Existing
rows are finding-scoped: their ``finding_ids`` is back-filled from ``finding_id``.

Portable and idempotent via the inspector (migration 0003 may already have created the
table from the current models); the alter runs in a batch so SQLite can do it.
Downgrade deletes the asset-scoped rows (they cannot be represented before this
revision) and restores the old shape.

Revision ID: 0015_greybox_network_defenses
"""
import uuid

import sqlalchemy as sa
from alembic import op

revision = "0015_greybox_network_defenses"  # <=32 chars
down_revision = "0014_greybox_defenses"
branch_labels = None
depends_on = None

TABLE = "greybox_defenses"
FK_NAME = "fk_greybox_defenses_asset_id"


def _columns() -> dict[str, dict] | None:
    insp = sa.inspect(op.get_bind())
    if TABLE not in insp.get_table_names():
        return None
    return {c["name"]: c for c in insp.get_columns(TABLE)}


def upgrade() -> None:
    cols = _columns()
    if cols is None:
        return
    todo_add = [n for n in ("asset_id", "scope", "finding_ids") if n not in cols]
    todo_null = cols["finding_id"]["nullable"] is False
    if todo_add or todo_null:
        with op.batch_alter_table(TABLE) as batch:
            if "asset_id" in todo_add:
                batch.add_column(sa.Column(
                    "asset_id", sa.Uuid(),
                    sa.ForeignKey("greybox_assets.id", ondelete="CASCADE",
                                  name=FK_NAME), nullable=True))
            if "scope" in todo_add:
                batch.add_column(sa.Column(
                    "scope", sa.String(8), nullable=False, server_default="finding"))
            if "finding_ids" in todo_add:
                batch.add_column(sa.Column(
                    "finding_ids", sa.JSON(), nullable=False, server_default="[]"))
            if todo_null:
                batch.alter_column("finding_id", existing_type=sa.Uuid(),
                                   nullable=True)
    if "finding_ids" in todo_add:
        bind = op.get_bind()
        rows = bind.execute(sa.text(
            f"SELECT id, finding_id FROM {TABLE} WHERE finding_id IS NOT NULL")).all()
        t = sa.table(TABLE, sa.column("id", sa.Uuid()),
                     sa.column("finding_ids", sa.JSON()))
        for rid, fid in rows:       # raw text SELECT: ids may come back as hex strings
            rid, fid = uuid.UUID(str(rid)), uuid.UUID(str(fid))
            bind.execute(t.update().where(t.c.id == rid)
                         .values(finding_ids=[str(fid)]))


def downgrade() -> None:
    cols = _columns()
    if cols is None:
        return
    op.execute(sa.text(f"DELETE FROM {TABLE} WHERE finding_id IS NULL"))
    drop = [n for n in ("asset_id", "scope", "finding_ids") if n in cols]
    make_required = cols["finding_id"]["nullable"] is True
    if not (drop or make_required):
        return
    with op.batch_alter_table(TABLE) as batch:
        if "asset_id" in drop:
            if op.get_bind().dialect.name != "sqlite":
                batch.drop_constraint(FK_NAME, type_="foreignkey")
            batch.drop_column("asset_id")
        for name in ("scope", "finding_ids"):
            if name in drop:
                batch.drop_column(name)
        if make_required:
            batch.alter_column("finding_id", existing_type=sa.Uuid(), nullable=False)
