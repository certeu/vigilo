"""generic forge column names

* ``repositories.gitlab_url`` -> ``remote_url``
* ``repositories.gitlab_project_id`` -> ``forge_project_id``
* ``credentials.gitlab_base_url`` -> ``forge_base_url``

Repositories can come from other forges than GitLab (GitHub, GitHub Enterprise), so
the columns lose their GitLab prefix. The API keeps accepting the old field names.

Portable + idempotent: a database that already has the new column only (fresh
database, baseline created from the current models) is left alone; one where 0003
added the new column next to the old one gets the old values copied over before the
old column is dropped.

Revision ID: 0009_generic_forge_fields
"""
import sqlalchemy as sa
from alembic import op

revision = "0009_generic_forge_fields"  # <=32 chars
down_revision = "0008_run_secrets_job_cookie"
branch_labels = None
depends_on = None

RENAMES = (
    ("repositories", "gitlab_url", "remote_url", 500),
    ("repositories", "gitlab_project_id", "forge_project_id", 100),
    ("credentials", "gitlab_base_url", "forge_base_url", 500),
)


def _cols(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _move(table: str, src: str, dst: str, length: int) -> None:
    cols = _cols(table)
    if src not in cols:
        return
    if dst not in cols:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(src, new_column_name=dst,
                               existing_type=sa.String(length), existing_nullable=True)
        return
    op.execute(sa.text(f"UPDATE {table} SET {dst} = {src} WHERE {dst} IS NULL OR {dst} = ''"))
    with op.batch_alter_table(table) as batch:
        batch.drop_column(src)


def upgrade() -> None:
    for table, old, new, length in RENAMES:
        _move(table, old, new, length)


def downgrade() -> None:
    for table, old, new, length in RENAMES:
        _move(table, new, old, length)
