"""greybox_exchange_identity: which identity each recorded request carried

``identity`` on ``greybox_http_exchanges`` ("anon", "provided-cookie" or an account
label — never a secret) attributes every recorded answer to the identity it was
given to. Cross-identity analyses (who was shown which object, through which
interface) read it; older rows stay NULL and are simply not attributed.

Portable and idempotent via the inspector.

Revision ID: 0024_greybox_exchange_identity
"""
import sqlalchemy as sa
from alembic import op

revision = "0024_greybox_exchange_identity"     # <=32 chars
down_revision = "0023_greybox_session_vault"
branch_labels = None
depends_on = None

TABLE = "greybox_http_exchanges"


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if TABLE not in insp.get_table_names():
        return
    if "identity" in {c["name"] for c in insp.get_columns(TABLE)}:
        return
    with op.batch_alter_table(TABLE) as batch:
        batch.add_column(sa.Column("identity", sa.String(64), nullable=True))


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if TABLE not in insp.get_table_names():
        return
    if "identity" not in {c["name"] for c in insp.get_columns(TABLE)}:
        return
    with op.batch_alter_table(TABLE) as batch:
        batch.drop_column("identity")
