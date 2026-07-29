"""baseline schema (all current tables)

Represents the schema previously produced by create_all(). For a fresh DB this
creates everything; for an existing create_all DB, running from base is safe
(create_all uses checkfirst, so existing tables are left alone) and simply
establishes the Alembic version baseline.

Revision ID: 0001_baseline
"""
from alembic import op

# Import models so every table is registered on Base.metadata.
import src.webapi.models  # noqa: F401
from src.webapi.db import Base

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind())
