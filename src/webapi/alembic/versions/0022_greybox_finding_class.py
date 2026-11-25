"""greybox_finding_class: what kind of issue a finding is, and how to fix it

``finding_class`` on ``greybox_findings`` (vulnerability | misconfiguration |
hardening | informational) separates an exploitable weakness from a missing
defence, so a missing header is never presented as an exploitable vulnerability.
``remediation`` holds the structured
advice: ``{"summary", "steps": [...], "validation": [...], "reproduction": [...],
"severity_rationale"}``.

Portable and idempotent via the inspector; existing rows get an empty class (the
report derives one from the check id) and no remediation.

Revision ID: 0022_greybox_finding_class
"""
import sqlalchemy as sa
from alembic import op

revision = "0022_greybox_finding_class"        # <=32 chars
down_revision = "0021_greybox_run_auth_states"
branch_labels = None
depends_on = None


def _columns() -> list[sa.Column]:
    return [sa.Column("finding_class", sa.String(24), nullable=False,
                      server_default=""),
            sa.Column("remediation", sa.JSON(), nullable=True)]


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_findings" not in insp.get_table_names():
        return
    have = {c["name"] for c in insp.get_columns("greybox_findings")}
    todo = [c for c in _columns() if c.name not in have]
    if not todo:
        return
    with op.batch_alter_table("greybox_findings") as batch:
        for col in todo:
            batch.add_column(col)


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "greybox_findings" not in insp.get_table_names():
        return
    have = {c["name"] for c in insp.get_columns("greybox_findings")}
    present = [c.name for c in _columns() if c.name in have]
    if not present:
        return
    with op.batch_alter_table("greybox_findings") as batch:
        for name in present:
            batch.drop_column(name)
