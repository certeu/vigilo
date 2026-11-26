"""Agent-owned canonical issue grouping and immutable occurrence evidence."""
import sqlalchemy as sa
from alembic import op

revision = "0025_greybox_correlation"
down_revision = "0024_greybox_exchange_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if "greybox_canonical_issues" not in tables:
        op.create_table("greybox_canonical_issues",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("run_id", sa.Uuid(), sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("title", sa.String(300), nullable=False),
            sa.Column("severity", sa.String(16), nullable=False),
            sa.Column("finding_class", sa.String(24), nullable=False),
            sa.Column("verification_status", sa.String(24), nullable=False),
            sa.Column("root_cause", sa.Text(), nullable=False, server_default=""),
            sa.Column("remediation", sa.JSON(), nullable=True),
            sa.Column("retesting_guidance", sa.Text(), nullable=True),
            sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
        op.create_index("ix_greybox_canonical_issues_run_updated",
                        "greybox_canonical_issues", ["run_id", "updated_at"])
    if "canonical_issue_id" not in {column["name"] for column in inspector.get_columns("greybox_findings")}:
        with op.batch_alter_table("greybox_findings") as batch:
            batch.add_column(sa.Column("canonical_issue_id", sa.Uuid(), nullable=True))
            batch.create_foreign_key("fk_greybox_findings_canonical_issue",
                "greybox_canonical_issues", ["canonical_issue_id"], ["id"], ondelete="SET NULL")
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "greybox_issue_findings" not in tables:
        op.create_table("greybox_issue_findings",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("run_id", sa.Uuid(), sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("issue_id", sa.Uuid(), sa.ForeignKey("greybox_canonical_issues.id", ondelete="CASCADE"), nullable=False),
            sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("greybox_findings.id", ondelete="CASCADE"), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True))
        op.create_index("ix_greybox_issue_findings_run_issue", "greybox_issue_findings",
                        ["run_id", "issue_id", "active"])
    if "greybox_issue_observations" not in tables:
        op.create_table("greybox_issue_observations",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("run_id", sa.Uuid(), sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("issue_id", sa.Uuid(), sa.ForeignKey("greybox_canonical_issues.id", ondelete="CASCADE"), nullable=False),
            sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("greybox_findings.id", ondelete="SET NULL"), nullable=True),
            sa.Column("event_key", sa.String(300), nullable=False),
            sa.Column("location", sa.JSON(), nullable=False),
            sa.Column("observation_status", sa.String(24), nullable=False),
            sa.Column("impact_status", sa.String(24), nullable=False),
            sa.Column("identity", sa.String(64), nullable=True),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("run_id", "event_key", name="uq_greybox_issue_observations_event"))
        op.create_index("ix_greybox_issue_observations_run_issue", "greybox_issue_observations",
                        ["run_id", "issue_id", "observed_at"])
    if "greybox_correlation_audit" not in tables:
        op.create_table("greybox_correlation_audit",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column("run_id", sa.Uuid(), sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("action", sa.String(24), nullable=False),
            sa.Column("canonical_issue_id", sa.Uuid(), sa.ForeignKey("greybox_canonical_issues.id", ondelete="CASCADE"), nullable=False),
            sa.Column("related_issue_ids", sa.JSON(), nullable=False),
            sa.Column("finding_ids", sa.JSON(), nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("evidence_refs", sa.JSON(), nullable=False),
            sa.Column("idempotency_key", sa.String(300), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("run_id", "idempotency_key", name="uq_greybox_correlation_idempotency"))
        op.create_index("ix_greybox_correlation_audit_run_issue", "greybox_correlation_audit",
                        ["run_id", "canonical_issue_id", "created_at"])


def downgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for table in ("greybox_correlation_audit", "greybox_issue_observations", "greybox_issue_findings"):
        if table in tables:
            op.drop_table(table)
    if "canonical_issue_id" in {column["name"] for column in sa.inspect(op.get_bind()).get_columns("greybox_findings")}:
        with op.batch_alter_table("greybox_findings") as batch:
            batch.drop_column("canonical_issue_id")
    if "greybox_canonical_issues" in tables:
        op.drop_table("greybox_canonical_issues")
