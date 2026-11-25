"""grey-box web platform tables (greybox_*)

Creates every grey-box table so
later grey-box slices need no further migration. New tables only: no white-box table
or row is touched.

Portable + idempotent via the inspector, like 0008 (on a fresh database migration 0003
may already have created these tables from the current models). The downgrade drops
them in reverse dependency order.

Revision ID: 0009_greybox_web
"""
import sqlalchemy as sa
from alembic import op

revision = "0009_greybox_web"  # <=32 chars
down_revision = "0008_run_secrets_job_cookie"
branch_labels = None
depends_on = None

_BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _uuid(name: str, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.Uuid(), nullable=nullable)


def _run_fk() -> sa.Column:
    return sa.Column("run_id", sa.Uuid(),
                     sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False)


def _id() -> sa.Column:
    return sa.Column("id", sa.Uuid(), primary_key=True)


def _str(name: str, n: int, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.String(n), nullable=nullable)


def _int(name: str, nullable: bool = False, default: str | None = "0") -> sa.Column:
    return sa.Column(name, sa.Integer(), nullable=nullable,
                     server_default=default if not nullable else None)


def _big(name: str, nullable: bool = False, default: str | None = None) -> sa.Column:
    return sa.Column(name, sa.BigInteger(), nullable=nullable, server_default=default)


def _json(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.JSON(), nullable=nullable)


def _bool(name: str, default: str = "false") -> sa.Column:
    return sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.text(default))


def _tables():
    """(name, create callable) in dependency order (parents first)."""

    def targets():
        op.create_table(
            "greybox_targets",
            _id(),
            sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
            _str("name", 200),
            _str("description", 2000, nullable=True),
            _str("base_url", 500),
            _json("scope"),
            _json("limits"),
            _json("checks", nullable=True),
            sa.Column("credential_id", sa.Uuid(),
                      sa.ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True),
            _bool("archived"),
            _ts("created_at"),
            _ts("updated_at"),
        )
        op.create_index("ix_greybox_targets_owner_id", "greybox_targets", ["owner_id"])

    def runs():
        op.create_table(
            "greybox_runs",
            _id(),
            sa.Column("target_id", sa.Uuid(),
                      sa.ForeignKey("greybox_targets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("owner_id", sa.Uuid(), sa.ForeignKey("users.id"), nullable=False),
            _str("status", 16),
            _str("phase", 32, nullable=True),
            _str("end_reason", 32, nullable=True),
            _str("error_summary", 2000, nullable=True),
            _str("base_url", 500),
            _json("scope"),
            _json("limits"),
            _json("checks"),
            _uuid("credential_id"),
            _str("idempotency_key", 64, nullable=True),
            _ts("cancel_requested_at", nullable=True),
            _uuid("cancel_requested_by"),
            _str("lease_owner", 128, nullable=True),
            _ts("lease_expires_at", nullable=True),
            _ts("heartbeat_at", nullable=True),
            _int("attempts"),
            _big("last_seq", default="0"),
            _big("graph_version", default="0"),
            _int("requests_made"),
            _int("requests_blocked"),
            _ts("created_at"),
            _ts("started_at", nullable=True),
            _ts("finished_at", nullable=True),
            sa.UniqueConstraint("owner_id", "idempotency_key",
                                name="uq_greybox_runs_owner_idem"),
        )
        op.create_index("ix_greybox_runs_status_created", "greybox_runs",
                        ["status", "created_at"])
        op.create_index("ix_greybox_runs_owner_created", "greybox_runs",
                        ["owner_id", "created_at"])
        op.create_index("ix_greybox_runs_target_created", "greybox_runs",
                        ["target_id", "created_at"])
        op.create_index("ix_greybox_runs_status_lease", "greybox_runs",
                        ["status", "lease_expires_at"])

    def agents():
        op.create_table(
            "greybox_agents",
            _id(),
            _run_fk(),
            _str("name", 64),
            _str("role", 16),
            _str("status", 16),
            _uuid("current_work_order_id"),
            _str("current_summary", 300, nullable=True),
            _int("work_orders_done"),
            _int("work_orders_failed"),
            _big("last_event_seq", nullable=True),
            _ts("started_at", nullable=True),
            _ts("finished_at", nullable=True),
            sa.UniqueConstraint("run_id", "name", name="uq_greybox_agents_run_name"),
        )
        op.create_index("ix_greybox_agents_run", "greybox_agents", ["run_id"])

    def assets():
        op.create_table(
            "greybox_assets",
            _id(),
            _run_fk(),
            _str("kind", 16),
            _str("key", 600),
            _str("label", 300),
            sa.Column("parent_id", sa.Uuid(), sa.ForeignKey("greybox_assets.id"),
                      nullable=True),
            sa.Column("in_scope", sa.Boolean(), nullable=False),
            _bool("tested"),
            _int("finding_count"),
            _str("state", 16),
            _json("data"),
            _big("first_seen_seq"),
            _big("version"),
            _ts("created_at"),
            _ts("updated_at"),
            sa.UniqueConstraint("run_id", "kind", "key",
                                name="uq_greybox_assets_run_kind_key"),
        )
        op.create_index("ix_greybox_assets_run_version", "greybox_assets",
                        ["run_id", "version"])

    def asset_edges():
        op.create_table(
            "greybox_asset_edges",
            _id(),
            _run_fk(),
            sa.Column("src_id", sa.Uuid(),
                      sa.ForeignKey("greybox_assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("dst_id", sa.Uuid(),
                      sa.ForeignKey("greybox_assets.id", ondelete="CASCADE"), nullable=False),
            _str("rel", 16),
            _big("version"),
            sa.UniqueConstraint("run_id", "src_id", "rel", "dst_id",
                                name="uq_greybox_asset_edges_run_src_rel_dst"),
        )
        op.create_index("ix_greybox_asset_edges_run_version", "greybox_asset_edges",
                        ["run_id", "version"])

    def work_orders():
        op.create_table(
            "greybox_work_orders",
            _id(),
            _run_fk(),
            _str("dedup_key", 300),
            _str("kind", 16),
            _str("tool", 48),
            _str("title", 300),
            _str("reason", 500),
            _json("params"),
            _int("priority", default="50"),
            _str("status", 16),
            sa.Column("asset_id", sa.Uuid(),
                      sa.ForeignKey("greybox_assets.id", ondelete="SET NULL"), nullable=True),
            _uuid("node_id"),
            _uuid("parent_node_id"),
            _uuid("agent_id"),
            _str("lease_owner", 128, nullable=True),
            _ts("lease_expires_at", nullable=True),
            _int("attempts"),
            _int("max_attempts", default="2"),
            _str("result_summary", 500, nullable=True),
            _str("error", 1000, nullable=True),
            _big("created_seq"),
            _ts("created_at"),
            _ts("started_at", nullable=True),
            _ts("finished_at", nullable=True),
            sa.UniqueConstraint("run_id", "dedup_key", name="uq_greybox_work_orders_run_dedup"),
        )
        op.create_index("ix_greybox_work_orders_run_status_prio", "greybox_work_orders",
                        ["run_id", "status", "priority", "created_at"])

    def graph_nodes():
        op.create_table(
            "greybox_graph_nodes",
            _id(),
            _run_fk(),
            _str("kind", 16),
            _str("key", 300),
            _str("label", 300),
            _str("status", 16),
            _uuid("agent_id"),
            _uuid("work_order_id"),
            _uuid("finding_id"),
            _uuid("asset_id"),
            _big("event_seq", nullable=True),
            _json("data"),
            _big("version"),
            _ts("created_at"),
            _ts("updated_at"),
            sa.UniqueConstraint("run_id", "kind", "key",
                                name="uq_greybox_graph_nodes_run_kind_key"),
        )
        op.create_index("ix_greybox_graph_nodes_run_version", "greybox_graph_nodes",
                        ["run_id", "version"])

    def graph_edges():
        op.create_table(
            "greybox_graph_edges",
            _id(),
            _run_fk(),
            sa.Column("src_id", sa.Uuid(),
                      sa.ForeignKey("greybox_graph_nodes.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("dst_id", sa.Uuid(),
                      sa.ForeignKey("greybox_graph_nodes.id", ondelete="CASCADE"),
                      nullable=False),
            _str("rel", 16),
            _big("version"),
            sa.UniqueConstraint("run_id", "src_id", "rel", "dst_id",
                                name="uq_greybox_graph_edges_run_src_rel_dst"),
            sa.CheckConstraint("src_id <> dst_id", name="ck_greybox_graph_edges_no_self_loop"),
        )
        op.create_index("ix_greybox_graph_edges_run_version", "greybox_graph_edges",
                        ["run_id", "version"])

    def findings():
        op.create_table(
            "greybox_findings",
            _id(),
            _run_fk(),
            _str("dedup_key", 300),
            _str("check_id", 48),
            _str("title", 300),
            _str("severity", 16),
            _str("status", 16),
            _str("confidence", 8),
            sa.Column("description", sa.Text(), nullable=False),
            _json("location"),
            sa.Column("affected_asset_id", sa.Uuid(),
                      sa.ForeignKey("greybox_assets.id", ondelete="SET NULL"), nullable=True),
            _uuid("node_id"),
            _uuid("agent_id"),
            _uuid("work_order_id"),
            _json("evidence"),
            _json("verification", nullable=True),
            _json("detection_hints"),
            _json("references"),
            _str("cwe", 16, nullable=True),
            _big("first_event_seq"),
            _big("version"),
            _ts("created_at"),
            _ts("updated_at"),
            sa.UniqueConstraint("run_id", "dedup_key", name="uq_greybox_findings_run_dedup"),
        )
        op.create_index("ix_greybox_findings_run_version", "greybox_findings",
                        ["run_id", "version"])

    def events():
        op.create_table(
            "greybox_events",
            sa.Column("id", _BIGID, primary_key=True, autoincrement=True),
            _run_fk(),
            _big("seq"),
            _ts("ts"),
            _str("kind", 48),
            _str("level", 8),
            _str("source", 16),
            sa.Column("agent_id", sa.Uuid(),
                      sa.ForeignKey("greybox_agents.id", ondelete="SET NULL"), nullable=True),
            _uuid("work_order_id"),
            _str("tool_call_id", 36, nullable=True),
            _str("summary", 300),
            _str("status", 16, nullable=True),
            _int("duration_ms", nullable=True),
            _json("refs"),
            _json("data"),
            sa.UniqueConstraint("run_id", "seq", name="uq_greybox_events_run_seq"),
        )
        op.create_index("ix_greybox_events_run_kind_seq", "greybox_events",
                        ["run_id", "kind", "seq"])
        op.create_index("ix_greybox_events_run_agent_seq", "greybox_events",
                        ["run_id", "agent_id", "seq"])
        op.create_index("ix_greybox_events_run_wo_seq", "greybox_events",
                        ["run_id", "work_order_id", "seq"])

    def http_exchanges():
        op.create_table(
            "greybox_http_exchanges",
            sa.Column("id", _BIGID, primary_key=True, autoincrement=True),
            _run_fk(),
            _ts("ts"),
            _uuid("agent_id"),
            _uuid("work_order_id"),
            _str("tool", 48),
            _str("tool_call_id", 36, nullable=True),
            _str("method", 10),
            _str("url", 2000),
            _str("scheme", 8, nullable=True),
            _str("host", 255, nullable=True),
            _int("port", nullable=True),
            _str("path", 1000, nullable=True),
            _str("resolved_ip", 64, nullable=True),
            _int("status_code", nullable=True),
            _int("duration_ms", nullable=True),
            _json("request_headers"),
            sa.Column("request_body", sa.Text(), nullable=True),
            _bool("request_body_truncated"),
            _json("response_headers"),
            sa.Column("response_body", sa.Text(), nullable=True),
            _bool("response_body_truncated"),
            _int("response_size", nullable=True),
            _str("content_type", 200, nullable=True),
            _str("body_omitted_reason", 32, nullable=True),
            _bool("blocked"),
            _str("block_reason", 64, nullable=True),
            _str("error", 300, nullable=True),
            _int("redirect_hop"),
            _big("parent_exchange_id", nullable=True),
        )
        op.create_index("ix_greybox_http_exchanges_run_id", "greybox_http_exchanges",
                        ["run_id", "id"])

    def reports():
        op.create_table(
            "greybox_reports",
            sa.Column("run_id", sa.Uuid(),
                      sa.ForeignKey("greybox_runs.id", ondelete="CASCADE"), primary_key=True),
            _str("status", 16),
            sa.Column("markdown", sa.Text(), nullable=True),
            _str("error", 500, nullable=True),
            _ts("generated_at", nullable=True),
        )

    return [
        ("greybox_targets", targets),
        ("greybox_runs", runs),
        ("greybox_agents", agents),
        ("greybox_assets", assets),
        ("greybox_asset_edges", asset_edges),
        ("greybox_work_orders", work_orders),
        ("greybox_graph_nodes", graph_nodes),
        ("greybox_graph_edges", graph_edges),
        ("greybox_findings", findings),
        ("greybox_events", events),
        ("greybox_http_exchanges", http_exchanges),
        ("greybox_reports", reports),
    ]


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name, create in _tables():
        if name not in existing:
            create()


def downgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name, _ in reversed(_tables()):
        if name in existing:
            op.drop_table(name)
