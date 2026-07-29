from __future__ import annotations

import sqlalchemy as sa


def _url(tmp_path):
    return f"sqlite:///{tmp_path}/mig.db"


class TestMigrations:
    def test_upgrade_creates_schema_and_stamps_head(self, tmp_path):
        from scripts.run_migrations import build_config
        from alembic import command

        cfg = build_config(_url(tmp_path))
        command.upgrade(cfg, "head")

        eng = sa.create_engine(_url(tmp_path))
        insp = sa.inspect(eng)
        tables = set(insp.get_table_names())
        # core tables + alembic bookkeeping
        assert {"users", "repositories", "jobs", "runs", "alembic_version"} <= tables
        # 0002 added the archived column
        cols = {c["name"] for c in insp.get_columns("repositories")}
        assert "archived" in cols
        with eng.connect() as c:
            ver = c.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
        assert ver == "0007_job_notify_email"

    def test_upgrade_is_idempotent(self, tmp_path):
        from scripts.run_migrations import build_config
        from alembic import command
        cfg = build_config(_url(tmp_path))
        command.upgrade(cfg, "head")
        command.upgrade(cfg, "head")  # second run must be a no-op, not an error

    def test_downgrade_reverts_version(self, tmp_path):
        from scripts.run_migrations import build_config
        from alembic import command
        cfg = build_config(_url(tmp_path))
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "0001_baseline")  # additive reconcile: no-op reverse
        eng = sa.create_engine(_url(tmp_path))
        with eng.connect() as c:
            ver = c.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
        assert ver == "0001_baseline"

    def test_baseline_then_incremental_on_existing_data(self, tmp_path):
        """The scenario that matters: an existing populated DB takes 0002."""
        from scripts.run_migrations import build_config
        from alembic import command
        import uuid
        url = _url(tmp_path)
        cfg = build_config(url)
        command.upgrade(cfg, "0001_baseline")  # existing DB at baseline
        eng = sa.create_engine(url)
        # simulate an older DB missing the archived column + holding data
        with eng.begin() as c:
            c.execute(sa.text("ALTER TABLE repositories DROP COLUMN archived"))
            uid = str(uuid.uuid4())
            c.execute(sa.text(
                "INSERT INTO users (id,email,hashed_password,is_active,is_superuser,"
                "is_verified,role,created_at) VALUES (:i,'k@x.eu','h',1,0,1,'user',"
                "'2026-01-01')"), {"i": uid})
            c.execute(sa.text(
                "INSERT INTO repositories (id,created_by,name,source_type,"
                "pipeline_config,scan_config,is_private,upload_ready,push_patches,"
                "created_at) VALUES (:r,:u,'KEEP','upload','{}','{}',0,0,0,'2026-01-01')"),
                {"r": str(uuid.uuid4()), "u": uid})
        # upgrade the populated DB
        command.upgrade(cfg, "head")
        with sa.create_engine(url).connect() as c:
            cols = {x["name"] for x in sa.inspect(c.engine).get_columns("repositories")}
            name = c.execute(sa.text("SELECT name FROM repositories")).scalar()
            archived = c.execute(sa.text("SELECT archived FROM repositories")).scalar()
        assert "archived" in cols          # column added
        assert name == "KEEP"              # existing data preserved
        assert archived in (0, False)      # defaulted
