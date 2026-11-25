from __future__ import annotations

import sqlalchemy as sa


def _migration_head(cfg):
    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(cfg).get_heads()
    assert len(heads) == 1, f"expected a linear migration history, found {heads}"
    return heads[0]


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
        assert ver == _migration_head(cfg)

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


class TestRunSecretsMigration:
    def test_0008_creates_table_and_job_column_and_is_reversible(self, tmp_path):
        from scripts.run_migrations import build_config
        from alembic import command

        url = _url(tmp_path)
        cfg = build_config(url)
        command.upgrade(cfg, "head")
        insp = sa.inspect(sa.create_engine(url))
        assert "run_secrets" in insp.get_table_names()
        assert {"run_id", "key_hash", "secret_enc", "expires_at", "redeem_count"} <= {
            c["name"] for c in insp.get_columns("run_secrets")}
        assert "target_credential_id" in {c["name"] for c in insp.get_columns("jobs")}

        command.downgrade(cfg, "0007_job_notify_email")
        insp = sa.inspect(sa.create_engine(url))
        assert "run_secrets" not in insp.get_table_names()
        assert "target_credential_id" not in {c["name"] for c in insp.get_columns("jobs")}
        command.upgrade(cfg, "head")   # and forward again
        assert "run_secrets" in sa.inspect(sa.create_engine(url)).get_table_names()

    def test_0008_adds_the_column_to_a_populated_0007_database(self, tmp_path):
        from scripts.run_migrations import build_config
        from alembic import command

        url = _url(tmp_path)
        cfg = build_config(url)
        command.upgrade(cfg, "0007_job_notify_email")
        eng = sa.create_engine(url)
        with eng.begin() as c:   # simulate a DB created before 0008 (0003 already ran on old models)
            c.execute(sa.text("DROP TABLE IF EXISTS run_secrets"))
            try:
                c.execute(sa.text("ALTER TABLE jobs DROP COLUMN target_credential_id"))
            except Exception:
                pass
        command.upgrade(cfg, "head")
        insp = sa.inspect(sa.create_engine(url))
        assert "run_secrets" in insp.get_table_names()
        assert "target_credential_id" in {c["name"] for c in insp.get_columns("jobs")}


class TestGreyboxWebMigration:
    """0009_greybox_web: all grey-box tables, reversible, matching the ORM models."""

    def _greybox_tables(self, url):
        return {t for t in sa.inspect(sa.create_engine(url)).get_table_names()
                if t.startswith("greybox_")
                and t != "greybox_egress_proxies"}   # 0016, outside GREYBOX_TABLES

    def test_0009_upgrade_downgrade_upgrade(self, tmp_path):
        from scripts.run_migrations import build_config
        from alembic import command
        from src.greybox_web.models import GREYBOX_TABLES

        url = _url(tmp_path)
        cfg = build_config(url)
        command.upgrade(cfg, "head")
        assert self._greybox_tables(url) == set(GREYBOX_TABLES)

        command.downgrade(cfg, "0008_run_secrets_job_cookie")
        assert self._greybox_tables(url) == set()
        insp = sa.inspect(sa.create_engine(url))
        # white-box tables untouched by the downgrade
        assert {"users", "repositories", "jobs", "runs", "run_secrets",
                "credentials"} <= set(insp.get_table_names())

        command.upgrade(cfg, "head")   # created by 0009 itself this time (not 0003)
        assert self._greybox_tables(url) == set(GREYBOX_TABLES)
        with sa.create_engine(url).connect() as c:
            ver = c.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()
        assert ver == _migration_head(cfg)

    def test_0009_schema_matches_models(self, tmp_path):
        """The hand-written migration and the ORM models must not drift."""
        from scripts.run_migrations import build_config
        from alembic import command
        from src.webapi.db import Base
        import src.webapi.models  # noqa: F401
        from src.greybox_web.models import GREYBOX_TABLES

        url = _url(tmp_path)
        cfg = build_config(url)
        command.upgrade(cfg, "0008_run_secrets_job_cookie")
        eng = sa.create_engine(url)
        with eng.begin() as c:   # make sure 0009 (not 0003) creates the tables
            for t in reversed(GREYBOX_TABLES):
                c.execute(sa.text(f"DROP TABLE IF EXISTS {t}"))
        command.upgrade(cfg, "head")
        insp = sa.inspect(sa.create_engine(url))
        for name in GREYBOX_TABLES:
            model = Base.metadata.tables[name]
            cols = {c["name"]: c for c in insp.get_columns(name)}
            assert set(cols) == {c.name for c in model.columns}, name
            for col in model.columns:
                assert bool(cols[col.name]["nullable"]) == bool(col.nullable), (name, col.name)
            uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints(name)}
            want_uniques = {tuple(c.name for c in u.columns) for u in model.constraints
                            if isinstance(u, sa.UniqueConstraint)}
            assert uniques == want_uniques, name
            idx = {tuple(i["column_names"]) for i in insp.get_indexes(name)}
            want_idx = {tuple(c.name for c in i.columns) for i in model.indexes}
            assert idx == want_idx, name
            fks = {(tuple(f["constrained_columns"]), f["referred_table"])
                   for f in insp.get_foreign_keys(name)}
            want_fks = {((fk.parent.name,), fk.column.table.name)
                        for fk in model.foreign_keys}
            assert fks == want_fks, name
