"""Generic forge field names (remote_url, forge_project_id, forge_base_url) and the
deprecated GitLab names the API keeps accepting."""
from __future__ import annotations

import uuid

import sqlalchemy as sa

from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


async def _h(client, session_maker):
    await _make_user(session_maker, "f@example.com", PW, "user")
    return {"Authorization": f"Bearer {await _token(client, 'f@example.com', PW)}"}


class TestRepositoryFields:
    async def test_new_names(self, client, session_maker):
        h = await _h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "r", "source_type": "gitlab", "remote_url": "https://gl.example/g/p.git",
            "forge_project_id": "42"})
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["forge"] == "gitlab"
        assert body["remote_url"] == body["gitlab_url"] == "https://gl.example/g/p.git"
        assert body["forge_project_id"] == body["gitlab_project_id"] == "42"

    async def test_deprecated_names_still_accepted(self, client, session_maker):
        h = await _h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "r", "source_type": "gitlab", "gitlab_url": "https://gl.example/g/p.git",
            "gitlab_project_id": "42"})
        assert r.status_code == 201, r.text
        assert r.json()["remote_url"] == "https://gl.example/g/p.git"
        assert r.json()["forge_project_id"] == "42"

    async def test_conflicting_old_and_new_name_is_422(self, client, session_maker):
        h = await _h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "r", "source_type": "gitlab", "remote_url": "https://gl.example/g/a.git",
            "gitlab_url": "https://gl.example/g/b.git"})
        assert r.status_code == 422, r.text

    async def test_forge_source_needs_a_url(self, client, session_maker):
        h = await _h(client, session_maker)
        for st in ("gitlab", "github"):
            r = await client.post("/repositories", headers=h, json={"name": "r", "source_type": st})
            assert r.status_code == 422, (st, r.text)

    async def test_upload_has_no_forge(self, client, session_maker):
        h = await _h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={"name": "u", "source_type": "upload"})
        assert r.status_code == 201 and r.json()["forge"] is None


class TestCredentialFields:
    async def test_deprecated_base_url_name(self, client, session_maker):
        h = await _h(client, session_maker)
        r = await client.post("/credentials", headers=h, json={
            "kind": "gitlab_token", "label": "t", "secret": "glpat-x",
            "gitlab_base_url": "https://gl.example"})
        assert r.status_code == 201, r.text
        assert r.json()["forge_base_url"] == r.json()["gitlab_base_url"] == "https://gl.example"

    async def test_new_base_url_name(self, client, session_maker):
        h = await _h(client, session_maker)
        r = await client.post("/credentials", headers=h, json={
            "kind": "gitlab_token", "label": "t", "secret": "glpat-x",
            "forge_base_url": "https://gl.example"})
        assert r.status_code == 201, r.text
        assert r.json()["forge_base_url"] == "https://gl.example"


class TestMigration0009:
    def _url(self, tmp_path):
        return f"sqlite:///{tmp_path}/forge.db"

    def _old_schema_with_data(self, tmp_path):
        """A database at 0008 that still has the GitLab column names, with data."""
        from alembic import command
        from scripts.run_migrations import build_config

        url = self._url(tmp_path)
        cfg = build_config(url)
        command.upgrade(cfg, "0008_run_secrets_job_cookie")
        eng = sa.create_engine(url)
        uid, rid, cid = (str(uuid.uuid4()) for _ in range(3))
        with eng.begin() as c:
            # the baseline is built from the current models: go back to the old names
            for table, old, new in (("repositories", "gitlab_url", "remote_url"),
                                    ("repositories", "gitlab_project_id", "forge_project_id"),
                                    ("credentials", "gitlab_base_url", "forge_base_url")):
                c.execute(sa.text(f"ALTER TABLE {table} RENAME COLUMN {new} TO {old}"))
            c.execute(sa.text(
                "INSERT INTO users (id,email,hashed_password,is_active,is_superuser,"
                "is_verified,role,created_at) VALUES (:i,'m@x.eu','h',1,0,1,'user',"
                "'2026-01-01')"), {"i": uid})
            c.execute(sa.text(
                "INSERT INTO credentials (id,owner_id,kind,label,secret_enc,gitlab_base_url,"
                "created_at) VALUES (:c,:u,'gitlab_token','t',x'00','https://gl.example',"
                "'2026-01-01')"), {"c": cid, "u": uid})
            c.execute(sa.text(
                "INSERT INTO repositories (id,created_by,name,source_type,gitlab_url,"
                "gitlab_project_id,pipeline_config,scan_config,is_private,upload_ready,"
                "push_patches,archived,ingestion_status,created_at) VALUES (:r,:u,'KEEP',"
                "'gitlab','https://gl.example/g/p.git','42','{}','{}',0,0,0,0,'ready',"
                "'2026-01-01')"), {"r": rid, "u": uid})
        return cfg, url

    def test_renames_columns_and_keeps_data(self, tmp_path):
        from alembic import command

        cfg, url = self._old_schema_with_data(tmp_path)
        command.upgrade(cfg, "head")
        eng = sa.create_engine(url)
        insp = sa.inspect(eng)
        repo_cols = {c["name"] for c in insp.get_columns("repositories")}
        cred_cols = {c["name"] for c in insp.get_columns("credentials")}
        assert {"remote_url", "forge_project_id"} <= repo_cols
        assert not {"gitlab_url", "gitlab_project_id"} & repo_cols
        assert "forge_base_url" in cred_cols and "gitlab_base_url" not in cred_cols
        with eng.connect() as c:
            assert c.execute(sa.text(
                "SELECT remote_url, forge_project_id FROM repositories")).one() == (
                "https://gl.example/g/p.git", "42")
            assert c.execute(sa.text("SELECT forge_base_url FROM credentials")).scalar() == (
                "https://gl.example")

    def test_copies_over_when_both_columns_exist(self, tmp_path):
        """0003 (schema sync) may have added the new column next to the old one."""
        from alembic import command

        cfg, url = self._old_schema_with_data(tmp_path)
        with sa.create_engine(url).begin() as c:
            c.execute(sa.text("ALTER TABLE repositories ADD COLUMN remote_url VARCHAR(500)"))
        command.upgrade(cfg, "head")
        eng = sa.create_engine(url)
        assert "gitlab_url" not in {c["name"] for c in sa.inspect(eng).get_columns("repositories")}
        with eng.connect() as c:
            assert c.execute(sa.text("SELECT remote_url FROM repositories")).scalar() == (
                "https://gl.example/g/p.git")

    def test_downgrade_restores_the_old_names(self, tmp_path):
        from alembic import command

        cfg, url = self._old_schema_with_data(tmp_path)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "0008_run_secrets_job_cookie")
        eng = sa.create_engine(url)
        assert "gitlab_url" in {c["name"] for c in sa.inspect(eng).get_columns("repositories")}
        with eng.connect() as c:
            assert c.execute(sa.text("SELECT gitlab_url FROM repositories")).scalar() == (
                "https://gl.example/g/p.git")
