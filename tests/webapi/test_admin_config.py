from __future__ import annotations


class TestAdminConfig:
    async def test_user_cannot_read(self, client, user_token):
        resp = await client.get("/admin/config",
                                headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 403

    async def test_admin_get_returns_defaults(self, client, admin_token):
        resp = await client.get("/admin/config",
                                headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        assert resp.json()["executor"] == "claude"

    async def test_admin_put_updates(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        resp = await client.put("/admin/config", headers=h,
                                json={"executor": "codex", "global_concurrent_run_cap": 4})
        assert resp.status_code == 200
        assert resp.json()["executor"] == "codex"
        again = await client.get("/admin/config", headers=h)
        assert again.json()["global_concurrent_run_cap"] == 4


class TestAdminConfigValidation:
    async def test_rejects_unknown_executor(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        r = await client.put("/admin/config", headers=h, json={"executor": "gpt"})
        assert r.status_code == 422

    async def test_rejects_bad_model_names(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        for bad in ("has space", "x" * 101):
            r = await client.put("/admin/config", headers=h, json={"model_large": bad})
            assert r.status_code == 422, bad

    async def test_empty_model_clears_to_worker_default(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        r = await client.put("/admin/config", headers=h, json={"model_large": "  "})
        assert r.status_code == 200 and r.json()["model_large"] == ""

    async def test_trims_and_normalizes(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        r = await client.put("/admin/config", headers=h,
                             json={"executor": " Codex ", "model_small": " gpt-5-mini "})
        assert r.status_code == 200
        assert r.json()["executor"] == "codex"
        assert r.json()["model_small"] == "gpt-5-mini"

    async def test_user_cannot_put(self, client, user_token):
        r = await client.put("/admin/config", headers={"Authorization": f"Bearer {user_token}"},
                             json={"executor": "codex"})
        assert r.status_code == 403

    async def test_model_defaults_for_any_user(self, client, user_token):
        r = await client.get("/config/models", headers={"Authorization": f"Bearer {user_token}"})
        assert r.status_code == 200
        assert set(r.json()) == {"executor", "model_small", "model_medium", "model_large",
                             "default_max_concurrent_pipelines"}
        assert isinstance(r.json()["default_max_concurrent_pipelines"], int)


    async def test_model_defaults_reflects_admin_concurrency(self, client, admin_token, user_token):
        r = await client.put("/admin/config", headers={"Authorization": f"Bearer {admin_token}"},
                             json={"default_max_concurrent_pipelines": 3})
        assert r.status_code == 200
        r2 = await client.get("/config/models", headers={"Authorization": f"Bearer {user_token}"})
        assert r2.status_code == 200
        assert r2.json()["default_max_concurrent_pipelines"] == 3


class TestExecutorStatus:
    async def test_admin_only(self, client, user_token):
        r = await client.get("/admin/executors/status",
                             headers={"Authorization": f"Bearer {user_token}"})
        assert r.status_code == 403

    async def test_presence_only_no_values(self, client, admin_token, monkeypatch):
        for v in ("ANTHROPIC_API_KEY", "CODEX_API_KEY", "OPENAI_API_KEY", "LITELLM_API_KEY",
                  "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_FOUNDRY"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("CODEX_BASE_URL", "http://gw.internal/v1")
        monkeypatch.setenv("CODEX_API_KEY", "sekrit-value")
        r = await client.get("/admin/executors/status",
                             headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert "sekrit-value" not in r.text and "gw.internal" not in r.text
        by = {e["executor"]: e for e in r.json()["executors"]}
        assert by["codex"]["configured"] is True
        assert by["claude"]["configured"] is False
        assert "ANTHROPIC_API_KEY" in by["claude"]["missing"]
        assert by["opencode"]["configured"] is False
