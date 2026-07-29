from __future__ import annotations

from src.webapi.settings import Settings, get_settings


class TestSettings:
    def test_reads_from_env(self, monkeypatch):
        monkeypatch.setenv("VIGILO_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
        monkeypatch.setenv("VIGILO_JWT_SECRET", "s3cret")
        monkeypatch.setenv("VIGILO_FERNET_KEY", "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWZlcm5ldC0xMg==")
        get_settings.cache_clear()
        s = get_settings()
        assert s.database_url == "sqlite+aiosqlite:///:memory:"
        assert s.jwt_secret == "s3cret"
        assert s.jwt_lifetime_seconds == 3600  # default
        get_settings.cache_clear()

    def test_defaults(self, monkeypatch):
        monkeypatch.setenv("VIGILO_JWT_SECRET", "x")
        monkeypatch.setenv("VIGILO_FERNET_KEY", "y")
        get_settings.cache_clear()
        s = get_settings()
        assert s.serve_ui is False
        assert s.first_admin_email is None
        get_settings.cache_clear()
