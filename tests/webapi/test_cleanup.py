from __future__ import annotations

import os


class TestCleanup:
    def test_removes_source_keeps_vigilo(self, monkeypatch, tmp_path):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_JOBS_DATA_DIR", str(tmp_path / "jobs"))
        settings_mod.get_settings.cache_clear()
        from src.webapi.cleanup import cleanup_run_source

        data_dir = tmp_path / "jobs" / "run-1"
        repo = data_dir / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "app.py").write_text("x=1")
        (repo / "requirements.txt").write_text("flask")
        deliverables = repo / ".vigilo" / "sess" / "deliverables"
        deliverables.mkdir(parents=True)
        (deliverables / "report_stats.json").write_text("{}")

        assert cleanup_run_source(str(data_dir)) is True
        # source gone, .vigilo (report) preserved
        assert not (repo / "src").exists()
        assert not (repo / "requirements.txt").exists()
        assert (deliverables / "report_stats.json").exists()
        # idempotent: second call finds nothing to clean
        assert cleanup_run_source(str(data_dir)) is False
        settings_mod.get_settings.cache_clear()

    def test_refuses_outside_jobs_dir(self, monkeypatch, tmp_path):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_JOBS_DATA_DIR", str(tmp_path / "jobs"))
        settings_mod.get_settings.cache_clear()
        from src.webapi.cleanup import cleanup_run_source

        outside = tmp_path / "elsewhere"
        (outside / "repo").mkdir(parents=True)
        (outside / "repo" / "keep.txt").write_text("important")
        assert cleanup_run_source(str(outside)) is False
        assert (outside / "repo" / "keep.txt").exists()  # untouched
        settings_mod.get_settings.cache_clear()
