from __future__ import annotations

import os
import subprocess
import zipfile

import pytest

from src.webapi.ingestion import (
    REMOTE_MARKER,
    build_clone_url,
    clone_repo,
    extract_archive,
    prepare_repo,
    write_remote_marker,
)


def _make_zip(path, files: dict[str, str]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)


class TestExtractArchive:
    def test_extract_zip(self, tmp_path):
        archive = tmp_path / "src.zip"
        _make_zip(archive, {"app.py": "print(1)", "sub/x.txt": "hi"})
        dest = tmp_path / "repo"
        extract_archive(str(archive), str(dest))
        assert (dest / "app.py").read_text() == "print(1)"
        assert (dest / "sub" / "x.txt").read_text() == "hi"

    def test_zip_traversal_rejected(self, tmp_path):
        archive = tmp_path / "evil.zip"
        _make_zip(archive, {"../escape.txt": "nope"})
        with pytest.raises(ValueError):
            extract_archive(str(archive), str(tmp_path / "repo"))

    def test_unsupported_type(self, tmp_path):
        bad = tmp_path / "x.rar"
        bad.write_text("nope")
        with pytest.raises(ValueError):
            extract_archive(str(bad), str(tmp_path / "repo"))

    def test_strips_single_wrapper_dir(self, tmp_path):
        # macOS Finder / GitHub tarballs nest content under one wrapper dir; it must
        # be descended so the source lands at the repo root, not one level too deep.
        archive = tmp_path / "wrapped.zip"
        _make_zip(archive, {"proj/app.py": "print(1)", "proj/sub/x.txt": "hi"})
        dest = tmp_path / "repo"
        extract_archive(str(archive), str(dest))
        assert (dest / "app.py").read_text() == "print(1)"
        assert (dest / "sub" / "x.txt").read_text() == "hi"
        assert not (dest / "proj").exists()

    def test_drops_macosx_sidecar(self, tmp_path):
        archive = tmp_path / "finder.zip"
        _make_zip(archive, {"proj/app.py": "x=1", "__MACOSX/._app.py": "junk"})
        dest = tmp_path / "repo"
        extract_archive(str(archive), str(dest))
        assert (dest / "app.py").exists()
        assert not (dest / "__MACOSX").exists()

    def test_keeps_multiple_top_level_entries(self, tmp_path):
        # More than one top-level entry => not a wrapper, keep the layout as-is.
        archive = tmp_path / "flat.zip"
        _make_zip(archive, {"a.py": "1", "b/c.py": "2"})
        dest = tmp_path / "repo"
        extract_archive(str(archive), str(dest))
        assert (dest / "a.py").exists() and (dest / "b" / "c.py").exists()


class TestCloneUrl:
    def test_token_injected(self):
        url = build_clone_url("https://gitlab.internal/group/proj.git", "glpat-secret")
        assert url == "https://oauth2:glpat-secret@gitlab.internal/group/proj.git"

    def test_preserves_port_and_path(self):
        url = build_clone_url("https://gl.example:8443/a/b.git", "tok")
        assert url == "https://oauth2:tok@gl.example:8443/a/b.git"


class TestCloneRepo:
    def test_clone_local_repo(self, tmp_path):
        # Create a real source repo to clone from (git available in CI/dev).
        origin = tmp_path / "origin"
        origin.mkdir()
        subprocess.run(["git", "init", "-q", str(origin)], check=True)
        (origin / "README.md").write_text("hello")
        subprocess.run(["git", "-C", str(origin), "add", "."], check=True)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", "-C", str(origin), "commit", "-qm", "init"],
                       check=True, env=env)
        dest = tmp_path / "clone"
        clone_repo(f"file://{origin}", str(dest))
        assert (dest / "README.md").read_text() == "hello"

    def test_clone_failure_scrubs_url(self, tmp_path):
        def fake_runner(cmd, capture_output, text, env=None):
            class R:
                returncode = 1
                stderr = f"fatal: could not read {cmd[-2]}"
            return R()
        with pytest.raises(RuntimeError) as ei:
            clone_repo("https://oauth2:SECRET@gl/x.git", str(tmp_path / "d"),
                       runner=fake_runner)
        assert "SECRET" not in str(ei.value)
        assert "<clone-url>" in str(ei.value)


class TestPrepareRepo:
    def test_prepare_upload(self, tmp_path):
        archive = tmp_path / "s.zip"
        _make_zip(archive, {"main.py": "x=1"})
        repo_dir = tmp_path / "run" / "repo"
        prepare_repo(source_type="upload", repo_dir=str(repo_dir),
                     upload_path=str(archive))
        assert (repo_dir / "main.py").exists()

    def test_marker_has_no_token(self, tmp_path):
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        write_remote_marker(str(repo_dir), "https://gitlab.internal/g/p.git")
        content = (repo_dir / REMOTE_MARKER).read_text()
        assert content.strip() == "https://gitlab.internal/g/p.git"
        assert "oauth2" not in content and "@" not in content
