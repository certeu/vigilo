"""Report screenshots: ``GET /runs/{id}/files/screenshots/...`` and ``open_report_image``.

The report references its evidence relatively (``screenshots/x.png``); the UI fetches
those through this endpoint with the normal Bearer header. Agents control the
workspace, so the endpoint must:

- serve only raster images under ``deliverables/screenshots/`` (SVG/HTML could run
  script on the API origin);
- never follow a symlink anywhere below the run's data dir;
- authenticate like every other route (Bearer only, no ``?token=`` that would end up
  in access logs) and enforce run access.
"""
from __future__ import annotations

import os
import uuid

import pytest

from src.webapi.models import User
from src.webapi.reports import (
    REPORT_FILENAME,
    REPORT_IMAGE_TYPES,
    deliverables_dir,
    open_report_image,
)
from tests.webapi.test_reports import _repo_job_run, _write_report

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
SESSION = "web-test"


def _shots_dir(data_dir: str, session_id: str) -> str:
    return os.path.join(deliverables_dir(data_dir, session_id), "screenshots")


def _write_screenshot(data_dir: str, session_id: str, rel: str, data: bytes = PNG) -> str:
    path = os.path.join(_shots_dir(data_dir, session_id), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _open(data_dir, rel: str) -> tuple[bytes, str] | None:
    opened = open_report_image(str(data_dir), SESSION, rel)
    if opened is None:
        return None
    fh, media_type = opened
    with fh:
        return fh.read(), media_type


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------ open_report_image (unit)


class TestOpenReportImage:
    @pytest.mark.parametrize("name, media_type", [
        ("a.png", "image/png"),
        ("a.jpg", "image/jpeg"),
        ("a.jpeg", "image/jpeg"),
        ("a.gif", "image/gif"),
        ("a.webp", "image/webp"),
        ("UPPER.PNG", "image/png"),
    ])
    def test_raster_types(self, tmp_path, name, media_type):
        _write_screenshot(str(tmp_path), SESSION, name)
        assert _open(tmp_path, f"screenshots/{name}") == (PNG, media_type)

    def test_allowlist_is_raster_only(self):
        assert set(REPORT_IMAGE_TYPES.values()) <= {"image/png", "image/jpeg", "image/gif", "image/webp"}

    @pytest.mark.parametrize("rel", [
        "./screenshots/x.png",
        "screenshots//x.png",
        "screenshots/./x.png",
    ])
    def test_harmless_path_variants(self, tmp_path, rel):
        _write_screenshot(str(tmp_path), SESSION, "x.png")
        assert _open(tmp_path, rel) == (PNG, "image/png")

    def test_nested_and_unusual_names(self, tmp_path):
        for rel in ("sub/dir/x.png", "xss alert.png", "café #1?.png"):
            _write_screenshot(str(tmp_path), SESSION, rel)
            assert _open(tmp_path, f"screenshots/{rel}") == (PNG, "image/png"), rel

    @pytest.mark.parametrize("name", [
        "poc.svg", "poc.html", "poc.htm", "poc.js", "notes.txt", "noext", "x.png.html",
    ])
    def test_non_raster_refused(self, tmp_path, name):
        _write_screenshot(str(tmp_path), SESSION, name, b"<script>alert(1)</script>")
        assert _open(tmp_path, f"screenshots/{name}") is None

    @pytest.mark.parametrize("rel", [
        "",
        "/",
        "screenshots",
        "screenshots/",
        "x.png",                          # deliverables root, not screenshots/
        REPORT_FILENAME,
        "other/x.png",
        "screenshots/../x.png",
        "screenshots/sub/../../x.png",
        "../screenshots/x.png",
        "/screenshots/../../x.png",
        "screenshots/x.png\0.png",
    ])
    def test_paths_outside_screenshots_refused(self, tmp_path, rel):
        _write_screenshot(str(tmp_path), SESSION, "x.png")
        d = deliverables_dir(str(tmp_path), SESSION)
        with open(os.path.join(d, "x.png"), "wb") as fh:
            fh.write(PNG)
        os.makedirs(os.path.join(d, "other"))
        with open(os.path.join(d, "other", "x.png"), "wb") as fh:
            fh.write(PNG)
        assert _open(tmp_path, rel) is None

    def test_missing_file(self, tmp_path):
        assert _open(tmp_path, "screenshots/missing.png") is None
        os.makedirs(_shots_dir(str(tmp_path), SESSION))
        assert _open(tmp_path, "screenshots/missing.png") is None

    def test_directory_named_like_an_image(self, tmp_path):
        os.makedirs(os.path.join(_shots_dir(str(tmp_path), SESSION), "x.png"))
        assert _open(tmp_path, "screenshots/x.png") is None

    def test_fifo_refused_without_blocking(self, tmp_path):
        d = _shots_dir(str(tmp_path), SESSION)
        os.makedirs(d)
        os.mkfifo(os.path.join(d, "x.png"))
        assert _open(tmp_path, "screenshots/x.png") is None


class TestOpenReportImageSymlinks:
    """Every level below data_dir is agent-controlled: none may be a symlink."""

    @pytest.fixture
    def outside(self, tmp_path):
        """A tree outside the run holding a screenshots/x.png with secret bytes."""
        root = tmp_path / "outside"
        (root / "screenshots").mkdir(parents=True)
        (root / "screenshots" / "x.png").write_bytes(b"secret-bytes")
        (root / "deliverables" / "screenshots").mkdir(parents=True)
        (root / "deliverables" / "screenshots" / "x.png").write_bytes(b"secret-bytes")
        return root

    @pytest.fixture
    def data_dir(self, tmp_path):
        d = tmp_path / "run"
        d.mkdir()
        return d

    def test_symlinked_file(self, data_dir, outside):
        d = _shots_dir(str(data_dir), SESSION)
        os.makedirs(d)
        os.symlink(outside / "screenshots" / "x.png", os.path.join(d, "x.png"))
        assert _open(data_dir, "screenshots/x.png") is None

    def test_symlink_to_image_inside_the_run(self, data_dir):
        real = _write_screenshot(str(data_dir), SESSION, "real.png")
        os.symlink(real, os.path.join(os.path.dirname(real), "alias.png"))
        assert _open(data_dir, "screenshots/real.png") == (PNG, "image/png")
        assert _open(data_dir, "screenshots/alias.png") is None

    def test_symlinked_screenshots_dir(self, data_dir, outside):
        d = deliverables_dir(str(data_dir), SESSION)
        os.makedirs(d)
        os.symlink(outside / "screenshots", os.path.join(d, "screenshots"))
        assert _open(data_dir, "screenshots/x.png") is None

    def test_symlinked_deliverables_dir(self, data_dir, outside):
        d = deliverables_dir(str(data_dir), SESSION)
        os.makedirs(os.path.dirname(d))
        os.symlink(outside, d)
        assert _open(data_dir, "screenshots/x.png") is None

    def test_symlinked_session_dir(self, data_dir, outside):
        session_dir = os.path.dirname(deliverables_dir(str(data_dir), SESSION))
        os.makedirs(os.path.dirname(session_dir))
        os.symlink(outside, session_dir)
        assert _open(data_dir, "screenshots/x.png") is None

    def test_symlinked_repo_dir(self, data_dir, tmp_path):
        other = tmp_path / "other-run"
        _write_screenshot(str(other), SESSION, "x.png", b"secret-bytes")
        os.symlink(other / "repo", data_dir / "repo")
        assert _open(data_dir, "screenshots/x.png") is None


# ------------------------------------------------------------------ endpoint (API)


def _data_dir(run: dict) -> str:
    from src.webapi.settings import get_settings
    return os.path.join(get_settings().jobs_data_dir, run["id"])


def _url(run: dict, rel: str) -> str:
    return f"/runs/{run['id']}/files/{rel}"


async def _private_run(client, token: str) -> dict:
    h = _bearer(token)
    repo = (await client.post("/repositories", headers=h, json={
        "name": "private", "source_type": "upload", "is_private": True})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
    return (await client.post(f"/jobs/{job['id']}/run", headers=h)).json()


class TestEndpointServing:
    async def test_png_served_with_safe_headers(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        r = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(user_token))
        assert r.status_code == 200
        assert r.content == PNG
        assert r.headers["content-type"] == "image/png"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "no-store" in r.headers["cache-control"]
        assert "attachment" not in r.headers.get("content-disposition", "")

    async def test_jpeg_media_type(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.jpg")
        r = await client.get(_url(run, "screenshots/x.jpg"), headers=_bearer(user_token))
        assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"

    @pytest.mark.parametrize("name, encoded", [
        ("xss alert.png", "xss%20alert.png"),
        ("café #1?.png", "caf%C3%A9%20%231%3F.png"),
        ("100%.png", "100%25.png"),
    ])
    async def test_percent_encoded_names(self, client, user_token, name, encoded):
        """The UI encodes each segment once; the server must decode it once."""
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], name)
        r = await client.get(_url(run, f"screenshots/{encoded}"), headers=_bearer(user_token))
        assert r.status_code == 200 and r.content == PNG

    async def test_double_encoded_name_is_not_found(self, client, user_token):
        """Regression: the first version requested xss%2520alert.png for xss%20alert.png."""
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "xss alert.png")
        r = await client.get(_url(run, "screenshots/xss%2520alert.png"), headers=_bearer(user_token))
        assert r.status_code == 404

    async def test_nested_screenshot(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "VG-004/step 1.png")
        r = await client.get(_url(run, "screenshots/VG-004/step%201.png"), headers=_bearer(user_token))
        assert r.status_code == 200 and r.content == PNG

    async def test_large_file_streamed_completely(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        data = PNG + os.urandom(300 * 1024)  # several 64 KiB chunks
        _write_screenshot(_data_dir(run), run["session_id"], "big.png", data)
        r = await client.get(_url(run, "screenshots/big.png"), headers=_bearer(user_token))
        assert r.status_code == 200 and r.content == data

    @pytest.mark.parametrize("rel", [
        "screenshots/poc.svg",
        "screenshots/poc.html",
        REPORT_FILENAME,
        "findings_index.json",
        "screenshots/missing.png",
        "screenshots",
        "screenshots/%2e%2e/" + REPORT_FILENAME,
        "screenshots/..%2F" + REPORT_FILENAME,
        "screenshots%2F..%2F..%2F..%2F..%2Fsecret.png",
    ])
    async def test_not_served(self, client, user_token, rel):
        run = await _repo_job_run(client, user_token)
        data_dir = _data_dir(run)
        _write_screenshot(data_dir, run["session_id"], "poc.svg", b"<svg onload=alert(1)>")
        _write_screenshot(data_dir, run["session_id"], "poc.html", b"<script>alert(1)</script>")
        _write_report(data_dir, run["session_id"], "# secret report")
        with open(os.path.join(deliverables_dir(data_dir, run["session_id"]), "findings_index.json"), "w") as fh:
            fh.write("{}")
        with open(os.path.join(data_dir, "secret.png"), "wb") as fh:
            fh.write(b"secret-bytes")
        r = await client.get(_url(run, rel), headers=_bearer(user_token))
        assert r.status_code == 404, rel
        assert b"secret" not in r.content and b"alert" not in r.content

    async def test_symlinked_deliverables_not_served(self, client, user_token, tmp_path):
        """The original bug: a symlinked deliverables/ exposed files outside the run."""
        run = await _repo_job_run(client, user_token)
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "screenshots").mkdir(parents=True)
        (elsewhere / "screenshots" / "x.png").write_bytes(b"secret-bytes")
        d = deliverables_dir(_data_dir(run), run["session_id"])
        os.makedirs(os.path.dirname(d))
        os.symlink(elsewhere, d)
        r = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(user_token))
        assert r.status_code == 404 and b"secret-bytes" not in r.content

    async def test_symlinked_screenshot_not_served(self, client, user_token, tmp_path):
        run = await _repo_job_run(client, user_token)
        secret = tmp_path / "secret.png"
        secret.write_bytes(b"secret-bytes")
        d = _shots_dir(_data_dir(run), run["session_id"])
        os.makedirs(d)
        os.symlink(secret, os.path.join(d, "x.png"))
        r = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(user_token))
        assert r.status_code == 404 and b"secret-bytes" not in r.content


class TestEndpointAuth:
    async def test_no_credentials(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        assert (await client.get(_url(run, "screenshots/x.png"))).status_code == 401

    async def test_query_token_is_not_accepted(self, client, user_token):
        """The JWT must never travel in the URL (it would be written to access logs)."""
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        r = await client.get(_url(run, "screenshots/x.png"), params={"token": user_token})
        assert r.status_code == 401

    def test_openapi_has_no_token_parameter(self, client):
        spec = client._app.openapi()
        op = spec["paths"]["/runs/{run_id}/files/{rel_path}"]["get"]
        names = {p["name"] for p in op.get("parameters", [])}
        assert names == {"run_id", "rel_path"}

    async def test_invalid_bearer(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        r = await client.get(_url(run, "screenshots/x.png"), headers=_bearer("not-a-jwt"))
        assert r.status_code == 401

    async def test_token_revoked_by_password_change(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        resp = await client.post("/users/me/change-password", headers=_bearer(user_token), json={
            "current_password": "userpass123", "new_password": "A-much-Stronger-pass-42!"})
        assert resp.status_code == 200, resp.text
        fresh = resp.json()["access_token"]
        old = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(user_token))
        assert old.status_code == 401
        new = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(fresh))
        assert new.status_code == 200

    async def test_deactivated_user(self, client, user_token, session_maker):
        run = await _repo_job_run(client, user_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        from sqlalchemy import update
        async with session_maker() as s:
            await s.execute(update(User).where(User.email == "user@example.com").values(is_active=False))
            await s.commit()
        r = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(user_token))
        assert r.status_code == 401


class TestEndpointAccess:
    async def test_private_run_owner_and_admin_only(self, client, session_maker, admin_token):
        from tests.webapi.conftest import _make_user, _token
        await _make_user(session_maker, "owner@example.com", "ownerpass123", "user")
        await _make_user(session_maker, "other@example.com", "otherpass123", "user")
        owner = await _token(client, "owner@example.com", "ownerpass123")
        other = await _token(client, "other@example.com", "otherpass123")
        run = await _private_run(client, owner)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        url = _url(run, "screenshots/x.png")
        assert (await client.get(url, headers=_bearer(owner))).status_code == 200
        assert (await client.get(url, headers=_bearer(admin_token))).status_code == 200
        denied = await client.get(url, headers=_bearer(other))
        assert denied.status_code in (403, 404) and denied.content != PNG

    async def test_same_access_as_report_endpoint(self, client, session_maker, admin_token, user_token):
        """Whoever can read the report can see its screenshots, and nobody else."""
        run = await _private_run(client, admin_token)
        _write_screenshot(_data_dir(run), run["session_id"], "x.png")
        _write_report(_data_dir(run), run["session_id"], "# r")
        for token in (admin_token, user_token):
            report = await client.get(f"/runs/{run['id']}/report", headers=_bearer(token))
            shot = await client.get(_url(run, "screenshots/x.png"), headers=_bearer(token))
            assert (report.status_code == 200) == (shot.status_code == 200)

    async def test_unknown_run(self, client, user_token):
        r = await client.get(f"/runs/{uuid.uuid4()}/files/screenshots/x.png", headers=_bearer(user_token))
        assert r.status_code == 404

    async def test_malformed_run_id(self, client, user_token):
        r = await client.get("/runs/not-a-uuid/files/screenshots/x.png", headers=_bearer(user_token))
        assert r.status_code == 422
