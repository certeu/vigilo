import asyncio
import io
import json
import tarfile

from src.greybox_web.artifact import Reader
from src.greybox_web.tools import artifacts


def test_artifact_reader_and_secret_validation(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "prod.env").write_text("PASSWORD=Concrete-7qLm9X")
    (root / "example.env").write_text("PASSWORD=changeme")
    reader = Reader(root)
    rows = asyncio.run(reader(None))
    assert rows[0]["path"] == "example.env" or rows[0]["path"] == "prod.env"
    prod = asyncio.run(reader("prod.env"))
    assert prod["content"] == "PASSWORD=Concrete-7qLm9X"
    assert artifacts._SECRET.search(prod["content"])
    assert artifacts._SKIP.search("changeme")


def test_artifact_tool_produces_and_reverifies_evidence(tmp_path):
    from src.greybox_web.scope import ScopePolicy
    from src.greybox_web.tools import ToolContext

    root = tmp_path / "repo"
    root.mkdir()
    (root / "prod.env").write_text("PASSWORD=Concrete-7qLm9X")
    reader = Reader(root)
    ctx = ToolContext(http=None, base_url="http://127.0.0.1/", scope=ScopePolicy(("127.0.0.1",), ("http",), (80,), mode="artifact"), limits={}, params={"path":"prod.env"}, inventory=reader)
    result = asyncio.run(artifacts.inspect(ctx))
    assert len(result.findings) == 1 and result.findings[0].asset_ref == ("resource_type", "repository")
    vctx = ToolContext(http=None, base_url=ctx.base_url, scope=ctx.scope, limits={}, params={"path":"prod.env", "key":"PASSWORD"}, inventory=reader)
    assert asyncio.run(artifacts.verify(vctx)).confirmed


async def test_artifact_upload_api(client, user_token, set_env, tmp_path):
    import io
    import tarfile

    set_env("VIGILO_UPLOADS_DIR", str(tmp_path / "uploads"))
    target = (await client.post("/greybox/targets", headers={"Authorization": f"Bearer {user_token}"}, json={"name":"repo", "base_url":"http://artifact.example.test/", "assessment_mode":"artifact"})).json()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"PASSWORD=Concrete-7qLm9X\n"
        info = tarfile.TarInfo("config/prod.env")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    response = await client.post(f"/greybox/targets/{target['id']}/artifact", headers={"Authorization": f"Bearer {user_token}"}, files={"file": ("repo.tar.gz", buf.getvalue(), "application/gzip")})
    assert response.status_code == 201 and response.json()["files"] == 1
    assert (tmp_path / "uploads" / "greybox-artifacts" / target["id"] / "prod.env").is_file()


def test_artifact_verification_spec_does_not_add_http_url():
    import uuid
    from src.greybox_web.planner import NewFinding, verification_specs

    spec = verification_specs([NewFinding(
        id=uuid.uuid4(), check_id="artifact.inspect", dedup_key="artifact.inspect|repo|PASSWORD",
        verify={"path": "prod.env", "key": "PASSWORD"},
    )])[0]
    assert spec.params.keys() == {"finding_id", "path", "key"}
