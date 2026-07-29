from __future__ import annotations


class TestSystem:
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_version(self, client):
        resp = await client.get("/version")
        assert resp.status_code == 200
        assert "version" in resp.json()
