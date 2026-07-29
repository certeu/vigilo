from __future__ import annotations


class TestSmoke:
    async def test_openapi_lists_core_routes(self, client):
        spec = (await client.get("/openapi.json")).json()
        paths = set(spec["paths"].keys())
        for p in ["/health", "/version", "/auth/jwt/login", "/users/me",
                  "/users", "/credentials", "/admin/config"]:
            assert p in paths, f"missing {p}"
