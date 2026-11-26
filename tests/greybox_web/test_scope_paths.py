"""excluded_paths / path_prefixes must hold against path parameters (``;x``) that
servers such as Tomcat strip before routing."""
from __future__ import annotations

import pytest

from src.greybox_web.scope import ScopePolicy, normalise_path

SCOPE = ScopePolicy.from_dict({
    "allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
    "allowed_ports": [43123], "path_prefixes": ["/app"],
    "excluded_paths": ["/app/admin"], "redirect_policy": "in_scope",
    "allow_auth_testing": False,
})


@pytest.mark.parametrize("raw,expected", [
    ("/app;/../admin", "/admin"),
    ("/app/a/..;/admin", "/app/admin"),
    ("/app/admin;jsessionid=1", "/app/admin"),
    ("/app;x=1/admin", "/app/admin"),
    ("/app/;/admin", "/app/admin"),
    ("/app/a;b/../admin", "/app/admin"),
    ("/app/./admin", "/app/admin"),
    ("/app/x;", "/app/x"),
    ("/app/", "/app/"),
    ("/app/x/..", "/app/"),
])
def test_normalise_path_strips_path_params(raw, expected):
    assert normalise_path(raw) == expected


@pytest.mark.parametrize("path,allowed,reason", [
    ("/app/admin", False, "path_excluded"),
    ("/app/a/..;/admin", False, "path_excluded"),
    ("/app/admin;x=1", False, "path_excluded"),
    ("/app;x=1/admin", False, "path_excluded"),
    ("/app/%2e%2e;/admin", False, "path_not_in_scope"),
    ("/app;/../admin", False, "path_not_in_scope"),   # resolves to /admin
    ("/app/home;jsessionid=abc", True, None),
    ("/app/a/../home", True, None),
])
def test_check_url_with_path_parameters(path, allowed, reason):
    d = SCOPE.check_url(f"http://127.0.0.1:43123{path}")
    assert d.allowed is allowed
    assert d.reason == reason
