"""White-box repository URL SSRF guard (ingestion.resolve_git_host / guarded_git_env)."""
from __future__ import annotations

import socket
import types

import pytest

from src.webapi import ingestion
from src.webapi.settings import get_settings


def _dns(mapping):
    def fake(host, port, type=0, **kw):
        if host not in mapping:
            raise socket.gaierror("nx")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in mapping[host]]
    return fake


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("GITLAB_URL", raising=False)
    monkeypatch.setenv("VIGILO_JWT_SECRET", "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _set(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(f"VIGILO_{k.upper()}", v)
    get_settings.cache_clear()


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x.git", "https://[::1]/x.git", "http://169.254.169.254/latest/x.git",
    "http://10.1.2.3:8080/x.git", "http://192.168.0.5/x.git", "http://0.0.0.0/x.git",
    "http://224.0.0.1/x.git", "http://[::ffff:127.0.0.1]/x.git",
])
def test_ip_literals_denied(url):
    with pytest.raises(ValueError, match="not allowed"):
        ingestion.resolve_git_host(url)


def test_hostname_resolving_private_or_metadata_denied(monkeypatch):
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({
        "evil.example": ["10.0.0.7"], "meta.example": ["169.254.169.254"],
        "mixed.example": ["93.184.216.34", "127.0.0.1"]}))
    for h in ("evil.example", "meta.example", "mixed.example"):   # ANY bad record denies
        with pytest.raises(ValueError):
            ingestion.resolve_git_host(f"https://{h}/x.git")


def test_unresolvable_denied(monkeypatch):
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({}))
    with pytest.raises(ValueError, match="cannot resolve"):
        ingestion.resolve_git_host("https://nx.example/x.git")


def test_public_host_allowed_and_pinned(monkeypatch):
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({"gl.example": ["93.184.216.34"]}))
    host, port, ips = ingestion.resolve_git_host("https://gl.example/x.git")
    assert (host, port, ips) == ("gl.example", 443, ["93.184.216.34"])
    env = ingestion.guarded_git_env("https://gl.example:8443/x.git")
    cfg = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
           for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert cfg["http.curloptResolve"] == "gl.example:8443:93.184.216.34"   # DNS rebinding pin
    assert cfg["http.followRedirects"] == "false"                           # no redirect bounce


def test_allowlisted_internal_gitlab_ok_but_metadata_never(monkeypatch):
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({
        "gitlab.corp": ["10.9.9.9"], "sneaky.corp": ["169.254.169.254"]}))
    with pytest.raises(ValueError):
        ingestion.resolve_git_host("https://gitlab.corp/x.git")
    _set(monkeypatch, gitlab_allowed_hosts="GitLab.corp, sneaky.corp")
    assert ingestion.resolve_git_host("https://gitlab.corp/x.git")[2] == ["10.9.9.9"]
    with pytest.raises(ValueError, match="link_local|metadata"):
        ingestion.resolve_git_host("https://sneaky.corp/x.git")


def test_worker_gitlab_url_env_host_is_allowed(monkeypatch):
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({"gl.int": ["172.16.4.4"]}))
    monkeypatch.setenv("GITLAB_URL", "https://gl.int/gitlab")
    assert ingestion.resolve_git_host("https://gl.int/g/p.git")


def test_validate_access_never_runs_git_for_denied_host():
    called = []
    runner = lambda *a, **k: called.append(1) or types.SimpleNamespace(returncode=0, stdout="", stderr="")
    with pytest.raises(ValueError):
        ingestion.validate_remote_access("http://169.254.169.254/x.git", None, runner)
    assert called == []


def test_validate_access_passes_pinned_env_to_git(monkeypatch):
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({"gl.example": ["93.184.216.34"]}))
    seen = {}

    def runner(cmd, capture_output, text, timeout, env):
        seen.update(env)
        return types.SimpleNamespace(returncode=0, stdout="a\trefs/heads/m\n", stderr="")
    assert ingestion.validate_remote_access("https://gl.example/x.git", None, runner) == 1
    assert seen["GIT_CONFIG_COUNT"] == "2"



@pytest.mark.parametrize("ip", ["169.254.169.254", "10.0.0.7"])
def test_github_app_api_host_is_vetted(monkeypatch, ip):
    """A GitHub App calls the host's REST API before git runs: same host policy."""
    from src.services.forges import github_app

    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({"ghe.evil": [ip]}))
    with pytest.raises(github_app.GitHubAppError, match="not allowed"):
        github_app.pinned_opener("https://ghe.evil/api/v3", ingestion.resolve_git_host)


def test_github_forge_mints_with_the_git_host_policy(monkeypatch):
    from src.services.forges import get_forge
    from src.services.forges import github_app

    seen = {}
    monkeypatch.setattr(github_app, "installation_token",
                        lambda secret, url, **kw: seen.update(kw) or "t")
    assert get_forge("github").access_token("github_app", "{}", "https://ghe.example/a/b") == "t"
    assert seen["resolve"] is ingestion.resolve_git_host


def test_github_app_requests_go_to_the_vetted_address(monkeypatch):
    """No second DNS lookup (rebinding) and no proxy from the environment; TLS still
    checks the host name."""
    from src.services.forges import github_app

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({"ghe.example": ["93.184.216.34"]}))
    opener = github_app.pinned_opener("https://ghe.example/api/v3", ingestion.resolve_git_host)
    assert not any(isinstance(h, __import__("urllib.request").request.ProxyHandler)
                   and h.proxies for h in opener.handlers)

    connected, wrapped = [], []

    class _Ctx:
        def wrap_socket(self, sock, server_hostname):
            wrapped.append(server_hostname)
            raise OSError("stop here")

    def fake_connect(addr, *a, **k):
        connected.append(addr)
        return object()

    monkeypatch.setattr(github_app.socket, "create_connection", fake_connect)
    conn = github_app._PinnedHTTPSConnection("ghe.example", 443, pinned_ip="93.184.216.34",
                                             context=_Ctx())
    with pytest.raises(OSError):
        conn.connect()
    assert connected == [("93.184.216.34", 443)] and wrapped == ["ghe.example"]


def test_github_app_opener_refuses_other_hosts(monkeypatch):
    from src.services.forges import github_app

    monkeypatch.setattr(ingestion, "_getaddrinfo", _dns({"ghe.example": ["93.184.216.34"]}))
    opener = github_app.pinned_opener("https://ghe.example/api/v3", ingestion.resolve_git_host)
    with pytest.raises(Exception, match="not vetted"):
        opener.open("https://other.example/api/v3/app", timeout=1)
