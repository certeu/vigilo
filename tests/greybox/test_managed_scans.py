"""Tests for managed scan wrappers."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def test_base_scanner_interface():
    """BaseScanner is abstract and cannot be instantiated."""
    from src.greybox.managed.base import BaseScanner

    with pytest.raises(TypeError):
        BaseScanner("http://target.local")  # type: ignore[abstract]


def test_scan_result_model():
    """ScanResult has correct defaults."""
    from src.greybox.managed.base import ScanResult

    result = ScanResult(scan_type="test")
    assert result.scan_type == "test"
    assert result.new_endpoints == []
    assert result.findings == []
    assert result.leads == []
    assert result.technologies == []
    assert result.items_found == 0


def test_nuclei_scanner_parse_output():
    """NucleiScanner correctly parses JSON-lines nuclei output."""
    from src.greybox.managed.nuclei import NucleiScanner

    scanner = NucleiScanner("http://target.local")
    raw = "\n".join([
        json.dumps({
            "template-id": "cve-2021-44228",
            "info": {
                "name": "Log4Shell RCE",
                "severity": "critical",
                "tags": "cve,rce,log4j",
                "description": "Log4j remote code execution",
            },
            "matched-at": "http://target.local/api",
            "matcher-name": "rce",
        }),
        json.dumps({
            "template-id": "tech-detect-nginx",
            "info": {
                "name": "Nginx Detected",
                "severity": "info",
                "tags": ["tech"],
                "description": "Nginx web server detected",
            },
            "matched-at": "http://target.local",
        }),
        json.dumps({
            "template-id": "cve-2023-1234",
            "info": {
                "name": "Medium Vuln",
                "severity": "medium",
                "tags": "cve",
            },
            "matched-at": "http://target.local/page",
        }),
    ])

    result = scanner.parse_output(raw)
    assert result.scan_type == "nuclei"
    # critical + medium go to findings, info goes to leads
    assert len(result.findings) == 2
    assert len(result.leads) == 1
    assert result.findings[0]["template_id"] == "cve-2021-44228"
    assert result.findings[0]["severity"] == "critical"
    assert result.findings[0]["name"] == "Log4Shell RCE"
    assert result.leads[0]["severity"] == "info"
    assert result.items_found == 3


def test_nuclei_scanner_parse_output_empty():
    """NucleiScanner handles empty output."""
    from src.greybox.managed.nuclei import NucleiScanner

    scanner = NucleiScanner("http://target.local")
    result = scanner.parse_output("")
    assert result.items_found == 0
    assert result.findings == []


def test_feroxbuster_scanner_parse_output():
    """FeroxbusterScanner extracts paths from JSON-lines output."""
    from src.greybox.managed.feroxbuster import FeroxbusterScanner

    scanner = FeroxbusterScanner("http://target.local")
    raw = "\n".join([
        json.dumps({
            "type": "response",
            "url": "http://target.local/admin",
            "path": "/admin",
            "status": 200,
            "content_length": 5000,
            "method": "GET",
        }),
        json.dumps({
            "type": "response",
            "url": "http://target.local/api/secret",
            "path": "/api/secret",
            "status": 403,
            "content_length": 150,
            "method": "GET",
        }),
        json.dumps({
            "type": "response",
            "url": "http://target.local/debug",
            "path": "/debug",
            "status": 500,
            "content_length": 2000,
            "method": "GET",
        }),
        json.dumps({
            "type": "response",
            "url": "http://target.local/nothing",
            "path": "/nothing",
            "status": 404,
            "content_length": 100,
            "method": "GET",
        }),
        json.dumps({
            "type": "statistics",
            "requests": 1000,
        }),
    ])

    result = scanner.parse_output(raw)
    assert result.scan_type == "feroxbuster"
    # 200, 403, 500 are interesting; 404 is not
    assert len(result.new_endpoints) == 3
    assert result.new_endpoints[0]["path"] == "/admin"
    assert result.new_endpoints[1]["status"] == 403
    # 403 and 500 generate leads
    assert len(result.leads) == 2
    assert result.leads[0]["signal_type"] == "access_control_anomaly"
    assert result.leads[1]["signal_type"] == "error_response"
    assert result.items_found == 3


def test_headers_scanner():
    """HeadersScanner detects missing security headers."""
    from src.greybox.managed.headers import analyze_headers, REQUIRED_HEADERS

    # Response with only one security header present
    headers = {
        "content-type": "text/html",
        "server": "nginx",
        "strict-transport-security": "max-age=31536000",
    }
    result = analyze_headers(headers, "http://target.local")
    assert result.scan_type == "header_analysis"

    # All required headers minus the one present should be missing
    missing_headers = {f["header"] for f in result.findings}
    assert "strict-transport-security" not in missing_headers
    assert "content-security-policy" in missing_headers
    assert "x-frame-options" in missing_headers
    assert len(result.findings) == len(REQUIRED_HEADERS) - 1

    # Each finding has expected fields
    for finding in result.findings:
        assert "severity" in finding
        assert "cwe" in finding
        assert "description" in finding


def test_headers_scanner_all_present():
    """HeadersScanner reports nothing when all headers present."""
    from src.greybox.managed.headers import analyze_headers, REQUIRED_HEADERS

    headers = {name: "value" for name in REQUIRED_HEADERS}
    result = analyze_headers(headers, "http://target.local")
    assert result.items_found == 0
    assert result.findings == []


def test_cors_scanner_wildcard_with_credentials():
    """CorsScanner flags wildcard + credentials as high severity."""
    from src.greybox.managed.cors import analyze_cors

    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    }
    result = analyze_cors(headers, target_url="http://target.local")
    assert result.scan_type == "cors_check"
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "high"
    assert result.findings[0]["cwe"] == "CWE-942"
    assert "wildcard" in result.findings[0]["description"].lower()


def test_cors_scanner_wildcard_without_credentials():
    """CorsScanner flags wildcard without credentials as medium."""
    from src.greybox.managed.cors import analyze_cors

    headers = {
        "access-control-allow-origin": "*",
    }
    result = analyze_cors(headers)
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "medium"


def test_cors_scanner_reflects_origin():
    """CorsScanner detects reflected arbitrary origin."""
    from src.greybox.managed.cors import analyze_cors

    headers = {
        "access-control-allow-origin": "https://evil.example.com",
        "access-control-allow-credentials": "true",
    }
    result = analyze_cors(headers, test_origin="https://evil.example.com")
    assert len(result.findings) == 1
    assert result.findings[0]["severity"] == "high"
    assert "reflects" in result.findings[0]["description"].lower()


def test_cors_scanner_no_cors_headers():
    """CorsScanner reports nothing when no CORS headers present."""
    from src.greybox.managed.cors import analyze_cors

    result = analyze_cors({})
    assert result.items_found == 0
    assert result.findings == []


def test_scanner_subprocess_execution():
    """Verify BaseScanner.run() calls subprocess with correct command."""
    from src.greybox.managed.nuclei import NucleiScanner

    scanner = NucleiScanner("http://target.local", severity="high")
    cmd = scanner.build_command()
    assert cmd[0] == "nuclei"
    assert "-u" in cmd
    assert "http://target.local" in cmd
    assert "-jsonl" in cmd
    assert "-severity" in cmd
    assert "high" in cmd

    # Test async run with mocked subprocess
    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(return_value=(b"", b""))

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_proc
        result = asyncio.run(scanner.run())
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0]
        assert call_args[0] == "nuclei"
        assert result.scan_type == "nuclei"


def test_ssl_scanner_build_command():
    """SslScanner builds correct testssl.sh command."""
    from src.greybox.managed.ssl_analysis import SslScanner

    scanner = SslScanner("https://target.local:8443", fast=True)
    cmd = scanner.build_command()
    assert cmd[0] == "testssl"
    assert "target.local:8443" in cmd
    assert "--fast" in cmd


def test_feroxbuster_scanner_build_command_uses_silent():
    """Feroxbuster uses a non-interactive flag accepted by the container binary."""
    from src.greybox.managed.feroxbuster import FeroxbusterScanner

    scanner = FeroxbusterScanner("http://target.local")
    cmd = scanner.build_command()
    assert cmd[0] == "feroxbuster"
    assert "--quiet" in cmd
    assert "--silent" not in cmd


def test_ssl_scanner_parse_output():
    """SslScanner parses testssl.sh JSON output."""
    from src.greybox.managed.ssl_analysis import SslScanner

    scanner = SslScanner("https://target.local")
    raw = json.dumps([
        {"id": "heartbleed", "severity": "HIGH", "finding": "VULNERABLE"},
        {"id": "ccs", "severity": "MEDIUM", "finding": "VULNERABLE"},
        {"id": "cert_chain", "severity": "INFO", "finding": "Chain OK"},
    ])
    result = scanner.parse_output(raw)
    assert result.scan_type == "ssl_analysis"
    assert len(result.findings) == 2  # HIGH + MEDIUM
    assert result.findings[0]["test_id"] == "heartbleed"


def test_whatweb_scanner_parse_output():
    """WhatwebScanner extracts technology fingerprints."""
    from src.greybox.managed.whatweb import WhatwebScanner

    scanner = WhatwebScanner("http://target.local")
    raw = json.dumps({
        "target": "http://target.local",
        "plugins": {
            "jQuery": {"version": ["3.6.0"]},
            "PHP": {"version": ["8.1"]},
            "HTTPServer": {"string": ["nginx/1.24"]},
        },
    })
    result = scanner.parse_output(raw)
    assert result.scan_type == "tech_fingerprint"
    # HTTPServer is skipped
    assert len(result.technologies) == 2
    names = {t["name"] for t in result.technologies}
    assert "jQuery" in names
    assert "PHP" in names
    assert "HTTPServer" not in names


def test_robots_sitemap_scanner_parse_output():
    """RobotsSitemapScanner extracts paths from robots.txt."""
    from src.greybox.managed.robots_sitemap import RobotsSitemapScanner

    scanner = RobotsSitemapScanner("http://target.local")
    raw = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /private/\n"
        "Allow: /public/\n"
        "Sitemap: http://target.local/sitemap.xml\n"
        "# Comment line\n"
    )
    result = scanner.parse_output(raw)
    assert result.scan_type == "robots_sitemap"
    assert len(result.new_endpoints) == 4  # 2 disallow + 1 allow + 1 sitemap
    assert len(result.leads) == 2  # Only disallow paths are leads

    paths = [e["path"] for e in result.new_endpoints]
    assert "/admin/" in paths
    assert "/private/" in paths
    assert "/public/" in paths

    # Leads point to disallowed paths
    assert result.leads[0]["signal_type"] == "hidden_path"
    assert "/admin/" in result.leads[0]["path"]


def test_default_creds_run_finds_match(monkeypatch):
    """DefaultCredsScanner reports a critical finding for a working pair.

    Mocks ``httpx.AsyncClient`` so the GET (baseline) returns no cookies and
    the POST returns the success indicator + a session cookie — enough for
    the probe to confirm the credentials.
    """
    import sys
    from src.greybox.managed.default_creds import DefaultCredsScanner

    class _FakeJar:
        def __init__(self, names): self._names = names
        def __iter__(self): return iter(_FakeCookie(n) for n in self._names)

    class _FakeCookie:
        def __init__(self, name): self.name = name; self.value = "v"

    class _FakeResponse:
        def __init__(self, status, body): self.status_code = status; self.text = body

    class _FakeClient:
        """Records calls and returns scripted responses.

        Behavior:
          - The first call (baseline GET) returns 200, no cookies.
          - On POST with admin/admin, sets a fresh cookie and returns the
            success indicator. All other POSTs return 401 with no cookie.
        """
        def __init__(self, *args, **kwargs): self.cookies = MagicMock(jar=_FakeJar([]))
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): return _FakeResponse(200, "Login")
        async def post(self, url, data=None):
            data = data or {}
            if data.get("username") == "admin" and data.get("password") == "admin":
                self.cookies = MagicMock(jar=_FakeJar(["session"]))
                return _FakeResponse(200, "Welcome to Dashboard")
            return _FakeResponse(401, "")

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _FakeClient
    fake_httpx.HTTPError = Exception
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    scanner = DefaultCredsScanner(
        "http://target.local",
        login_url="http://target.local/login",
        success_indicator="dashboard",
    )
    result = asyncio.run(scanner.run())
    assert result.scan_type == "default_creds"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["severity"] == "critical"
    assert finding["username"] == "admin"
    assert finding["password"] == "admin"
    assert finding["vuln_type"] == "auth"


def test_base_scanner_extracts_cookie_kwargs():
    """BaseScanner pops cookie_header / identity_name from kwargs."""
    from src.greybox.managed.nuclei import NucleiScanner

    scanner = NucleiScanner(
        "http://target.local",
        cookie_header="session=abc; csrf=def",
        identity_name="admin",
        severity="high",
    )
    assert scanner.cookie_header == "session=abc; csrf=def"
    assert scanner.identity_name == "admin"
    assert scanner.is_authenticated is True
    # Original kwargs (not auth) remain accessible
    assert scanner.options.get("severity") == "high"


def test_base_scanner_unauthenticated_by_default():
    """A scanner constructed without auth context reports is_authenticated=False."""
    from src.greybox.managed.cors import CorsScanner

    scanner = CorsScanner("http://target.local")
    assert scanner.cookie_header == ""
    assert scanner.identity_name == ""
    assert scanner.is_authenticated is False


def test_nuclei_injects_cookie_header():
    """Nuclei's build_command includes -H 'Cookie: ...' when authenticated."""
    from src.greybox.managed.nuclei import NucleiScanner

    scanner = NucleiScanner("http://target.local", cookie_header="session=abc")
    cmd = scanner.build_command()
    assert "-H" in cmd
    cookie_idx = cmd.index("-H")
    assert cmd[cookie_idx + 1] == "Cookie: session=abc"


def test_nuclei_no_cookie_when_unauthenticated():
    """Nuclei does not emit any -H Cookie flag when cookie_header is empty."""
    from src.greybox.managed.nuclei import NucleiScanner

    scanner = NucleiScanner("http://target.local")
    cmd = scanner.build_command()
    assert not any("Cookie:" in str(part) for part in cmd)


def test_feroxbuster_injects_cookie_header():
    """Feroxbuster gets -H Cookie when authenticated."""
    from src.greybox.managed.feroxbuster import FeroxbusterScanner

    scanner = FeroxbusterScanner("http://target.local", cookie_header="s=1")
    cmd = scanner.build_command()
    assert "Cookie: s=1" in cmd


def test_curl_scanners_inject_cookie_header():
    """All curl-based scanners attach Cookie via -H when authenticated."""
    from src.greybox.managed.cors import CorsScanner
    from src.greybox.managed.headers import HeadersScanner
    from src.greybox.managed.robots_sitemap import RobotsSitemapScanner

    for cls in (CorsScanner, HeadersScanner, RobotsSitemapScanner):
        scanner = cls("http://target.local", cookie_header="t=2")
        cmd = scanner.build_command()
        assert "Cookie: t=2" in cmd, f"{cls.__name__} did not inject cookie"
        # The target URL must remain the final positional argument so curl
        # interprets prior -H values correctly.
        assert cmd[-1].endswith("target.local") or cmd[-1].endswith("target.local/robots.txt"), (
            f"{cls.__name__}: target URL must be the last argument"
        )


def test_whatweb_injects_cookie():
    """Whatweb gets --cookie=... when authenticated."""
    from src.greybox.managed.whatweb import WhatwebScanner

    scanner = WhatwebScanner("http://target.local", cookie_header="x=1")
    cmd = scanner.build_command()
    assert "--cookie=x=1" in cmd


def test_default_creds_run_no_match(monkeypatch):
    """DefaultCredsScanner emits zero findings when every pair is rejected."""
    import sys
    from src.greybox.managed.default_creds import DefaultCredsScanner

    class _FakeJar:
        def __iter__(self): return iter([])

    class _FakeResponse:
        def __init__(self, status, body): self.status_code = status; self.text = body

    class _FakeClient:
        def __init__(self, *args, **kwargs): self.cookies = MagicMock(jar=_FakeJar())
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): return _FakeResponse(200, "Login page")
        async def post(self, url, data=None): return _FakeResponse(401, "Invalid")

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _FakeClient
    fake_httpx.HTTPError = Exception
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    scanner = DefaultCredsScanner(
        "http://target.local",
        login_url="http://target.local/login",
        success_indicator="dashboard",
    )
    result = asyncio.run(scanner.run())
    assert result.findings == []
    assert result.leads == []  # no success_indicator-less mode here
