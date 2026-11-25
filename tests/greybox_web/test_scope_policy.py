"""ScopePolicy and IP classification (6.2): pure unit tests."""
from __future__ import annotations

import pytest

from src.greybox_web.netguard import classify_ip, ip_denial, is_always_denied
from src.greybox_web.scope import (
    PolicyContext,
    ScopePolicy,
    build_scope,
    normalise_host_pattern,
    normalise_path,
)

PRIVATE_OK = PolicyContext(allow_private=True,
                           blocked_hosts=frozenset({"api", "db", "localhost.localdomain",
                                                      "svc.internal.test"}),
                           blocked_endpoints=(("private", 8080), ("private", 8081),
                                              ("internal.test", 9000)))
STRICT = PolicyContext(allow_private=False, blocked_hosts=PRIVATE_OK.blocked_hosts,
                       blocked_endpoints=PRIVATE_OK.blocked_endpoints)


def build(base="http://127.0.0.1:43123/", ctx=PRIVATE_OK, **scope):
    return build_scope(base, scope or None, ctx)


def ok(base="http://127.0.0.1:43123/", ctx=PRIVATE_OK, **scope) -> ScopePolicy:
    url, policy, errors = build(base, ctx, **scope)
    assert errors == [], errors
    return policy


def errs(base="http://127.0.0.1:43123/", ctx=PRIVATE_OK, **scope) -> dict:
    url, policy, errors = build(base, ctx, **scope)
    assert policy is None and errors
    return {e.loc: e.msg for e in errors}


# ------------------------------------------------------------------ defaults


class TestDefaults:
    def test_defaults_from_base_url(self):
        url, p, e = build("HTTP://127.0.0.1:43123")
        assert e == []
        assert url == "http://127.0.0.1:43123/"
        assert p.to_dict() == {
            "allowed_hosts": ["127.0.0.1"], "allowed_schemes": ["http"],
            "allowed_ports": [43123], "path_prefixes": ["/"], "excluded_paths": [],
            "redirect_policy": "in_scope", "allow_auth_testing": True,
        }

    @pytest.mark.parametrize("base,port", [
        ("http://app.example.test/", 80), ("https://app.example.test/", 443),
        ("https://app.example.test:8443/x", 8443),
    ])
    def test_default_effective_port(self, base, port):
        assert ok(base).allowed_ports == (port,)

    def test_default_port_not_rendered_in_normalised_url(self):
        url, _, _ = build("https://App.Example.TEST:443/a/./b/../c?x=1")
        assert url == "https://app.example.test/a/c?x=1"

    def test_ipv6_base_url(self):
        url, p, e = build("http://[::1]:9000/")
        assert e == [] and p.allowed_hosts == ("::1",)
        assert url == "http://[::1]:9000/"

    def test_round_trip(self):
        p = ok(excluded_paths=["/logout"], allow_auth_testing=True)
        assert ScopePolicy.from_dict(p.to_dict()) == p


# ------------------------------------------------------------------- base URL


class TestBaseUrl:
    @pytest.mark.parametrize("base", [
        "ftp://127.0.0.1/", "127.0.0.1:43123", "//127.0.0.1/", "javascript:alert(1)", "",
        "http:///nohost",
    ])
    def test_rejects_non_http_urls(self, base):
        assert ("base_url",) in errs(base)

    def test_rejects_userinfo(self):
        assert "credentials" in errs("http://user:pw@127.0.0.1:43123/")[("base_url",)]

    def test_rejects_fragment(self):
        assert "fragment" in errs("http://127.0.0.1:43123/#x")[("base_url",)]

    @pytest.mark.parametrize("base", ["http://127.0.0.1:43123/a b", "http://127.0.0.1\\@x/",
                                      "http://127.0.0.1:43123/a\nb"])
    def test_rejects_whitespace_and_backslash(self, base):
        assert ("base_url",) in errs(base)

    def test_rejects_bad_port(self):
        assert ("base_url",) in errs("http://127.0.0.1:99999/")

    def test_rejects_wildcard_base(self):
        assert ("base_url",) in errs("http://*.example.test/")


# ------------------------------------------------------------------------ hosts


class TestHosts:
    @pytest.mark.parametrize("raw,norm", [
        ("Example.TEST.", "example.test"), ("127.0.0.1", "127.0.0.1"),
        ("[::1]", "::1"), ("0:0:0:0:0:0:0:1", "::1"), ("*.Example.test", "*.example.test"),
        ("bücher.example", "xn--bcher-kva.example"),
    ])
    def test_normalisation(self, raw, norm):
        assert normalise_host_pattern(raw) == (norm, None)

    @pytest.mark.parametrize("raw", [
        "*", "*.com", "a.*.example.test", "*example.test", "**.example.test",
        "user@example.test", "example.test/path", "http://example.test", "example.test:80",
        "exa mple.test", "-bad.example", "", "2852039166", "0x7f000001", "0177.0.0.1",
        "127.1", "a" * 64 + ".test",
    ])
    def test_invalid_patterns(self, raw):
        norm, msg = normalise_host_pattern(raw)
        assert norm is None and msg

    def test_bare_star_rejected_with_field_loc(self):
        e = errs(allowed_hosts=["127.0.0.1", "*"])
        assert ("scope", "allowed_hosts", 1) in e

    def test_tld_wildcard_rejected(self):
        e = errs("https://app.example.com/", allowed_hosts=["app.example.com", "*.com"])
        assert "top-level" in e[("scope", "allowed_hosts", 1)]

    def test_base_host_must_be_listed(self):
        e = errs(allowed_hosts=["127.0.0.2"])
        assert "127.0.0.1" in e[("scope", "allowed_hosts")]

    def test_base_host_not_satisfied_by_wildcard(self):
        e = errs("https://app.example.test/", allowed_hosts=["*.example.test"])
        assert ("scope", "allowed_hosts") in e

    def test_list_size_bounds(self):
        assert ("scope", "allowed_hosts") in errs(allowed_hosts=[])
        many = ["127.0.0.1"] + [f"h{i}.example.test" for i in range(20)]
        assert ("scope", "allowed_hosts") in errs(allowed_hosts=many)

    def test_duplicates_collapsed(self):
        p = ok(allowed_hosts=["127.0.0.1", "127.0.0.1", "127.000.0.1".replace("000", "0")])
        assert p.allowed_hosts == ("127.0.0.1",)

    def test_wildcard_matching(self):
        p = ok("https://app.example.test/", allowed_hosts=["app.example.test", "*.example.test"],
               allowed_schemes=["https"])
        assert p.check_url("https://a.example.test/").allowed
        assert p.check_url("https://a.b.example.test/").allowed
        assert p.check_url("https://APP.example.test./").allowed
        assert p.check_url("https://example.test/").reason == "host_not_allowed"
        assert p.check_url("https://evilexample.test/").reason == "host_not_allowed"
        assert p.check_url("https://example.test.evil.test/").reason == "host_not_allowed"


# ---------------------------------------------------------- platform IP policy


class TestHostPolicy:
    @pytest.mark.parametrize("host", [
        "169.254.169.254", "169.254.1.1", "0.0.0.0", "0.1.2.3", "fe80::1", "fd00:ec2::254",
        "::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "224.0.0.1",
        "255.255.255.255", "ff02::1", "::",
    ])
    def test_metadata_and_link_local_always_rejected(self, host):
        bracket = f"[{host}]" if ":" in host else host
        e = errs(f"http://{bracket}:43123/")
        assert "can never be scanned" in e[("base_url",)]
        # also as an extra allowed host, even with private targets enabled
        e = errs(allowed_hosts=["127.0.0.1", host])
        assert "can never be scanned" in e[("scope", "allowed_hosts", 1)]

    @pytest.mark.parametrize("host", [
        "127.0.0.1", "127.8.9.10", "10.0.0.5", "172.16.3.4", "192.168.1.1", "100.64.0.1",
        "fc00::1", "fd12:3456::1", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "localhost",
        "app.localhost",
    ])
    def test_private_targets_need_the_flag(self, host):
        bracket = f"[{host}]" if ":" in host else host
        base = f"http://{bracket}:43123/"
        assert "disabled on this platform" in errs(base, STRICT)[("base_url",)]
        assert ok(base, PRIVATE_OK)

    def test_public_targets_allowed_without_flag(self):
        assert ok("https://app.example.test/", STRICT)
        assert ok("http://93.184.216.34/", STRICT)

    @pytest.mark.parametrize("host", ["api", "db", "API", "localhost.localdomain"])
    def test_blocked_platform_hosts(self, host):
        e = errs(f"http://{host}:43123/")
        assert "platform service" in e[("base_url",)]

    def test_wildcard_covering_blocked_host_rejected(self):
        e = errs("http://app.internal.test/",
                 allowed_hosts=["app.internal.test", "*.internal.test"])
        assert "platform service" in e[("scope", "allowed_hosts", 1)]

    def test_blocked_platform_ports_on_private_addresses(self):
        assert "platform service" in errs("http://127.0.0.1:8080/")[("base_url",)]
        e = errs(allowed_ports=[43123, 8081])
        assert "platform service" in e[("scope", "allowed_ports", 1)]
        # an explicit host:port endpoint
        e = errs("http://internal.test:9000/")
        assert "platform service" in e[("base_url",)]
        # the same port on a public host is fine
        assert ok("http://app.example.test:8080/", STRICT)


class TestIpClassification:
    @pytest.mark.parametrize("ip,cat", [
        ("169.254.169.254", "metadata"), ("fd00:ec2::254", "metadata"),
        ("::ffff:169.254.169.254", "metadata"), ("64:ff9b::169.254.169.254", "metadata"),
        ("2002:a9fe:a9fe::1", "metadata"), ("169.254.0.1", "link_local"),
        ("fe80::abcd", "link_local"), ("0.0.0.0", "unspecified"), ("::", "unspecified"),
        ("239.1.1.1", "multicast"), ("ff05::2", "multicast"), ("240.0.0.1", "reserved"),
        ("127.0.0.1", "loopback"), ("::1", "loopback"), ("::ffff:127.0.0.1", "loopback"),
        ("10.1.1.1", "private"), ("172.31.255.255", "private"), ("192.168.0.1", "private"),
        ("100.127.255.255", "cgnat"), ("fd00::1", "ula"), ("8.8.8.8", "public"),
        ("2001:4860:4860::8888", "public"), ("172.32.0.1", "public"),
    ])
    def test_categories(self, ip, cat):
        assert classify_ip(ip) == cat

    def test_denial_reasons(self):
        assert ip_denial("169.254.169.254", allow_private=True) == "ip_denied:metadata"
        assert ip_denial("127.0.0.1", allow_private=False) == "ip_denied:loopback"
        assert ip_denial("127.0.0.1", allow_private=True) is None
        assert ip_denial("10.0.0.1", allow_private=True, host_authorised=False) == \
            "private_ip_for_public_name"
        assert ip_denial("8.8.8.8", allow_private=False) is None
        assert is_always_denied(classify_ip("::ffff:0.0.0.0"))


# ------------------------------------------------------------- schemes / ports


class TestSchemesPorts:
    def test_scheme_must_include_base(self):
        assert ("scope", "allowed_schemes") in errs(allowed_schemes=["https"])

    def test_invalid_scheme_entry(self):
        assert ("scope", "allowed_schemes", 1) in errs(allowed_schemes=["http", "ftp"])

    def test_port_must_include_base(self):
        assert ("scope", "allowed_ports") in errs(allowed_ports=[43124])

    @pytest.mark.parametrize("bad", [0, 65536, -1])
    def test_port_range(self, bad):
        assert ("scope", "allowed_ports", 1) in errs(allowed_ports=[43123, bad])

    def test_check_url_scheme_and_port(self):
        p = ok()
        assert p.check_url("https://127.0.0.1:43123/").reason == "scheme_not_allowed"
        assert p.check_url("http://127.0.0.1:43124/").reason == "port_not_allowed"
        assert p.check_url("http://127.0.0.1/").reason == "port_not_allowed"  # default 80
        assert p.check_url("http://127.0.0.1:43123/x").allowed

    def test_default_port_matches_explicit(self):
        p = ok("https://app.example.test/", allowed_schemes=["https"])
        assert p.check_url("https://app.example.test:443/").allowed
        assert p.check_url("https://app.example.test/").allowed


# ------------------------------------------------------------------------ URLs


class TestCheckUrl:
    def test_userinfo(self):
        assert ok().check_url("http://a:b@127.0.0.1:43123/").reason == "userinfo_present"
        assert ok().check_url("http://@127.0.0.1:43123/").reason == "userinfo_present"

    @pytest.mark.parametrize("url", [
        "/relative", "127.0.0.1:43123/", "http://127.0.0.1:notaport/", "http:///x",
        "http://127.0.0.1:43123/\\..\\", "http://127.0.0.1:43123/a b", "", "http://[::1/",
    ])
    def test_invalid(self, url):
        assert ok().check_url(url).reason == "invalid_url"

    def test_host_not_allowed(self):
        p = ok()
        assert p.check_url("http://169.254.169.254:43123/").reason == "host_not_allowed"
        assert p.check_url("http://127.0.0.2:43123/").reason == "host_not_allowed"
        assert p.check_url("http://2130706433:43123/").reason == "host_not_allowed"
        assert p.check_url("http://evil.invalid:43123/").reason == "host_not_allowed"

    def test_ipv6_matching(self):
        p = ok("http://[::1]:9000/")
        assert p.check_url("http://[0:0::1]:9000/a").allowed
        assert p.check_url("http://[::ffff:127.0.0.1]:9000/").reason == "host_not_allowed"


# ----------------------------------------------------------------------- paths


class TestPaths:
    @pytest.mark.parametrize("raw,norm", [
        ("", "/"), ("/", "/"), ("/a/./b", "/a/b"), ("/a/b/../c", "/a/c"), ("/../../etc", "/etc"),
        ("/a/b/..", "/a/"), ("//a///b", "/a/b"), ("/%61dmin", "/admin"), ("/%2e%2e/x", "/x"),
        ("/a%2fb", "/a%2Fb"), ("/%7euser", "/~user"), ("/a/%2E/b", "/a/b"),
    ])
    def test_normalise_path(self, raw, norm):
        assert normalise_path(raw) == norm

    def test_prefixes_and_exclusions(self):
        p = ok("http://127.0.0.1:43123/app/", path_prefixes=["/app", "/api/"],
               excluded_paths=["/app/logout"])
        assert p.check_url("http://127.0.0.1:43123/app").allowed
        assert p.check_url("http://127.0.0.1:43123/app/x?y=1").allowed
        assert p.check_url("http://127.0.0.1:43123/api/v1").allowed
        assert p.check_url("http://127.0.0.1:43123/application").reason == "path_not_in_scope"
        assert p.check_url("http://127.0.0.1:43123/other").reason == "path_not_in_scope"
        assert p.check_url("http://127.0.0.1:43123/app/logout").reason == "path_excluded"

    def test_base_path_must_be_in_scope(self):
        # base path "/" is not under /app
        e = errs(path_prefixes=["/app"])
        assert ("scope", "path_prefixes") in e

    def test_base_path_excluded(self):
        e = errs("http://127.0.0.1:43123/logout", excluded_paths=["/logout"])
        assert ("scope", "excluded_paths") in e

    @pytest.mark.parametrize("url", [
        "/logout", "/logout/", "/logout?x=1", "/LOGOUT", "/Logout;jsessionid=1", "/x/../logout",
        "/%6cogout", "//logout", "/./logout", "/logout-all",
    ])
    def test_exclusion_evasion_variants_blocked(self, url):
        p = ok(excluded_paths=["/logout"])
        assert p.check_url("http://127.0.0.1:43123" + url).reason == "path_excluded"

    def test_exclusion_wins_over_inclusion(self):
        p = ok(path_prefixes=["/", "/admin"], excluded_paths=["/admin"])
        assert p.check_url("http://127.0.0.1:43123/admin/x").reason == "path_excluded"
        # excluding the base path itself is a validation error
        assert ("scope", "excluded_paths") in errs(excluded_paths=["/"])

    @pytest.mark.parametrize("key", ["path_prefixes", "excluded_paths"])
    @pytest.mark.parametrize("bad", ["admin", "/a?b", "/a#b", "/a b", "/" + "a" * 600])
    def test_invalid_path_entries(self, key, bad):
        good = ["/"] if key == "path_prefixes" else []
        assert ("scope", key, len(good)) in errs(**{key: good + [bad]})

    def test_path_prefix_bounds(self):
        assert ("scope", "path_prefixes") in errs(path_prefixes=[])
        assert ("scope", "excluded_paths") in errs(excluded_paths=[f"/x{i}" for i in range(101)])

    def test_paths_normalised_on_save(self):
        p = ok(path_prefixes=["/a/../", "/b//c"], excluded_paths=["/%6cogout"])
        assert p.path_prefixes == ("/", "/b/c")
        assert p.excluded_paths == ("/logout",)


# --------------------------------------------------------------- misc fields


class TestMisc:
    def test_redirect_policy(self):
        assert ok(redirect_policy="none").redirect_policy == "none"
        assert ("scope", "redirect_policy") in errs(redirect_policy="always")

    def test_auth_testing_flag(self):
        assert ("scope", "allow_auth_testing") in errs(allow_auth_testing="yes")

    def test_summary(self):
        p = ok(excluded_paths=["/logout"])
        # authentication testing is the DEFAULT now ("hardcore by default")
        assert p.summary() == [
            "Hosts: 127.0.0.1", "Schemes: http", "Ports: 43123",
            "Paths: / (excluding /logout)", "Redirects: followed only within scope",
            "Authentication testing: enabled (logins, default credentials, "
            "object-level access)",
            "State-changing requests: refused (read-only + inert probes)",
        ]
        p2 = ok(redirect_policy="none", allow_auth_testing=False)
        assert "Redirects: never followed" in p2.summary()
        assert "Authentication testing: disabled" in p2.summary()
