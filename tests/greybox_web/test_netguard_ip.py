"""T7: IP classification and denial reasons, pure and table-driven.

Every category that must never be authorisable (metadata, link-local,
unspecified, multicast, reserved, in any IPv6 embedding) plus the
authorisable-with-flag private classes.
"""
from __future__ import annotations

import pytest

from src.greybox_web.netguard import classify_ip, ip_denial, is_always_denied, \
    is_private, parse_ip


ALWAYS_DENIED = [
    ("169.254.169.254", "metadata"),
    ("fd00:ec2::254", "metadata"),
    ("169.254.0.1", "link_local"),
    ("fe80::1", "link_local"),
    ("fe80:0:0:0:0:0:0:2", "link_local"),
    ("0.0.0.0", "unspecified"),
    ("::", "unspecified"),
    ("224.0.0.1", "multicast"),
    ("ff02::1", "multicast"),
    ("240.0.0.1", "reserved"),
    ("255.255.255.255", "reserved"),
    # IPv6 embeddings of denied IPv4
    ("::ffff:169.254.169.254", "metadata"),
    ("64:ff9b::169.254.169.254", "metadata"),
]

PRIVATE = [
    ("127.0.0.1", "loopback"), ("127.8.8.8", "loopback"), ("::1", "loopback"),
    ("10.0.0.1", "private"), ("172.16.0.1", "private"), ("172.31.255.254", "private"),
    ("192.168.1.1", "private"), ("100.64.0.1", "cgnat"),
    ("fc00::1", "ula"), ("fd12:3456::1", "ula"), ("fec0::1", "private"),
    # IPv6 embeddings of private IPv4: classified by the embedded address
    ("::ffff:127.0.0.1", "loopback"),
    ("::ffff:10.1.2.3", "private"),
    ("64:ff9b::a00:1", "private"),           # NAT64 of 10.0.0.1
    ("2002:7f00:1::", "loopback"),           # 6to4 of 127.0.0.1
]

PUBLIC = ["1.1.1.1", ("2606:4700::6810:84e5"), "8.8.8.8", "93.184.216.34"]


@pytest.mark.parametrize("addr,category", ALWAYS_DENIED)
def test_always_denied(addr, category):
    assert classify_ip(addr) == category
    assert is_always_denied(category)
    assert ip_denial(addr, allow_private=True) == f"ip_denied:{category}"
    assert ip_denial(addr, allow_private=False) == f"ip_denied:{category}"


@pytest.mark.parametrize("addr,category", PRIVATE)
def test_private_authorisable(addr, category):
    assert classify_ip(addr) == category
    assert is_private(category)
    assert ip_denial(addr, allow_private=False) == f"ip_denied:{category}"
    assert ip_denial(addr, allow_private=True) is None       # authorised host
    # DNS-rebinding defence: a public NAME resolving here is denied even with
    # private targets allowed (host_authorised=False).
    assert ip_denial(addr, allow_private=True, host_authorised=False) \
        == "private_ip_for_public_name"


@pytest.mark.parametrize("addr", PUBLIC)
def test_public(addr):
    assert classify_ip(addr) == "public"
    assert ip_denial(addr, allow_private=False) is None


def test_parse_ip_forms():
    assert parse_ip("127.0.0.1") is not None
    assert parse_ip("[::1]") is not None
    assert parse_ip("fe80::1%eth0") is None          # zone ids rejected
    assert parse_ip("example.test") is None
    assert parse_ip("127.1") is None                 # not a canonical literal


def test_invalid_string_raises():
    with pytest.raises(ValueError):
        classify_ip("not-an-ip")
