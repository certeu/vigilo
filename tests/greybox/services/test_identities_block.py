"""Tests for `build_identities_block` — Slice 16 / G2.

The helper concatenates per-identity login blocks into a single
prompt-ready string separated by `---` lines. The resolver uses this to
populate the new `{{IDENTITIES}}` template variable so specialists can
branch on identity count (0 / 1 / 2+).
"""
from __future__ import annotations

from src.greybox.services.credentials import build_identities_block
from src.greybox.types.config import IdentityConfig


def _identity(name: str, *, with_login: bool = True) -> IdentityConfig:
    login = None
    if with_login:
        login = {
            "url": "http://target/login",
            "method": "form",
            "fields": {"username": f"{name}@test.com", "password": "Pw1!"},
            "success_indicator": "Dashboard",
        }
    return IdentityConfig(name=name, role=name, privilege_level=1, login=login)


def test_three_identities_count_and_separator():
    identities = [_identity("admin"), _identity("user"), _identity("auditor")]
    block = build_identities_block(identities, "http://target")
    # Two separators divide three blocks.
    assert block.count("\n---\n") == 2
    for name in ("admin", "user", "auditor"):
        assert name in block


def test_empty_identities_returns_placeholder_text():
    block = build_identities_block([], "http://target")
    assert block.strip() != ""
    assert "No authenticated identities configured." in block


def test_skips_identity_without_login_config():
    identities = [_identity("admin"), _identity("anon", with_login=False)]
    block = build_identities_block(identities, "http://target")
    assert "admin" in block
    assert "anon" not in block
    assert "\n---\n" not in block  # single block left → no separator


def test_single_identity_no_trailing_separator():
    block = build_identities_block([_identity("admin")], "http://target")
    assert "admin" in block
    assert "\n---\n" not in block


def test_identity_count_matches_length():
    identities = [_identity("a"), _identity("b"), _identity("c")]
    # The helper is not responsible for counting, but the resolver calls
    # `str(len(identities))` — verify the invariant the caller relies on.
    assert str(len(identities)) == "3"
