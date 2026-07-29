"""Tests for SurrealDB record ID canonicalization."""
from __future__ import annotations


def test_simple_path():
    from src.greybox.graph.ids import canonicalize_id
    assert canonicalize_id("endpoint", "GET:/api/users") == "endpoint:GET_api_users"


def test_nested_path():
    from src.greybox.graph.ids import canonicalize_id
    result = canonicalize_id("endpoint", "POST:/api/v2/admin/delete-user")
    assert result == "endpoint:POST_api_v2_admin_delete_user"


def test_brackets():
    from src.greybox.graph.ids import canonicalize_id
    result = canonicalize_id("parameter", "search[q]")
    assert result == "parameter:search_q"


def test_full_url_strips_host():
    from src.greybox.graph.ids import canonicalize_id
    result = canonicalize_id("page", "https://target.com/login?next=/admin")
    assert result == "page:login_next_admin"


def test_long_path_uses_hash_suffix():
    from src.greybox.graph.ids import canonicalize_id
    long_path = "/api/v3/" + "/".join(f"segment{i}" for i in range(20))
    result = canonicalize_id("endpoint", long_path)
    assert len(result) <= 64 + len("endpoint:")
    assert result.startswith("endpoint:")
    parts = result.split("_")
    assert len(parts[-1]) == 8


def test_empty_after_strip():
    from src.greybox.graph.ids import canonicalize_id
    result = canonicalize_id("page", "https://target.com/")
    assert result != "page:"
    assert len(result) > len("page:")


def test_collapsing_underscores():
    from src.greybox.graph.ids import canonicalize_id
    result = canonicalize_id("endpoint", "GET:///api///double")
    assert "__" not in result
