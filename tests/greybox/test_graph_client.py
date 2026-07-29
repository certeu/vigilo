"""Tests for SurrealDB graph client."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.query = AsyncMock(return_value=[{"result": [], "status": "OK"}])
    db.signin = AsyncMock()
    db.use = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_client_connect(mock_db):
    with patch("src.greybox.graph.client.AsyncSurreal") as MockSurreal:
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        MockSurreal.return_value = mock_ctx

        from src.greybox.graph.client import GraphClient
        async with GraphClient("ws://localhost:8000", "test", "root", "root") as client:
            assert client.db is mock_db
            mock_db.use.assert_called_once_with("vigilo", "test")


@pytest.mark.asyncio
async def test_client_create_node(mock_db):
    from src.greybox.graph.client import GraphClient
    from src.greybox.graph.schema import EndpointNode

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"

    node = EndpointNode(
        method="GET", path="/api/users",
        full_url="http://t.local/api/users",
        discovered_by="discovery",
    )
    mock_db.query.return_value = [{"result": [{"id": "endpoint:GET_api_users"}], "status": "OK"}]

    result = await client.create_node("endpoint", "GET:/api/users", node)
    assert result["id"] == "endpoint:GET_api_users"
    mock_db.query.assert_called_once()
    call_args = mock_db.query.call_args[0][0]
    assert "CREATE endpoint:" in call_args
    # E3: Verify parameterized CONTENT (no raw values in query)
    assert "CONTENT $data" in call_args


@pytest.mark.asyncio
async def test_client_query_nodes(mock_db):
    from src.greybox.graph.client import GraphClient

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"

    mock_db.query.return_value = [{"result": [
        {"id": "endpoint:GET_api_users", "method": "GET", "path": "/api/users"},
    ], "status": "OK"}]

    results = await client.query_nodes("endpoint", filters={"requires_auth": True})
    assert len(results) == 1
    assert results[0]["path"] == "/api/users"


@pytest.mark.asyncio
async def test_client_create_edge(mock_db):
    from src.greybox.graph.client import GraphClient

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"

    mock_db.query.return_value = [{"result": [{"id": "has_param:abc"}], "status": "OK"}]

    result = await client.create_edge(
        "has_param", "endpoint:GET_api_users", "parameter:search_q"
    )
    call_args = mock_db.query.call_args[0][0]
    assert "RELATE" in call_args


@pytest.mark.asyncio
async def test_client_raw_query(mock_db):
    from src.greybox.graph.client import GraphClient

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"

    mock_db.query.return_value = [{"result": [{"count": 42}], "status": "OK"}]
    results = await client.raw_query("SELECT count() FROM endpoint GROUP ALL")
    assert results[0]["count"] == 42


@pytest.mark.asyncio
async def test_update_node_validates_record_id(mock_db):
    from src.greybox.graph.client import GraphClient

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"

    with pytest.raises(ValueError, match="Invalid record ID"):
        await client.update_node("'; DROP TABLE endpoint; --", {"name": "bad"})


@pytest.mark.asyncio
async def test_create_node_sends_native_datetime(mock_db):
    """CONTENT $data must carry native datetime objects.

    SCHEMAFULL `TYPE datetime` fields reject ISO strings server-side
    ("expected a datetime"). The Python SurrealDB SDK serializes datetime
    objects as CBOR datetimes, so model_dump must preserve them.
    """
    from datetime import datetime

    from src.greybox.graph.client import GraphClient
    from src.greybox.graph.schema import EndpointNode

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"
    mock_db.query.return_value = [{"result": [{"id": "endpoint:x"}], "status": "OK"}]

    node = EndpointNode(
        method="GET", path="/api/x",
        full_url="http://t.local/api/x",
        discovered_by="discovery",
    )
    await client.create_node("endpoint", "GET_api_x", node)

    query = mock_db.query.call_args[0][0]
    sent_params = mock_db.query.call_args[0][1]
    assert "CONTENT $data" in query
    assert isinstance(sent_params["data"], dict)
    assert sent_params["data"]["method"] == "GET"
    assert isinstance(sent_params["data"]["discovered_at"], datetime)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "node_type, kwargs, datetime_fields",
    [
        ("page",
         {"url": "http://t/", "discovered_by": "d"},
         ["discovered_at"]),
        ("endpoint",
         {"method": "GET", "path": "/x", "full_url": "http://t/x",
          "discovered_by": "d"},
         ["discovered_at"]),
        ("parameter",
         {"name": "q", "location": "query", "discovered_by": "d"},
         ["discovered_at"]),
        ("technology",
         {"name": "nginx", "category": "server", "discovered_by": "d"},
         ["discovered_at"]),
        ("identity",
         {"role": "user", "credential_ref": "config:user"},
         ["discovered_at"]),
        ("workflow",
         {"name": "login", "discovered_by": "d"},
         ["discovered_at"]),
        ("component",
         {"name": "api", "discovered_by": "d"},
         ["discovered_at"]),
        ("test_attempt",
         {"vuln_type": "sqli", "technique": "error", "payload": "'",
          "verdict": "conclusive_clean", "agent": "a"},
         ["attempted_at"]),
        ("finding",
         {"title": "x", "vuln_type": "sqli", "severity": "high",
          "impact": "RCE", "discovered_by": "d"},
         ["discovered_at"]),
        ("lead",
         {"signal": "s", "hypothesis": "h", "discovered_by": "d"},
         ["discovered_at"]),
    ],
)
async def test_create_node_datetime_fields_are_native(
    mock_db, node_type, kwargs, datetime_fields,
):
    """Regression guard: every schema-typed `datetime` field on every node
    type must reach SurrealDB as a native ``datetime`` object.

    SCHEMAFULL ``TYPE datetime`` fields reject ISO strings server-side. This
    test fails if ``create_node`` ever re-introduces ``mode="json"`` or any
    serialization path that stringifies datetimes.
    """
    from datetime import datetime

    from src.greybox.graph.client import GraphClient
    from src.greybox.graph.schema import NODE_TYPE_MAP

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"
    mock_db.query.return_value = [
        {"result": [{"id": f"{node_type}:x"}], "status": "OK"}
    ]

    node = NODE_TYPE_MAP[node_type](**kwargs)
    await client.create_node(node_type, "x", node)

    sent = mock_db.query.call_args[0][1]["data"]
    for field in datetime_fields:
        assert isinstance(sent[field], datetime), (
            f"{node_type}.{field} must be native datetime, got "
            f"{type(sent[field]).__name__}"
        )


@pytest.mark.asyncio
async def test_extract_results_raises_on_driver_error(mock_db):
    """Regression: SurrealDB driver returns query errors as raw strings.

    Previous behaviour silently treated them as success, so schema violations
    in CREATE/RELATE passed with count=N but zero rows persisted.
    """
    from src.greybox.graph.client import GraphClient

    client = GraphClient.__new__(GraphClient)
    client.db = mock_db
    client.session_id = "test"
    mock_db.query.return_value = "Found NONE for field `discovered_at`"

    with pytest.raises(RuntimeError, match="SurrealDB query error"):
        await client.raw_query("SELECT 1")
