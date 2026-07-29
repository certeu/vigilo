"""Async SurrealDB client wrapper for the knowledge graph.

Provides typed operations for node/edge CRUD, querying, and claiming.
Used by both Temporal activities (async) and graph-tool CLI (sync wrapper).
"""
from __future__ import annotations

import logging
import re
from typing import Any

from pydantic import BaseModel
from surrealdb import AsyncSurreal

from src.greybox.graph.ids import canonicalize_id, normalize_record_id
from src.greybox.graph.schema import NODE_TYPE_MAP

logger = logging.getLogger(__name__)

# E3.2: Record ID validation regex
_RECORD_ID_RE = re.compile(r"^[a-z_]+:[a-zA-Z0-9_]+$")



class GraphClient:
    """Async wrapper around SurrealDB for knowledge graph operations."""

    def __init__(
        self, url: str, session_id: str, user: str, password: str,
    ) -> None:
        self._url = url
        self.session_id = session_id
        self._user = user
        self._password = password
        self.db: AsyncSurreal | None = None
        self._surreal: AsyncSurreal | None = None

    async def __aenter__(self) -> GraphClient:
        self._surreal = AsyncSurreal(self._url)
        self.db = await self._surreal.__aenter__()
        await self.db.signin({"username": self._user, "password": self._password})
        await self.db.use("vigilo", self.session_id)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._surreal:
            await self._surreal.__aexit__(*args)

    # -- Node operations (E3: parameterized queries) --

    async def create_node(
        self, node_type: str, raw_id: str, data: BaseModel,
    ) -> dict[str, Any]:
        """Create a node in the graph."""
        record_id = canonicalize_id(node_type, raw_id)
        # Default mode keeps datetime objects native so the SurrealDB Python
        # SDK serializes them as CBOR datetimes. SCHEMAFULL `TYPE datetime`
        # fields do NOT coerce ISO strings — passing strings triggers
        # "expected a datetime" errors server-side.
        fields = data.model_dump(exclude_none=True)
        query = f"CREATE {record_id} CONTENT $data"
        result = await self.db.query(query, {"data": fields})
        return self._extract_result(result)

    async def update_node(
        self, record_id: str, updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Update properties on an existing node."""
        record_id = normalize_record_id(record_id)
        if not _RECORD_ID_RE.match(record_id):
            raise ValueError(f"Invalid record ID: {record_id}")
        query = f"UPDATE {record_id} MERGE $data"
        result = await self.db.query(query, {"data": updates})
        return self._extract_result(result)

    async def query_nodes(
        self,
        node_type: str,
        filters: dict[str, Any] | None = None,
        order_by: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Query nodes by type with optional filters."""
        if node_type not in NODE_TYPE_MAP:
            raise ValueError(f"Unknown node type: {node_type}")
        query = f"SELECT * FROM {node_type}"
        params: dict[str, Any] = {}
        if filters:
            conditions = []
            for i, (k, v) in enumerate(filters.items()):
                param_name = f"f_{i}"
                conditions.append(f"{k} = ${param_name}")
                params[param_name] = v
            query += " WHERE " + " AND ".join(conditions)
        if order_by:
            query += f" ORDER BY {order_by}"
        if limit:
            query += f" LIMIT {limit}"
        result = await self.db.query(query, params)
        return self._extract_results(result)

    async def get_node(self, record_id: str) -> dict[str, Any] | None:
        """Get a single node by record ID."""
        record_id = normalize_record_id(record_id)
        if not _RECORD_ID_RE.match(record_id):
            raise ValueError(f"Invalid record ID: {record_id}")
        result = await self.db.query(f"SELECT * FROM {record_id}")
        results = self._extract_results(result)
        return results[0] if results else None

    # -- Edge operations --

    async def create_edge(
        self,
        edge_type: str,
        from_id: str,
        to_id: str,
        properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a relation (edge) between two nodes."""
        from_id = normalize_record_id(from_id)
        to_id = normalize_record_id(to_id)
        if not _RECORD_ID_RE.match(from_id):
            raise ValueError(f"Invalid from record ID: {from_id}")
        if not _RECORD_ID_RE.match(to_id):
            raise ValueError(f"Invalid to record ID: {to_id}")
        query = f"RELATE {from_id}->{edge_type}->{to_id}"
        params: dict[str, Any] = {}
        if properties:
            query += " CONTENT $data"
            params = {"data": properties}
        result = await self.db.query(query, params)
        return self._extract_result(result)

    # -- Claim operations (E3.4: parameterized) --

    async def claim_node(
        self, record_id: str, agent: str, ttl_seconds: int = 300,
    ) -> bool:
        """Atomically claim a node for testing. Returns True if acquired."""
        record_id = normalize_record_id(record_id)
        if not _RECORD_ID_RE.match(record_id):
            raise ValueError(f"Invalid record ID: {record_id}")
        query = f"""
            UPDATE {record_id} SET
                claimed_by = $agent,
                claimed_at = time::now(),
                claim_expires = time::now() + {ttl_seconds}s
            WHERE claimed_by = NONE
               OR claim_expires < time::now()
            RETURN AFTER
        """
        result = await self.db.query(query, {"agent": agent})
        results = self._extract_results(result)
        return len(results) > 0 and results[0].get("claimed_by") == agent

    async def release_claim(self, record_id: str, agent: str) -> None:
        """Release a claim on a node."""
        record_id = normalize_record_id(record_id)
        if not _RECORD_ID_RE.match(record_id):
            raise ValueError(f"Invalid record ID: {record_id}")
        await self.db.query(f"""
            UPDATE {record_id} SET
                claimed_by = NONE,
                claimed_at = NONE,
                claim_expires = NONE
            WHERE claimed_by = $agent
        """, {"agent": agent})

    # -- Raw query --

    async def raw_query(self, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a raw SurrealQL query."""
        result = await self.db.query(query, params or {})
        return self._extract_results(result)

    # -- Helpers --

    @staticmethod
    def _extract_result(response: list[dict]) -> dict[str, Any]:
        results = GraphClient._extract_results(response)
        return results[0] if results else {}

    @staticmethod
    def _extract_results(response: Any) -> list[dict[str, Any]]:
        # SurrealDB driver returns query errors as raw strings. Surface them
        # as exceptions instead of silently treating them as successful rows.
        if isinstance(response, str):
            raise RuntimeError(f"SurrealDB query error: {response}")
        if not response:
            return []
        first = response[0]
        if isinstance(first, str):
            raise RuntimeError(f"SurrealDB query error: {first}")
        if isinstance(first, dict) and "result" in first:
            inner = first["result"]
            if isinstance(inner, str):
                raise RuntimeError(f"SurrealDB query error: {inner}")
            return inner or []
        return response
