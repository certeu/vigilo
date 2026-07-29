"""Graph schema initialization -- creates tables and indexes in SurrealDB.

Called by the init_graph Temporal activity during Preflight.
"""
from __future__ import annotations

import logging
from typing import Any, Protocol

from src.greybox.graph.schema import EDGE_TYPES, SCHEMA_META_DDL, SCHEMA_VERSION

logger = logging.getLogger(__name__)


class SchemaVersionMismatchError(RuntimeError):
    """Raised when the database schema version does not match ``SCHEMA_VERSION``.

    Grey-box is a fresh-scan project: there are no in-place migrations.
    The operator must wipe the SurrealDB database and re-run the scan.
    """

NODE_TABLES_DDL = """
DEFINE TABLE IF NOT EXISTS page SCHEMAFULL;
DEFINE FIELD url ON page TYPE string;
DEFINE FIELD title ON page TYPE option<string>;
DEFINE FIELD status_code ON page TYPE int;
DEFINE FIELD content_type ON page TYPE string;
DEFINE FIELD crawl_depth ON page TYPE int;
DEFINE FIELD content_signature ON page TYPE option<string>;
DEFINE FIELD discovered_by ON page TYPE string;
DEFINE FIELD discovered_at ON page TYPE datetime;
DEFINE FIELD auth_required ON page TYPE bool;

DEFINE TABLE IF NOT EXISTS endpoint SCHEMAFULL;
DEFINE FIELD method ON endpoint TYPE string;
DEFINE FIELD path ON endpoint TYPE string;
DEFINE FIELD full_url ON endpoint TYPE string;
DEFINE FIELD content_type ON endpoint TYPE option<string>;
DEFINE FIELD response_headers ON endpoint TYPE option<object>;
DEFINE FIELD status_codes_seen ON endpoint TYPE array<int>;
DEFINE FIELD discovered_by ON endpoint TYPE string;
DEFINE FIELD discovered_at ON endpoint TYPE datetime;
DEFINE FIELD rate_limited ON endpoint TYPE bool DEFAULT false;
DEFINE FIELD requires_auth ON endpoint TYPE bool DEFAULT true;
DEFINE FIELD claimed_by ON endpoint TYPE option<string> DEFAULT NONE;
DEFINE FIELD claimed_at ON endpoint TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD claim_expires ON endpoint TYPE option<datetime> DEFAULT NONE;

DEFINE TABLE IF NOT EXISTS parameter SCHEMAFULL;
DEFINE FIELD name ON parameter TYPE string;
DEFINE FIELD location ON parameter TYPE string
    ASSERT $value IN ['query', 'body', 'header', 'cookie', 'path'];
DEFINE FIELD data_type ON parameter TYPE string;
DEFINE FIELD shape ON parameter TYPE string DEFAULT 'free_text'
    ASSERT $value IN ['numeric_id', 'uuid', 'email', 'url', 'free_text', 'json', 'enum', 'boolean'];
DEFINE FIELD example_value ON parameter TYPE option<string>;
DEFINE FIELD constraints ON parameter TYPE option<string>;
DEFINE FIELD injectable ON parameter TYPE string DEFAULT 'untested'
    ASSERT $value IN ['untested', 'yes', 'no'];
DEFINE FIELD sanitized ON parameter TYPE string DEFAULT 'unknown'
    ASSERT $value IN ['unknown', 'yes', 'partial', 'no'];
DEFINE FIELD discovered_by ON parameter TYPE string;
DEFINE FIELD discovered_at ON parameter TYPE datetime;
DEFINE FIELD claimed_by ON parameter TYPE option<string> DEFAULT NONE;
DEFINE FIELD claimed_at ON parameter TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD claim_expires ON parameter TYPE option<datetime> DEFAULT NONE;

DEFINE TABLE IF NOT EXISTS technology SCHEMAFULL;
DEFINE FIELD name ON technology TYPE string;
DEFINE FIELD version ON technology TYPE option<string>;
DEFINE FIELD category ON technology TYPE string;
DEFINE FIELD confidence ON technology TYPE string;
DEFINE FIELD source ON technology TYPE string;
DEFINE FIELD discovered_by ON technology TYPE string;
DEFINE FIELD discovered_at ON technology TYPE datetime;

DEFINE TABLE IF NOT EXISTS identity SCHEMAFULL;
DEFINE FIELD role ON identity TYPE string;
DEFINE FIELD privilege_level ON identity TYPE int;
DEFINE FIELD auth_method ON identity TYPE string;
DEFINE FIELD credential_ref ON identity TYPE string;
DEFINE FIELD session_active ON identity TYPE bool DEFAULT true;
DEFINE FIELD discovered_by ON identity TYPE string;
DEFINE FIELD discovered_at ON identity TYPE datetime;

DEFINE TABLE IF NOT EXISTS workflow SCHEMAFULL;
DEFINE FIELD name ON workflow TYPE string;
DEFINE FIELD description ON workflow TYPE string;
DEFINE FIELD step_count ON workflow TYPE int;
DEFINE FIELD discovered_by ON workflow TYPE string;
DEFINE FIELD discovered_at ON workflow TYPE datetime;

DEFINE TABLE IF NOT EXISTS component SCHEMAFULL;
DEFINE FIELD name ON component TYPE string;
DEFINE FIELD description ON component TYPE string;
DEFINE FIELD path_pattern ON component TYPE string;
DEFINE FIELD requires_role ON component TYPE option<string>;
DEFINE FIELD discovered_by ON component TYPE string;
DEFINE FIELD discovered_at ON component TYPE datetime;

DEFINE TABLE IF NOT EXISTS test_attempt SCHEMAFULL;
DEFINE FIELD vuln_type ON test_attempt TYPE string;
DEFINE FIELD technique ON test_attempt TYPE string;
DEFINE FIELD payload ON test_attempt TYPE string;
DEFINE FIELD payload_hash ON test_attempt TYPE string;
DEFINE FIELD verdict ON test_attempt TYPE string
    ASSERT $value IN ['conclusive_vulnerable', 'conclusive_clean', 'inconclusive', 'failed'];
DEFINE FIELD failure_reason ON test_attempt TYPE option<string>;
DEFINE FIELD error_class ON test_attempt TYPE option<string>;
DEFINE FIELD response_code ON test_attempt TYPE int;
DEFINE FIELD response_excerpt ON test_attempt TYPE option<string>;
DEFINE FIELD duration_ms ON test_attempt TYPE int;
DEFINE FIELD agent ON test_attempt TYPE string;
DEFINE FIELD attempted_at ON test_attempt TYPE datetime;

DEFINE TABLE IF NOT EXISTS finding SCHEMAFULL;
DEFINE FIELD title ON finding TYPE string;
DEFINE FIELD vuln_type ON finding TYPE string;
DEFINE FIELD severity ON finding TYPE string
    ASSERT $value IN ['critical', 'high', 'medium', 'low', 'info'];
DEFINE FIELD status ON finding TYPE string
    ASSERT $value IN ['confirmed', 'potential', 'lead_promoted', 'invalidated'];
DEFINE FIELD cwe_id ON finding TYPE option<string>;
DEFINE FIELD cvss_estimate ON finding TYPE option<float>;
DEFINE FIELD confidence ON finding TYPE string;
DEFINE FIELD evidence_ref ON finding TYPE option<string>;
DEFINE FIELD poc_payload ON finding TYPE option<string>;
DEFINE FIELD impact ON finding TYPE string;
DEFINE FIELD discovered_by ON finding TYPE string;
DEFINE FIELD confirmed_by ON finding TYPE option<string>;
DEFINE FIELD grants ON finding TYPE array<string> DEFAULT [];
DEFINE FIELD requires ON finding TYPE array<string> DEFAULT [];
DEFINE FIELD detection_hints ON finding TYPE option<object>;
DEFINE FIELD discovered_at ON finding TYPE datetime;

DEFINE TABLE IF NOT EXISTS lead SCHEMAFULL;
DEFINE FIELD signal ON lead TYPE string;
DEFINE FIELD hypothesis ON lead TYPE string;
DEFINE FIELD signal_strength ON lead TYPE string
    ASSERT $value IN ['low', 'medium', 'high'];
DEFINE FIELD investigation_hints ON lead TYPE array<string>;
DEFINE FIELD status ON lead TYPE string DEFAULT 'open'
    ASSERT $value IN ['open', 'investigating', 'dismissed', 'promoted'];
DEFINE FIELD investigation_attempts ON lead TYPE int DEFAULT 0;
DEFINE FIELD max_attempts ON lead TYPE int DEFAULT 3;
DEFINE FIELD assigned_to ON lead TYPE option<string>;
DEFINE FIELD evidence_blob_path ON lead TYPE option<string>;
DEFINE FIELD discovered_by ON lead TYPE string;
DEFINE FIELD discovered_at ON lead TYPE datetime;
DEFINE FIELD claimed_by ON lead TYPE option<string> DEFAULT NONE;
DEFINE FIELD claimed_at ON lead TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD claim_expires ON lead TYPE option<datetime> DEFAULT NONE;
"""


def _build_edge_tables_ddl() -> str:
    """Derive edge-table DDL from the EDGE_TYPES registry.

    Uses TYPE RELATION so Surrealist renders the rows as graph edges.
    List-valued from/to (e.g., ["endpoint", "page"]) become a `|`-joined
    string: `FROM endpoint|page`.
    """
    def fmt(v: str | list[str]) -> str:
        return "|".join(sorted(v)) if isinstance(v, list) else v

    lines = ["-- Edge tables (derived from EDGE_TYPES registry)"]
    for edge_name, spec in EDGE_TYPES.items():
        from_str = fmt(spec["from"])
        to_str = fmt(spec["to"])
        lines.append(
            f"DEFINE TABLE IF NOT EXISTS {edge_name} "
            f"TYPE RELATION FROM {from_str} TO {to_str} SCHEMALESS;"
        )
    return "\n".join(lines) + "\n"


EDGE_TABLES_DDL = _build_edge_tables_ddl()

TABLES_DDL = NODE_TABLES_DDL + "\n" + EDGE_TABLES_DDL + "\n" + SCHEMA_META_DDL

# Exported for smoke test
GRAPH_SCHEMA_DDL = TABLES_DDL

INDEXES_DDL = """
DEFINE INDEX IF NOT EXISTS idx_param_injectable ON parameter FIELDS injectable;
DEFINE INDEX IF NOT EXISTS idx_ta_vuln_type ON test_attempt FIELDS vuln_type;
DEFINE INDEX IF NOT EXISTS idx_lead_status ON lead FIELDS status;
DEFINE INDEX IF NOT EXISTS idx_lead_strength ON lead FIELDS signal_strength;
DEFINE INDEX IF NOT EXISTS idx_finding_status ON finding FIELDS status;
DEFINE INDEX IF NOT EXISTS idx_finding_severity ON finding FIELDS severity;
DEFINE INDEX IF NOT EXISTS idx_endpoint_path ON endpoint FIELDS path;
DEFINE INDEX IF NOT EXISTS idx_endpoint_method_path ON endpoint FIELDS method, path;
"""


class _GraphClientLike(Protocol):
    """Minimum surface ``ensure_schema`` needs from a client.

    Implemented by :class:`src.greybox.graph.client.GraphClient` and by
    the ``_FakeClient`` in ``tests/greybox/test_init_schema_ratchet.py``.
    """

    async def raw_query(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ...


async def ensure_schema(client: _GraphClientLike) -> None:
    """Apply the full DDL on first init; raise on version mismatch.

    Behaviour:
        - Empty database (no ``_schema_meta`` row): apply ``TABLES_DDL`` +
          ``INDEXES_DDL`` and insert a row tagging this scan with the
          current ``SCHEMA_VERSION``.
        - Matching version: no-op; DDL is not re-applied.
        - Mismatch: raise :class:`SchemaVersionMismatchError`. Grey-box
          has no migrations — the operator must wipe the database.
    """
    rows = await client.raw_query("SELECT version FROM _schema_meta LIMIT 1;")
    if rows:
        row = rows[0] or {}
        db_version = row.get("version")
        if db_version != SCHEMA_VERSION:
            raise SchemaVersionMismatchError(
                f"Schema version mismatch: db={db_version} code={SCHEMA_VERSION}. "
                "This is a fresh-scan project — delete the SurrealDB database and re-run."
            )
        return

    # First-time init: apply DDL and stamp the version.
    await client.raw_query(TABLES_DDL)
    await client.raw_query(INDEXES_DDL)
    await client.raw_query(
        "CREATE _schema_meta CONTENT { version: $v, created_at: time::now() };",
        {"v": SCHEMA_VERSION},
    )
    logger.info("Graph schema initialized at version %d", SCHEMA_VERSION)
