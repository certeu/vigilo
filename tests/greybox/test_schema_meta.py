"""Tests for the schema-version ratchet constants.

The schema-version ratchet has been bumped each time a backward-incompatible
graph-schema change shipped. v3 adds the ``detection_hints`` field on the
``finding`` table — every confirmed finding now carries a JSON object of
WAF / SIEM / log / network indicators that the report writer renders into
the Detection Engineering Appendix.
"""
from __future__ import annotations


def test_schema_version_is_current():
    from src.greybox.graph.schema import SCHEMA_VERSION

    assert SCHEMA_VERSION == 3
    assert isinstance(SCHEMA_VERSION, int)


def test_schema_meta_ddl_defines_schemafull_table():
    from src.greybox.graph.schema import SCHEMA_META_DDL

    assert "DEFINE TABLE IF NOT EXISTS _schema_meta SCHEMAFULL" in SCHEMA_META_DDL
    assert "DEFINE FIELD version ON _schema_meta TYPE int" in SCHEMA_META_DDL
    assert "DEFINE FIELD created_at ON _schema_meta TYPE datetime" in SCHEMA_META_DDL


def test_schema_meta_ddl_is_included_in_full_ddl():
    """The aggregated DDL applied by init_schema must include _schema_meta."""
    from src.greybox.graph.init_schema import TABLES_DDL

    assert "_schema_meta" in TABLES_DDL
    assert "DEFINE TABLE IF NOT EXISTS _schema_meta SCHEMAFULL" in TABLES_DDL
