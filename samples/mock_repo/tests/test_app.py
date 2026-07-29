"""Minimal tests for the demo app (scaffolding realism, not security tests)."""
from api.storage import dump_session, load_session


def test_session_roundtrip():
    payload = {"user": "alice", "role": "viewer"}
    assert load_session(dump_session(payload)) == payload
