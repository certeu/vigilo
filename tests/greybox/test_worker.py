"""Tests for the grey-box worker entry point."""
from __future__ import annotations

import pytest

from src.greybox.temporal.worker import build_parser, _generate_session_id, ALL_ACTIVITIES


def test_worker_parser():
    """Parser accepts required --url and --creds, with defaults."""
    parser = build_parser()
    args = parser.parse_args(["--url", "http://target.local", "--creds", "creds.yaml"])
    assert args.url == "http://target.local"
    assert args.creds == "creds.yaml"
    assert args.task_queue == "vigilo-greybox"
    assert args.config_path is None
    assert args.output_path is None
    assert args.resume_workspace is None


def test_worker_parser_with_config():
    """Parser accepts optional --config, --output, --task-queue."""
    parser = build_parser()
    args = parser.parse_args([
        "--url", "http://target.local",
        "--creds", "configs/creds.yaml",
        "--config", "configs/gb-config.yaml",
        "--output", "/tmp/output",
        "--task-queue", "my-queue",
    ])
    assert args.url == "http://target.local"
    assert args.creds == "configs/creds.yaml"
    assert args.config_path == "configs/gb-config.yaml"
    assert args.output_path == "/tmp/output"
    assert args.task_queue == "my-queue"


def test_worker_parser_resume():
    """Parser accepts --workspace for resume mode."""
    parser = build_parser()
    args = parser.parse_args([
        "--url", "http://target.local",
        "--creds", "creds.yaml",
        "--workspace", "gb-myhost-1713200000",
    ])
    assert args.resume_workspace == "gb-myhost-1713200000"


def test_worker_parser_missing_url():
    """Parser raises on missing --url."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--creds", "creds.yaml"])


def test_worker_parser_missing_creds():
    """Parser raises on missing --creds."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--url", "http://target.local"])


def test_generate_session_id():
    """Session ID follows gb-{hostname}-{timestamp} format."""
    sid = _generate_session_id()
    assert sid.startswith("gb-")
    parts = sid.split("-", 2)  # gb, hostname..., timestamp
    assert len(parts) >= 2
    # Timestamp portion should be numeric
    last_segment = sid.rsplit("-", 1)[-1]
    assert last_segment.isdigit()


def test_all_activities_populated():
    """ALL_ACTIVITIES contains the expected activity functions."""
    names = [a.__name__ for a in ALL_ACTIVITIES]
    assert "authenticate_sessions" in names
    assert "build_agent_prompt" in names
    assert "export_graph" in names
    assert "init_graph" in names
    assert "init_workspace" in names
    assert "prepare_session" in names
    assert "run_greybox_agent" in names
    assert "run_managed_scan" in names
    assert "check_credential_signals" in names
    assert "write_audit_event" in names
