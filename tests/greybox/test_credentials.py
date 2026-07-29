"""Tests for credential loading and identity configuration."""
from __future__ import annotations

import yaml
import pytest


@pytest.fixture
def creds_file(tmp_path):
    creds = {
        "identities": [
            {
                "name": "admin",
                "role": "admin",
                "privilege_level": 10,
                "login": {
                    "url": "http://target/login",
                    "method": "form",
                    "fields": {"username": "admin@test.com", "password": "Admin123!"},
                    "success_indicator": "Dashboard",
                },
            },
            {
                "name": "user",
                "role": "user",
                "privilege_level": 1,
                "login": {
                    "url": "http://target/login",
                    "method": "form",
                    "fields": {"username": "user@test.com", "password": "User123!"},
                    "success_indicator": "Dashboard",
                },
            },
            {"name": "anonymous", "role": "anonymous", "privilege_level": 0, "login": None},
        ]
    }
    path = tmp_path / "creds.yaml"
    path.write_text(yaml.dump(creds))
    return path


def test_load_identities(creds_file):
    from src.greybox.services.credentials import load_identities
    identities = load_identities(creds_file)
    assert len(identities) == 3
    assert identities[0].name == "admin"
    assert identities[0].privilege_level == 10
    assert identities[2].login is None


def test_load_identities_missing_file():
    from pathlib import Path
    from src.greybox.services.credentials import load_identities
    with pytest.raises(FileNotFoundError):
        load_identities(Path("/nonexistent/creds.yaml"))


def test_build_login_instructions(creds_file):
    from src.greybox.services.credentials import load_identities, build_login_block
    identities = load_identities(creds_file)
    block = build_login_block(identities[0], "http://target")
    assert "admin@test.com" in block
    assert "Dashboard" in block


def test_build_login_instructions_anonymous(creds_file):
    from src.greybox.services.credentials import load_identities, build_login_block
    identities = load_identities(creds_file)
    anon = identities[2]
    block = build_login_block(anon, "http://target")
    assert "no authentication" in block.lower() or block == ""
