from __future__ import annotations

import pytest

from src.webapi.security.vault import SecretVault, generate_key


class TestSecretVault:
    def test_roundtrip(self):
        vault = SecretVault(generate_key())
        token = vault.encrypt("glpat-abc123")
        assert isinstance(token, bytes)
        assert token != b"glpat-abc123"
        assert vault.decrypt(token) == "glpat-abc123"

    def test_wrong_key_cannot_decrypt(self):
        token = SecretVault(generate_key()).encrypt("secret")
        with pytest.raises(Exception):
            SecretVault(generate_key()).decrypt(token)

    def test_empty_key_rejected(self):
        with pytest.raises(ValueError):
            SecretVault("")
