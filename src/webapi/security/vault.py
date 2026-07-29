"""Symmetric encryption for per-user credential secrets (Fernet)."""
from __future__ import annotations

from cryptography.fernet import Fernet


def generate_key() -> str:
    """Return a new base64-encoded Fernet key (store in VIGILO_FERNET_KEY)."""
    return Fernet.generate_key().decode()


class SecretVault:
    """Encrypt/decrypt short secret strings with a symmetric key."""

    def __init__(self, key: str) -> None:
        if not key:
            raise ValueError("Fernet key is required (set VIGILO_FERNET_KEY)")
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode())

    def decrypt(self, token: bytes) -> str:
        return self._fernet.decrypt(token).decode()


def build_vault(settings) -> SecretVault:
    return SecretVault(settings.fernet_key)
