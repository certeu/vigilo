from __future__ import annotations

from src.webapi.schemas import CredentialCreate, CredentialRead


class TestSchemas:
    def test_credential_read_has_no_secret_field(self):
        assert "secret" not in CredentialRead.model_fields
        assert "secret_enc" not in CredentialRead.model_fields
        assert "has_secret" in CredentialRead.model_fields

    def test_credential_create_requires_secret(self):
        c = CredentialCreate(kind="gitlab_token", label="t", secret="glpat-x",
                             gitlab_base_url="https://gl")
        assert c.secret == "glpat-x"
