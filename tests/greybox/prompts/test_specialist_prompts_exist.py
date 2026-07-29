"""Guardrail tests for the 4+2 specialist prompt roster (Slice 14).

After Cluster E, only 6 specialist prompts should exist on disk:
- 4 flagship: authorization, injection, reflection, ssrf
- 2 conditional: graphql, websocket

Legacy prompts (auth, authz, bizlogic, crypto, xss) must be removed —
their content is absorbed into authorization (auth/authz/bizlogic)
or reflection (xss/crypto).
"""
from __future__ import annotations

from pathlib import Path


PROMPT_DIR = Path(__file__).resolve().parents[3] / "prompts" / "greybox"
EXPECTED = {
    "specialist-authorization.txt",
    "specialist-injection.txt",
    "specialist-reflection.txt",
    "specialist-ssrf.txt",
    "specialist-graphql.txt",
    "specialist-websocket.txt",
}
RETIRED = {
    "specialist-auth.txt",
    "specialist-authz.txt",
    "specialist-bizlogic.txt",
    "specialist-crypto.txt",
    "specialist-xss.txt",
}


def test_expected_specialist_prompts_exist():
    for name in EXPECTED:
        assert (PROMPT_DIR / name).is_file(), f"missing {name}"


def test_retired_prompts_are_removed():
    for name in RETIRED:
        assert not (PROMPT_DIR / name).exists(), f"retired file still present: {name}"


def test_authorization_prompt_has_identity_count_placeholder():
    text = (PROMPT_DIR / "specialist-authorization.txt").read_text()
    assert "{{IDENTITY_COUNT}}" in text
