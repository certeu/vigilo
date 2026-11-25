"""Backend catalogue and selection: derived from the same variables white-box uses.
Pure functions over an injected env mapping: no real keys, no .env, no network."""
from __future__ import annotations

import pytest

from src.greybox_web import modelsel as m

FOUNDRY = {"CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_FOUNDRY_API_KEY": "sekret-key",
           "ANTHROPIC_FOUNDRY_BASE_URL": "https://f.example/anthropic",
           "ANTHROPIC_MEDIUM_MODEL": "med", "ANTHROPIC_LARGE_MODEL": "big",
           "ANTHROPIC_SMALL_MODEL": "sm"}


def by_id(env, dev=False):
    return {b.id: b for b in m.backends(env, dev)}


def test_foundry_env_gives_claude_with_medium_first():
    b = by_id(FOUNDRY)["claude"]
    assert b.available and b.models == ("med", "big", "sm")
    assert b.credentials.protocol == "anthropic"
    assert b.credentials.base_url == "https://f.example/anthropic"
    assert "sekret-key" not in repr(b)                       # key hidden from repr
    assert m.default_choice(FOUNDRY, False) == ("claude", "med")


def test_anthropic_api_key_only():
    b = by_id({"ANTHROPIC_API_KEY": "k"})["claude"]
    assert b.available and b.credentials.base_url == ""


def test_bedrock_and_missing_keys_unavailable():
    assert not by_id({"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_API_KEY": "k"}
                     )["claude"].available
    all_ = by_id({})
    assert not any(b.available for b in all_.values())
    assert "ANTHROPIC_API_KEY" in all_["claude"].reason
    assert m.default_choice({}, False) is None


def test_codex_wire_api_selects_the_protocol():
    base = {"CODEX_API_KEY": "k", "CODEX_BASE_URL": "https://c.example/v1",
            "CODEX_MEDIUM_MODEL": "cm"}
    resp = by_id({**base, "CODEX_WIRE_API": "responses"})["codex"]
    assert resp.available and resp.credentials.protocol == "openai-responses"
    dflt = by_id(base)["codex"]                    # default wire api is responses
    assert dflt.available and dflt.credentials.protocol == "openai-responses"
    chat = by_id({**base, "CODEX_WIRE_API": "chat"})["codex"]
    assert chat.available and chat.models[0] == "cm"
    assert chat.credentials.protocol == "openai"
    assert not by_id({"CODEX_WIRE_API": "responses"})["codex"].available   # no key


def test_opencode_litellm_strips_prefix():
    b = by_id({"LITELLM_BASE_URL": "http://g", "LITELLM_API_KEY": "k"})["opencode"]
    assert b.available and all("/" not in x for x in b.models)


def test_fake_only_in_dev_mode_and_default_prefers_real():
    assert "fake" not in by_id({}, dev=False)
    assert m.default_choice({}, True) == ("fake", "fake-explorer")
    assert m.default_choice(FOUNDRY, True)[0] == "claude"


def test_validate_choice():
    assert m.validate_choice("", "", FOUNDRY, False) == ("", "")
    assert m.validate_choice("claude", "", FOUNDRY, False) == ("claude", "med")
    assert m.validate_choice("claude", "big", FOUNDRY, False) == ("claude", "big")
    for bad in (("nope", ""), ("codex", ""), ("claude", "other"), ("", "med"),
                ("fake", "")):
        with pytest.raises(m.ModelSelectionError):
            m.validate_choice(*bad, FOUNDRY, False)


def test_resolve_model_for_run_like_object():
    class Run:
        model_backend, model = "claude", "big"
    backend, model, creds = m.resolve_model(Run, FOUNDRY, False)
    assert (backend, model, creds.api_key) == ("claude", "big", "sekret-key")

    class Empty:
        model_backend = model = ""
    assert m.resolve_model(Empty, FOUNDRY, False).model == "med"
    with pytest.raises(m.ModelSelectionError, match="No AI model configured"):
        m.resolve_model(Empty, {}, False)
