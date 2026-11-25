"""Model backend catalogue and selection for the grey-box exploration agent.

Grey-box reuses the backends white-box already defines (``src/ai``, ``admin_config``):
``claude`` (Anthropic API or Azure Foundry), ``codex`` (OpenAI-compatible endpoint) and
``opencode`` (LiteLLM gateway), configured through the same ``ANTHROPIC_*`` / ``CODEX_*``
/ ``LITELLM_*`` variables. The user picks a backend and model per target (copied onto
each run); ``fake`` exists only when ``VIGILO_DEV_MODE`` is on.

Variables are read from the process environment, overlaid on the repo ``.env`` (the
local dev convention), so an app started from the repo root works from ``.env`` alone.
Nothing here ever returns or logs a key except :class:`Credentials`, which hides it
from ``repr`` and is only handed to the model client.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

FAKE = "fake"
ANTHROPIC = "anthropic"      # wire protocols understood by exploration/client.py
OPENAI_CHAT = "openai"
OPENAI_RESPONSES = "openai-responses"

OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"
_TIERS = ("medium", "large", "small")   # medium first: the default model


class ModelSelectionError(ValueError):
    """The requested backend/model cannot be used."""


@dataclass(frozen=True)
class Credentials:
    protocol: str
    base_url: str = ""
    api_key: str = field(default="", repr=False)


@dataclass(frozen=True)
class Backend:
    id: str
    label: str
    available: bool
    reason: str = ""            # why unavailable (names of variables only)
    models: tuple[str, ...] = ()
    credentials: Credentials | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ResolvedModel:
    backend: str
    model: str
    credentials: Credentials

    def __iter__(self):         # (backend, model, credentials) unpacking
        yield self.backend
        yield self.model
        yield self.credentials


def load_env() -> dict[str, str]:
    """``.env`` in the working directory overlaid by the process environment."""
    out: dict[str, str] = {}
    if os.environ.get("VIGILO_IGNORE_DOTENV", "").lower() in ("1", "true", "yes"):
        return dict(os.environ)       # hermetic runs (E2E): never read the repo .env
    try:
        from dotenv import dotenv_values
        out.update({k: v for k, v in dotenv_values(".env").items() if v is not None})
    except Exception:
        pass
    out.update(os.environ)
    return out


def _g(env: Mapping[str, str], name: str) -> str:
    return (env.get(name) or "").strip()


def _tier_models(resolve, env: Mapping[str, str], strip: str = "") -> tuple[str, ...]:
    seen: list[str] = []
    for tier in _TIERS:
        m = resolve(tier, env)
        if strip and m.startswith(strip):
            m = m[len(strip):]
        if m and m not in seen:
            seen.append(m)
    return tuple(seen)


def _claude(env: Mapping[str, str]) -> Backend:
    from src.ai.claude_executor import resolve_model
    label = "Claude (Anthropic / Azure Foundry)"
    models = _tier_models(resolve_model, env)
    if _g(env, "CLAUDE_CODE_USE_BEDROCK"):
        return Backend("claude", label, False, "AWS Bedrock is not supported for "
                       "grey-box exploration (use ANTHROPIC_API_KEY or Foundry)", models)
    foundry_key = _g(env, "ANTHROPIC_FOUNDRY_API_KEY")
    foundry_base = _g(env, "ANTHROPIC_FOUNDRY_BASE_URL")
    if not foundry_base and _g(env, "ANTHROPIC_FOUNDRY_RESOURCE"):
        foundry_base = (f"https://{_g(env, 'ANTHROPIC_FOUNDRY_RESOURCE')}"
                        ".services.ai.azure.com/anthropic")
    if foundry_key and foundry_base and (
            _g(env, "CLAUDE_CODE_USE_FOUNDRY") or not _g(env, "ANTHROPIC_API_KEY")):
        return Backend("claude", label, True, "", models,
                       Credentials(ANTHROPIC, foundry_base, foundry_key))
    key = _g(env, "ANTHROPIC_API_KEY") or _g(env, "ANTHROPIC_AUTH_TOKEN")
    if key:
        return Backend("claude", label, True, "", models,
                       Credentials(ANTHROPIC, _g(env, "ANTHROPIC_BASE_URL"), key))
    return Backend("claude", label, False,
                   "set ANTHROPIC_API_KEY, or ANTHROPIC_FOUNDRY_API_KEY with "
                   "ANTHROPIC_FOUNDRY_BASE_URL", models)


def _codex(env: Mapping[str, str]) -> Backend:
    from src.ai.codex_executor import resolve_model
    label = "Codex (OpenAI-compatible)"
    models = _tier_models(resolve_model, env)
    key = _g(env, "CODEX_API_KEY") or _g(env, "OPENAI_API_KEY")
    if not key:
        return Backend("codex", label, False,
                       "set CODEX_API_KEY (and CODEX_BASE_URL for a gateway)", models)
    wire = (_g(env, "CODEX_WIRE_API") or "responses").lower()
    protocol = OPENAI_CHAT if wire == "chat" else OPENAI_RESPONSES
    return Backend("codex", label, True, "", models, Credentials(
        protocol, _g(env, "CODEX_BASE_URL") or OPENAI_DEFAULT_BASE, key))


def _opencode(env: Mapping[str, str]) -> Backend:
    from src.ai.opencode_executor import LITELLM_PROVIDER_PREFIX, resolve_model
    label = "OpenCode (LiteLLM gateway)"
    models = _tier_models(resolve_model, env, strip=f"{LITELLM_PROVIDER_PREFIX}/")
    base, key = _g(env, "LITELLM_BASE_URL"), _g(env, "LITELLM_API_KEY")
    if not (base and key):
        return Backend("opencode", label, False,
                       "set LITELLM_BASE_URL and LITELLM_API_KEY", models)
    return Backend("opencode", label, True, "", models,
                   Credentials(OPENAI_CHAT, base, key))


def backends(env: Mapping[str, str] | None = None,
             dev_mode: bool | None = None) -> list[Backend]:
    """Every backend, available or not (with the reason), plus ``fake`` in dev mode."""
    env = load_env() if env is None else env
    if dev_mode is None:
        from src.webapi.settings import get_settings
        dev_mode = bool(get_settings().dev_mode)
    out = [_claude(env), _codex(env), _opencode(env)]
    if dev_mode:
        out.append(Backend(FAKE, "Fake model (development only)", True, "",
                           ("fake-explorer",), Credentials(FAKE)))
    return out


def default_choice(env: Mapping[str, str] | None = None,
                   dev_mode: bool | None = None) -> tuple[str, str] | None:
    """The backend/model used when the target has none: the white-box executor
    (``VIGILO_EXECUTOR`` / auto-detection) if usable, else the first usable backend."""
    env = load_env() if env is None else env
    avail = [b for b in backends(env, dev_mode) if b.available]
    if not avail:
        return None
    from src.ai.executor import get_executor_type
    want = get_executor_type(env)
    # "fake" is only ever chosen explicitly unless it is all there is (dev/tests).
    real = [b for b in avail if b.id != FAKE]
    pool = real or avail
    pick = next((b for b in pool if b.id == want), pool[0])
    return pick.id, pick.models[0]


def validate_choice(backend: str, model: str, env: Mapping[str, str] | None = None,
                    dev_mode: bool | None = None) -> tuple[str, str]:
    """Normalise a (backend, model) pair; ``("", "")`` means "use the default".
    Raises :class:`ModelSelectionError` for unknown/unavailable backends or models."""
    backend, model = (backend or "").strip().lower(), (model or "").strip()
    if not backend:
        if model:
            raise ModelSelectionError("model_backend is required when model is set")
        return "", ""
    env = load_env() if env is None else env
    by_id = {b.id: b for b in backends(env, dev_mode)}
    b = by_id.get(backend)
    if b is None:
        raise ModelSelectionError(f"Unknown model backend: {backend}")
    if not b.available:
        raise ModelSelectionError(
            f"Model backend {backend} is not available: {b.reason}")
    if model and model not in b.models:
        raise ModelSelectionError(
            f"Model {model!r} is not offered by {backend} "
            f"(available: {', '.join(b.models)})")
    return backend, model or b.models[0]


NO_MODEL_MESSAGE = ("No AI model configured for grey-box exploration. Configure a "
                    "backend (ANTHROPIC_API_KEY or ANTHROPIC_FOUNDRY_API_KEY + "
                    "ANTHROPIC_FOUNDRY_BASE_URL, CODEX_*, LITELLM_*) as for white-box scans.")


def resolve_model(run_or_target: Any, env: Mapping[str, str] | None = None,
                  dev_mode: bool | None = None) -> ResolvedModel:
    """(backend, model, credentials) for a run (or target) from its ``model_backend`` /
    ``model`` fields, falling back to the default choice. Raises
    :class:`ModelSelectionError` when nothing usable is configured."""
    env = load_env() if env is None else env
    backend = (getattr(run_or_target, "model_backend", "") or "").strip().lower()
    model = (getattr(run_or_target, "model", "") or "").strip()
    if not backend:
        d = default_choice(env, dev_mode)
        if d is None:
            raise ModelSelectionError(NO_MODEL_MESSAGE)
        backend, model = d[0], model or d[1]
    b = next((x for x in backends(env, dev_mode) if x.id == backend), None)
    if b is None or not b.available or b.credentials is None:
        raise ModelSelectionError(
            f"Model backend {backend!r} is not available"
            + (f": {b.reason}" if b is not None and b.reason else ""))
    return ResolvedModel(backend, model or b.models[0], b.credentials)
