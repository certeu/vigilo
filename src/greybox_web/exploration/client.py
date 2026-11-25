"""Provider-neutral model client for the exploration agent.

One call shape — ``complete(system, user) -> ModelReply`` — behind three wire
protocols. Which backend/model a run uses is decided by ``src.greybox_web.modelsel``
(the backends white-box already defines, selected per target/run); this module only
speaks the protocol it is handed:

* ``anthropic`` — the Messages API, including Anthropic-compatible gateways (Azure
  Foundry);
* ``openai``    — any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI,
  LiteLLM, Ollama, vLLM);
* ``openai-responses`` — the OpenAI Responses API (``/responses``), Codex's default;
* ``fake``      — a deterministic responder, dev mode and tests only.

The client is transport-injectable (``httpx.MockTransport`` in tests), enforces a
per-call timeout, and reports usage so the caller can enforce the per-run budget.
It never sees a shell, the filesystem, or the target: prompts in, text out.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

# Reasoning models (gpt-5, o-series) spend part of the output limit on hidden
# reasoning: 2000 left too little for the visible reply and cut it mid-JSON.
DEFAULT_MAX_OUTPUT_TOKENS = 8000
MAX_OUTPUT_TOKENS_CAP = 16000
log = logging.getLogger("greybox.explorer")

ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"
# Defaults only apply when the resolved model is empty.
ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-5-5"
OPENAI_DEFAULT_MODEL = "gpt-4o-mini"      # OpenAI-compatible gateways usually need an explicit model
OPENAI_DEFAULT_BASE = "https://api.openai.com"


class AgentError(Exception):
    """A model call failed (transport, HTTP, or malformed response).
    ``retryable=False`` marks a failure that repeating cannot fix (TLS trust, bad
    credentials): the explorer does not retry it within the cycle."""

    retryable = True


class AgentTLSError(AgentError):
    """The model endpoint's certificate could not be verified."""

    retryable = False


class AgentUnavailable(Exception):
    """The backend is configured but unusable (e.g. no API key)."""


@dataclass(frozen=True)
class ModelReply:
    text: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    stop_reason: str = ""            # provider's stop / finish reason / incomplete reason
    truncated: bool = False          # cut at the output-token limit
    mode: str = "text"               # text | tool | json_schema (how it was produced)
    structured: Any = None           # decoded tool-call input / schema output, if any

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class AgentBudget:
    """Per-run model budget, enforced by the caller (the explorer)."""

    max_calls: int = 300
    max_tokens: int = 6_000_000
    calls_used: int = 0
    tokens_used: int = 0

    @property
    def calls_left(self) -> int:
        return max(0, self.max_calls - self.calls_used)

    @property
    def tokens_left(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    def allows(self) -> bool:
        return self.calls_left > 0 and self.tokens_left > 0

    def spend(self, reply: ModelReply) -> None:
        self.calls_used += 1
        self.tokens_used += reply.total_tokens

    def as_dict(self) -> dict[str, Any]:
        return {"max_calls": self.max_calls, "max_tokens": self.max_tokens,
                "calls_used": self.calls_used, "tokens_used": self.tokens_used}


_CA_ENV = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")


#: The key-exchange group of the handshake fallback. P-256 is mandatory-to-implement
#: in TLS 1.3 (RFC 8446 §9.1), so every conforming endpoint accepts it.
FALLBACK_ECDH_CURVE = "prime256v1"


def build_ssl_context(ecdh_curve: str | None = None) -> ssl.SSLContext:
    """The TLS context for model calls. Verification is always on. Trust comes from
    the operating system store (``truststore`` when installed: macOS keychain /
    Windows store, so a corporate proxy CA works) or OpenSSL's default paths, plus any
    bundle named by ``SSL_CERT_FILE`` / ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE``
    (what the codex / claude CLIs honour), plus the certifi public roots.

    ``ecdh_curve`` pins the key exchange to one group (the handshake fallback, see
    :meth:`ModelClient._post`); it uses a plain OpenSSL context because ``truststore``
    does not expose the group setting."""
    ctx: ssl.SSLContext
    if ecdh_curve:
        ctx = ssl.create_default_context()
        ctx.set_ecdh_curve(ecdh_curve)
    else:
        try:
            import truststore                      # type: ignore[import-not-found]
            ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:                           # noqa: BLE001 — optional package
            ctx = ssl.create_default_context()
    for var in _CA_ENV:
        path = os.environ.get(var)
        if path and os.path.isfile(path):
            try:
                ctx.load_verify_locations(cafile=path)
            except (ssl.SSLError, OSError, NotImplementedError):
                log.warning("could not load the CA bundle from %s", var)
    if not hasattr(ctx, "_ctx"):                    # a plain ssl context: add certifi
        try:
            import certifi
            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:                           # noqa: BLE001
            pass
    return ctx


def _is_tls_error(exc: BaseException) -> bool:
    cur: BaseException | None = exc
    for _ in range(6):
        if cur is None:
            return False
        if isinstance(cur, ssl.SSLCertVerificationError) \
                or "CERTIFICATE_VERIFY_FAILED" in str(cur):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _is_handshake_rejected(exc: BaseException) -> bool:
    """The TLS handshake was cut off or refused (not a certificate problem): the
    connection dropped mid-handshake (``SSLEOFError``) or the peer answered with a
    ``protocol_version`` / ``handshake_failure`` alert. Seen behind middleboxes that
    mishandle the hybrid post-quantum key share OpenSSL >= 3.5 offers by default."""
    cur: BaseException | None = exc
    for _ in range(6):
        if cur is None:
            return False
        if isinstance(cur, ssl.SSLCertVerificationError):
            return False
        if isinstance(cur, ssl.SSLEOFError):
            return True
        if isinstance(cur, ssl.SSLError) and any(
                a in str(cur) for a in ("ALERT_PROTOCOL_VERSION",
                                        "ALERT_HANDSHAKE_FAILURE")):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _describe(exc: BaseException) -> str:
    """A readable transport error: httpx errors often stringify to ``""``, so name
    the exception and its root cause (``ConnectError: SSLEOFError: EOF ...``)."""
    parts: list[str] = []
    cur: BaseException | None = exc
    for _ in range(6):
        if cur is None:
            break
        text = str(cur).strip()
        parts.append(f"{type(cur).__name__}: {text}" if text else type(cur).__name__)
        cur = cur.__cause__ or cur.__context__
    # keep the outermost and the root cause; the middle links add noise
    return parts[0] if len(parts) == 1 else f"{parts[0]} (cause: {parts[-1]})"


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + path


def _openai_chat_url(base: str) -> str:
    """A chat-completions URL; ``base`` may or may not already end in ``/v1``."""
    b = (base or OPENAI_DEFAULT_BASE).rstrip("/")
    return b + ("" if b.endswith("/v1") else "/v1") + "/chat/completions"


class StructuredRejected(AgentError):
    """The provider refused the structured-output request (HTTP 400/422)."""


def _excerpt(r: httpx.Response) -> str:
    return r.text[:200]


class ModelClient:
    """The call contract. Implementations hold one ``httpx.AsyncClient`` each.

    ``complete`` takes an optional JSON ``schema``: the client then asks the provider
    for native structured output (tool use / ``json_schema``). When the provider
    rejects that mode (HTTP 400) the call is repeated as plain text, and the client
    remembers (``structured_ok``) so later calls go straight to text. Either way the
    caller gets a :class:`ModelReply` whose ``text`` is parseable by the tolerant
    ``schema.parse_reply``."""

    def __init__(self, *, model: str, timeout_s: float,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.model = model
        self.timeout_s = timeout_s
        self.structured_ok = True
        self.tls_fallback = False          # key exchange pinned to FALLBACK_ECDH_CURVE
        self._transport = transport
        self._http = httpx.AsyncClient(
            timeout=timeout_s, transport=transport,
            **({"verify": build_ssl_context()} if transport is None else {}))

    async def _enable_tls_fallback(self) -> None:
        """Rebuild the HTTP client with the key exchange pinned to P-256 (verification
        unchanged). Done at most once per client."""
        self.tls_fallback = True
        old = self._http
        self._http = httpx.AsyncClient(
            timeout=self.timeout_s, transport=self._transport,
            **({"verify": build_ssl_context(FALLBACK_ECDH_CURVE)}
               if self._transport is None else {}))
        await old.aclose()

    async def complete(self, system: str, user: str, *,
                       max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
                       schema: dict[str, Any] | None = None) -> ModelReply:
        if schema is not None and self.structured_ok:
            try:
                return await self._call(system, user, max_output_tokens, schema)
            except StructuredRejected as exc:
                self.structured_ok = False
                log.info("%s rejected structured output (%s); falling back to text",
                         type(self).__name__, str(exc)[:160])
        return await self._call(system, user, max_output_tokens, None)

    async def _call(self, system: str, user: str, max_output_tokens: int,
                    schema: dict[str, Any] | None) -> ModelReply:
        raise NotImplementedError

    async def _post(self, url: str, headers: dict[str, str], body: dict[str, Any],
                    structured: bool) -> httpx.Response:
        try:
            try:
                r = await self._http.post(url, headers=headers, json=body)
            except httpx.HTTPError as exc:
                if self.tls_fallback or not _is_handshake_rejected(exc):
                    raise
                log.warning("TLS handshake with %s was rejected (%s); retrying with "
                            "the key exchange pinned to %s", httpx.URL(url).host,
                            _describe(exc), FALLBACK_ECDH_CURVE)
                await self._enable_tls_fallback()
                r = await self._http.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            if _is_tls_error(exc):
                host = httpx.URL(url).host
                raise AgentTLSError(
                    f"TLS certificate verification failed for {host}: set "
                    "SSL_CERT_FILE (or REQUESTS_CA_BUNDLE) to a CA bundle that "
                    "trusts the endpoint, or install the 'truststore' package to "
                    "use the system store (verification stays on)") from exc
            raise AgentError(f"model transport failed: {_describe(exc)}") from exc
        if r.status_code in (401, 403):
            err = AgentError(f"model API returned {r.status_code}: {_excerpt(r)}")
            err.retryable = False
            raise err
        if r.status_code in (400, 422) and structured:
            raise StructuredRejected(f"model API returned {r.status_code}: "
                                     f"{_excerpt(r)}")
        if r.status_code >= 400:
            raise AgentError(f"model API returned {r.status_code}: {_excerpt(r)}")
        return r

    async def aclose(self) -> None:
        await self._http.aclose()


class AnthropicClient(ModelClient):
    """Anthropic Messages API, or any Anthropic-compatible gateway. Structured mode:
    one tool ``propose`` with the schema as ``input_schema``, ``tool_choice`` forced."""

    def __init__(self, *, api_key: str, base_url: str = ANTHROPIC_DEFAULT_BASE,
                 model: str = "", timeout_s: float = 60.0, version: str = "2023-06-01",
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(model=model or ANTHROPIC_DEFAULT_MODEL, timeout_s=timeout_s,
                         transport=transport)
        self.api_key = api_key
        self.base_url = (base_url or ANTHROPIC_DEFAULT_BASE).rstrip("/")
        self.version = version

    async def _call(self, system: str, user: str, max_output_tokens: int,
                    schema: dict[str, Any] | None) -> ModelReply:
        from src.greybox_web.exploration.schema import (
            PROPOSAL_TOOL_DESCRIPTION,
            PROPOSAL_TOOL_NAME,
        )
        start = time.monotonic()
        body: dict[str, Any] = {
            "model": self.model, "max_tokens": max_output_tokens, "system": system,
            "messages": [{"role": "user", "content": user}]}
        if schema is not None:
            body["tools"] = [{"name": PROPOSAL_TOOL_NAME,
                              "description": PROPOSAL_TOOL_DESCRIPTION,
                              "input_schema": schema}]
            body["tool_choice"] = {"type": "tool", "name": PROPOSAL_TOOL_NAME}
        r = await self._post(
            _join(self.base_url, "/v1/messages"),
            {"x-api-key": self.api_key, "anthropic-version": self.version,
             "content-type": "application/json"}, body, schema is not None)
        try:
            data = r.json()
            blocks = [b for b in data.get("content", []) if isinstance(b, dict)]
            text = "".join(b.get("text", "") for b in blocks
                           if b.get("type") == "text")
            tool = next((b.get("input") for b in blocks
                         if b.get("type") == "tool_use"
                         and isinstance(b.get("input"), dict) and b.get("input")),
                        None)
            usage = data.get("usage") or {}
            stop = str(data.get("stop_reason") or "")
        except (ValueError, AttributeError) as exc:
            raise AgentError("model API returned malformed JSON") from exc
        truncated = stop == "max_tokens"
        mode = "text"
        if tool is not None:
            mode, text = "tool", json.dumps(tool)
        if not text and not truncated:
            raise AgentError("model API returned no text content")
        return ModelReply(
            text=text, model=str(data.get("model") or self.model),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            latency_ms=int((time.monotonic() - start) * 1000),
            stop_reason=stop, truncated=truncated, mode=mode, structured=tool)


class OpenAICompatibleClient(ModelClient):
    """Any OpenAI-compatible chat-completions endpoint. Structured mode:
    ``response_format: json_schema`` (non-strict, so free-form ``params`` work)."""

    def __init__(self, *, base_url: str, api_key: str = "", model: str = "",
                 timeout_s: float = 60.0,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(model=model or OPENAI_DEFAULT_MODEL, timeout_s=timeout_s,
                         transport=transport)
        self.chat_url = _openai_chat_url(base_url)
        self.api_key = api_key
        self._token_param = "max_tokens"      # newer models want max_completion_tokens

    async def _call(self, system: str, user: str, max_output_tokens: int,
                    schema: dict[str, Any] | None) -> ModelReply:
        from src.greybox_web.exploration.schema import PROPOSAL_TOOL_NAME
        start = time.monotonic()
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        for _ in range(2):
            body: dict[str, Any] = {
                self._token_param: max_output_tokens, "model": self.model,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
            if schema is not None:
                body["response_format"] = {"type": "json_schema", "json_schema": {
                    "name": PROPOSAL_TOOL_NAME, "schema": schema, "strict": False}}
            try:
                r = await self._post(self.chat_url, headers, body,
                                     schema is not None)
                break
            except AgentError as exc:
                if self._token_param == "max_tokens" \
                        and "max_completion_tokens" in str(exc):
                    self._token_param = "max_completion_tokens"
                    continue
                raise
        try:
            data = r.json()
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            text = str(msg.get("content") or "")
            usage = data.get("usage") or {}
            stop = str(choice.get("finish_reason") or "")
        except (ValueError, IndexError, AttributeError) as exc:
            raise AgentError("model API returned malformed JSON") from exc
        truncated = stop == "length"
        if not text and msg.get("refusal"):
            raise AgentError(f"model refused: {str(msg['refusal'])[:160]}")
        if not text and not truncated:
            raise AgentError("model API returned no text content")
        return ModelReply(
            text=text, model=str(data.get("model") or self.model),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
            latency_ms=int((time.monotonic() - start) * 1000),
            stop_reason=stop, truncated=truncated,
            mode="json_schema" if schema is not None else "text")


class OpenAIResponsesClient(ModelClient):
    """The OpenAI Responses API (``POST {base}/responses``): the wire format Codex
    uses by default. ``instructions`` carries the system prompt, ``input`` the user
    message. Structured mode: ``text.format: json_schema``. The reply text is gathered
    from the ``output_text`` parts of the ``message`` items (``reasoning`` items are
    skipped); ``status: incomplete`` (``max_output_tokens``) marks a truncated reply —
    on reasoning models the limit also covers the hidden reasoning."""

    def __init__(self, *, base_url: str, api_key: str = "", model: str = "",
                 timeout_s: float = 60.0,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(model=model or OPENAI_DEFAULT_MODEL, timeout_s=timeout_s,
                         transport=transport)
        base = (base_url or OPENAI_DEFAULT_BASE).rstrip("/")
        self.responses_url = base + ("" if base.endswith("/v1") else "/v1") + "/responses"
        self.api_key = api_key

    async def _call(self, system: str, user: str, max_output_tokens: int,
                    schema: dict[str, Any] | None) -> ModelReply:
        from src.greybox_web.exploration.schema import PROPOSAL_TOOL_NAME
        start = time.monotonic()
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        body: dict[str, Any] = {"model": self.model, "instructions": system,
                                "input": user, "max_output_tokens": max_output_tokens}
        if schema is not None:
            body["text"] = {"format": {"type": "json_schema",
                                       "name": PROPOSAL_TOOL_NAME, "schema": schema,
                                       "strict": False}}
        r = await self._post(self.responses_url, headers, body, schema is not None)
        try:
            data = r.json()
            parts: list[str] = []
            refusal = ""
            for item in data.get("output") or []:
                if not isinstance(item, dict) or item.get("type") == "reasoning":
                    continue
                for c in item.get("content") or []:
                    if not isinstance(c, dict):
                        continue
                    if c.get("type") == "output_text":
                        parts.append(str(c.get("text") or ""))
                    elif c.get("type") == "refusal":
                        refusal = str(c.get("refusal") or "")
            text = "".join(parts)
            if not text and isinstance(data.get("output_text"), str):
                text = data["output_text"]
            usage = data.get("usage") or {}
            status = str(data.get("status") or "")
            reason = str((data.get("incomplete_details") or {}).get("reason") or "")
        except (ValueError, AttributeError, TypeError) as exc:
            raise AgentError("model API returned malformed JSON") from exc
        truncated = status == "incomplete" or reason in (
            "max_output_tokens", "max_tokens")
        if not text and refusal:
            raise AgentError(f"model refused: {refusal[:160]}")
        if not text and not truncated:
            raise AgentError("model API returned no text content")
        return ModelReply(
            text=text, model=str(data.get("model") or self.model),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            latency_ms=int((time.monotonic() - start) * 1000),
            stop_reason=reason or status, truncated=truncated,
            mode="json_schema" if schema is not None else "text")


Responder = Callable[[str, str], str]


class FakeClient(ModelClient):
    """A deterministic responder (tests, dev mode, the E2E suite, and the
    behavioural acceptance test). Usage is estimated; latency is simulated small."""

    def __init__(self, responder: Responder, *, model: str = "fake-explorer",
                 latency_ms: int = 5) -> None:
        super().__init__(model=model, timeout_s=10.0)
        self.responder = responder
        self.latency_ms = latency_ms
        self.calls: list[tuple[str, str]] = []

    async def complete(self, system: str, user: str, *,
                       max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
                       schema: dict[str, Any] | None = None) -> ModelReply:
        self.calls.append((system, user))
        text = self.responder(system, user)
        if not isinstance(text, str):
            raise AgentError("fake responder must return a string")
        return ModelReply(
            text=text, model=self.model,
            input_tokens=max(1, (len(system) + len(user)) // 4),
            output_tokens=max(1, len(text) // 4),
            latency_ms=self.latency_ms)


def build_client(protocol: str, *, base_url: str = "", api_key: str = "",
                 model: str = "", timeout_s: float | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> ModelClient:
    """The client for one wire protocol ("anthropic" | "openai" | "fake") with the
    given endpoint, key and model (as resolved by ``modelsel.resolve_model``).
    Raises :class:`AgentUnavailable` when the protocol is unknown or unusable."""
    from src.greybox_web import settings as gb_settings
    timeout = float(timeout_s if timeout_s is not None
                    else gb_settings.settings().greybox_agent_timeout_s)
    if protocol == "anthropic":
        if not api_key:
            raise AgentUnavailable("anthropic backend configured but no API key")
        client: ModelClient = AnthropicClient(
            api_key=api_key, base_url=base_url or ANTHROPIC_DEFAULT_BASE,
            model=model, timeout_s=timeout, transport=transport)
    elif protocol == "openai":
        if not base_url:
            raise AgentUnavailable("openai backend configured but no base URL")
        client = OpenAICompatibleClient(
            base_url=base_url, api_key=api_key, model=model, timeout_s=timeout,
            transport=transport)
    elif protocol == "openai-responses":
        if not base_url:
            raise AgentUnavailable("openai-responses backend configured but no base URL")
        client = OpenAIResponsesClient(
            base_url=base_url, api_key=api_key, model=model, timeout_s=timeout,
            transport=transport)
    elif protocol == "fake":
        # The default fake is a knowledge-reactive model (fake.py); tests inject
        # their own responder or client.
        from src.greybox_web.exploration.fake import heuristic_responder
        client = FakeClient(heuristic_responder, model=model or "fake-explorer")
    else:
        raise AgentUnavailable(f"unknown agent backend {protocol!r}")
    log.info("exploration agent client: protocol=%s model=%s", protocol, client.model)
    return client
