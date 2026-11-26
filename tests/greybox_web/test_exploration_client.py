"""Unit tests for the exploration model client.

Transport is always httpx.MockTransport: no test ever performs a real model call.
"""
from __future__ import annotations

import json

import httpx
import pytest

from src.greybox_web.exploration.client import (
    ANTHROPIC_DEFAULT_BASE,
    AgentBudget,
    AgentError,
    AgentUnavailable,
    AnthropicClient,
    FakeClient,
    OpenAICompatibleClient,
    build_client,
)


def _anthropic_transport(reply: dict, status: int = 200,
                        key: str = "k-123") -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/messages"
        assert request.headers["x-api-key"] == key
        assert request.headers["anthropic-version"] == "2023-06-01"
        body = json.loads(request.content)
        assert body["messages"][0]["role"] == "user" and body["messages"][0]["content"]
        assert isinstance(body["system"], str)
        return httpx.Response(status, json=reply)
    return httpx.MockTransport(handler)


async def test_anthropic_ok():
    c = AnthropicClient(api_key="k-123", model="claude-x", timeout_s=5,
                        transport=_anthropic_transport(
                            {"content": [{"type": "text", "text": "hello"}],
                             "model": "claude-x", "usage": {"input_tokens": 10,
                                                            "output_tokens": 5}}))
    r = await c.complete("be brief", "say hi")
    assert r.text == "hello" and r.model == "claude-x"
    assert r.input_tokens == 10 and r.output_tokens == 5
    assert r.total_tokens == 15 and r.latency_ms >= 0
    await c.aclose()


async def test_anthropic_http_error():
    c = AnthropicClient(api_key="k-123", transport=_anthropic_transport(
        {"error": "boom"}, status=500))
    with pytest.raises(AgentError, match="500"):
        await c.complete("s", "u")
    await c.aclose()


async def test_anthropic_no_text_content():
    c = AnthropicClient(api_key="k-123", transport=_anthropic_transport(
        {"content": [{"type": "tool_use"}], "usage": {}}))
    with pytest.raises(AgentError, match="no text"):
        await c.complete("s", "u")
    await c.aclose()


def _openai_transport(reply: dict) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/chat/completions")
        assert request.headers["authorization"] == "Bearer k-456"
        body = json.loads(request.content)
        assert body["messages"][0]["role"] == "system"
        return httpx.Response(200, json=reply)
    return httpx.MockTransport(handler)


async def test_openai_base_url_variants_and_ok():
    # base with and without /v1 both produce .../v1/chat/completions
    c1 = OpenAICompatibleClient(base_url="http://llm.local:8000/v1", api_key="k-456",
                                transport=_openai_transport(
        {"choices": [{"message": {"content": "hi"}}], "model": "m",
         "usage": {"prompt_tokens": 3, "completion_tokens": 2}}))
    c2 = OpenAICompatibleClient(base_url="http://llm.local:8000", api_key="k-456",
                                transport=_openai_transport(
        {"choices": [{"message": {"content": "hi"}}], "model": "m"}))
    assert c1.chat_url == c2.chat_url == "http://llm.local:8000/v1/chat/completions"
    r = await c1.complete("s", "u")
    assert r.text == "hi" and r.input_tokens == 3 and r.output_tokens == 2
    await c1.aclose()
    await c2.aclose()


async def test_openai_keyless_allowed():
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}],
                                         "usage": {}})
    c = OpenAICompatibleClient(base_url="http://ollama.local", api_key="",
                               transport=httpx.MockTransport(handler))
    r = await c.complete("s", "u")
    assert r.text == "x" and seen["auth"] is None
    await c.aclose()


async def test_fake_client_records_calls_and_estimates_usage():
    c = FakeClient(lambda s, u: f"{len(u)} chars")
    r = await c.complete("sys", "user-message")
    assert r.text == "12 chars"
    assert r.input_tokens >= 1 and r.output_tokens >= 1
    assert c.calls == [("sys", "user-message")]
    await c.aclose()


def test_agent_budget_math():
    b = AgentBudget(max_calls=2, max_tokens=10)
    assert b.allows() and b.calls_left == 2 and b.tokens_left == 10

    class R:                                    # spend() only needs total_tokens
        total_tokens = 4

    b.spend(R())                                # type: ignore[arg-type]
    assert b.calls_used == 1 and b.tokens_used == 4 and b.allows()
    b.spend(R())                                # type: ignore[arg-type]
    assert not b.allows()                       # calls exhausted
    assert b.as_dict() == {"max_calls": 2, "max_tokens": 10,
                           "calls_used": 2, "tokens_used": 8}


async def test_build_client_anthropic_needs_key():
    with pytest.raises(AgentUnavailable, match="no API key"):
        build_client("anthropic", timeout_s=5)


async def test_build_client_anthropic_from_resolved_credentials():
    c = build_client("anthropic", base_url="https://foundry.example",
                     api_key="fk-1", model="claude-x", timeout_s=5,
                     transport=_anthropic_transport(
                         {"content": [{"type": "text", "text": "x"}]}, key="fk-1"))
    assert c.api_key == "fk-1" and c.model == "claude-x"
    assert c.base_url == "https://foundry.example"
    await c.complete("s", "u")
    await c.aclose()


async def test_build_client_openai_needs_base_url():
    with pytest.raises(AgentUnavailable, match="base URL"):
        build_client("openai", api_key="k")
    with pytest.raises(AgentUnavailable, match="base URL"):
        build_client("openai-responses", api_key="k")


async def test_build_client_fake_protocol():
    c = build_client("fake", model="fake-explorer")
    assert isinstance(c, FakeClient)
    await c.aclose()


async def test_build_client_unknown_backend():
    with pytest.raises(AgentUnavailable, match="unknown agent backend"):
        build_client("nope")


def _responses_transport(reply: dict, status: int = 200) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v1/responses"
        assert request.headers["authorization"] == "Bearer k-789"
        body = json.loads(request.content)
        assert body["instructions"] == "sys" and body["input"] == "usr"
        assert body["model"] == "gpt-x"
        assert "messages" not in body
        return httpx.Response(status, json=reply)
    return httpx.MockTransport(handler)


async def test_openai_responses_output_items():
    c = build_client("openai-responses", base_url="http://gw.local/v1", api_key="k-789",
                     model="gpt-x", timeout_s=5, transport=_responses_transport({
        "model": "gpt-x-2025",
        "output": [{"type": "reasoning", "content": []},
                   {"type": "message", "content": [
                       {"type": "output_text", "text": "hel"},
                       {"type": "output_text", "text": "lo"}]}],
        "usage": {"input_tokens": 11, "output_tokens": 4}}))
    r = await c.complete("sys", "usr")
    assert r.text == "hello" and r.model == "gpt-x-2025"
    assert r.input_tokens == 11 and r.output_tokens == 4
    await c.aclose()


async def test_openai_responses_output_text_shortcut_and_base_variants():
    c = build_client("openai-responses", base_url="http://gw.local", api_key="k-789",
                     model="gpt-x", timeout_s=5, transport=_responses_transport(
        {"output_text": "direct", "usage": {"input_tokens": 1, "output_tokens": 2}}))
    assert c.responses_url == "http://gw.local/v1/responses"
    r = await c.complete("sys", "usr")
    assert r.text == "direct" and r.total_tokens == 3
    await c.aclose()


async def test_openai_responses_errors():
    c = build_client("openai-responses", base_url="http://gw.local/v1", api_key="k-789",
                     model="gpt-x", timeout_s=5,
                     transport=_responses_transport({"output": []}))
    with pytest.raises(AgentError, match="no text"):
        await c.complete("sys", "usr")
    await c.aclose()
    c = build_client("openai-responses", base_url="http://gw.local/v1", api_key="k-789",
                     model="gpt-x", timeout_s=5,
                     transport=_responses_transport({"error": "overloaded"}, 503))
    with pytest.raises(AgentError, match="503"):
        await c.complete("sys", "usr")
    await c.aclose()


def test_anthropic_default_base():
    assert ANTHROPIC_DEFAULT_BASE == "https://api.anthropic.com"


# ------------------------------------------------ native structured output (M-robust)

import ssl  # noqa: E402

from src.greybox_web.exploration.client import (  # noqa: E402
    AgentTLSError,
    OpenAIResponsesClient,
    build_ssl_context,
)
from src.greybox_web.exploration.schema import (  # noqa: E402
    PROPOSAL_SCHEMA,
    PROPOSAL_TOOL_NAME,
    parse_reply,
)

PROPOSAL = {"reasoning": "Fetch the root first to see what the app links to.",
            "assessment": "incomplete",
            "actions": [{"tool": "discovery.fetch_root", "params": {"url": "http://t/"},
                         "reason": "the first look at the target"}]}


def _recording(handler_reply):
    """A MockTransport that records request bodies and answers via ``handler_reply``."""
    seen: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        return handler_reply(body)
    return httpx.MockTransport(handler), seen


async def test_anthropic_forces_the_propose_tool_and_reads_its_input():
    tr, seen = _recording(lambda b: httpx.Response(200, json={
        "content": [{"type": "text", "text": "ok"},
                    {"type": "tool_use", "name": "propose", "input": PROPOSAL}],
        "stop_reason": "tool_use", "usage": {"input_tokens": 9, "output_tokens": 7}}))
    c = AnthropicClient(api_key="k", transport=tr)
    r = await c.complete("s", "u", schema=PROPOSAL_SCHEMA, max_output_tokens=5000)
    body = seen[0]
    assert body["tools"][0]["name"] == PROPOSAL_TOOL_NAME
    assert body["tools"][0]["input_schema"] == PROPOSAL_SCHEMA
    assert body["tool_choice"] == {"type": "tool", "name": PROPOSAL_TOOL_NAME}
    assert body["max_tokens"] == 5000
    assert r.mode == "tool" and r.structured == PROPOSAL and not r.truncated
    assert parse_reply(r.text).actions[0].tool == "discovery.fetch_root"
    await c.aclose()


async def test_anthropic_max_tokens_is_reported_as_truncated():
    tr, _ = _recording(lambda b: httpx.Response(200, json={
        "content": [{"type": "text", "text": '{"reasoning": "cut off in the mid'}],
        "stop_reason": "max_tokens", "usage": {"input_tokens": 9, "output_tokens": 2000}}))
    c = AnthropicClient(api_key="k", transport=tr)
    r = await c.complete("s", "u")
    assert r.truncated and r.stop_reason == "max_tokens" and r.output_tokens == 2000
    await c.aclose()


async def test_anthropic_falls_back_to_text_when_tools_are_rejected_and_remembers():
    def reply(b):
        if "tools" in b:
            return httpx.Response(400, json={"error": "tools not supported"})
        return httpx.Response(200, json={"content": [
            {"type": "text", "text": json.dumps(PROPOSAL)}], "usage": {}})
    tr, seen = _recording(reply)
    c = AnthropicClient(api_key="k", transport=tr)
    r1 = await c.complete("s", "u", schema=PROPOSAL_SCHEMA)
    assert r1.mode == "text" and parse_reply(r1.text).actions
    assert [("tools" in b) for b in seen] == [True, False] and not c.structured_ok
    await c.complete("s", "u", schema=PROPOSAL_SCHEMA)           # straight to text now
    assert [("tools" in b) for b in seen] == [True, False, False]
    await c.aclose()


async def test_anthropic_non_400_errors_do_not_trigger_the_fallback():
    tr, seen = _recording(lambda b: httpx.Response(500, json={"error": "boom"}))
    c = AnthropicClient(api_key="k", transport=tr)
    with pytest.raises(AgentError, match="500"):
        await c.complete("s", "u", schema=PROPOSAL_SCHEMA)
    assert len(seen) == 1 and c.structured_ok
    await c.aclose()


async def test_openai_chat_uses_json_schema_and_detects_length():
    tr, seen = _recording(lambda b: httpx.Response(200, json={
        "choices": [{"message": {"content": json.dumps(PROPOSAL)},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 6}}))
    c = OpenAICompatibleClient(base_url="http://llm.local/v1", transport=tr)
    r = await c.complete("s", "u", schema=PROPOSAL_SCHEMA)
    rf = seen[0]["response_format"]
    assert rf["type"] == "json_schema" and rf["json_schema"]["schema"] == PROPOSAL_SCHEMA
    assert rf["json_schema"]["strict"] is False
    assert r.mode == "json_schema" and parse_reply(r.text).actions
    await c.aclose()
    tr, _ = _recording(lambda b: httpx.Response(200, json={
        "choices": [{"message": {"content": '{"reasoning": "cut'},
                     "finish_reason": "length"}], "usage": {}}))
    c = OpenAICompatibleClient(base_url="http://llm.local/v1", transport=tr)
    r = await c.complete("s", "u")
    assert r.truncated and r.stop_reason == "length"
    await c.aclose()


async def test_openai_chat_falls_back_without_response_format():
    def reply(b):
        if "response_format" in b:
            return httpx.Response(400, json={"error": "unsupported response_format"})
        return httpx.Response(200, json={"choices": [
            {"message": {"content": json.dumps(PROPOSAL)}}], "usage": {}})
    tr, seen = _recording(reply)
    c = OpenAICompatibleClient(base_url="http://llm.local", transport=tr)
    r = await c.complete("s", "u", schema=PROPOSAL_SCHEMA)
    assert r.mode == "text" and not c.structured_ok and len(seen) == 2
    await c.aclose()


async def test_openai_chat_switches_to_max_completion_tokens_when_required():
    def reply(b):
        if "max_tokens" in b:
            return httpx.Response(400, json={"error": {
                "message": "Unsupported parameter: 'max_tokens'. Use "
                           "'max_completion_tokens' instead."}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}],
                                         "usage": {}})
    tr, seen = _recording(reply)
    c = OpenAICompatibleClient(base_url="http://llm.local", transport=tr)
    r = await c.complete("s", "u", max_output_tokens=777)
    assert r.text == "x" and seen[-1]["max_completion_tokens"] == 777
    assert c.structured_ok                                  # not mistaken for a schema error
    await c.aclose()


def _resp_client(handler_reply):
    tr, seen = _recording(handler_reply)
    return OpenAIResponsesClient(base_url="http://gw.local/v1", api_key="k",
                                 model="gpt-x", transport=tr), seen


async def test_responses_uses_text_format_json_schema_and_skips_reasoning_items():
    c, seen = _resp_client(lambda b: httpx.Response(200, json={
        "status": "completed", "model": "gpt-x",
        "output": [{"type": "reasoning", "summary": [], "content": []},
                   {"type": "message", "content": [
                       {"type": "output_text", "text": json.dumps(PROPOSAL)}]}],
        "usage": {"input_tokens": 5, "output_tokens": 50}}))
    r = await c.complete("s", "u", schema=PROPOSAL_SCHEMA, max_output_tokens=9000)
    fmt = seen[0]["text"]["format"]
    assert fmt["type"] == "json_schema" and fmt["schema"] == PROPOSAL_SCHEMA
    assert fmt["name"] == PROPOSAL_TOOL_NAME and fmt["strict"] is False
    assert seen[0]["max_output_tokens"] == 9000
    assert r.mode == "json_schema" and not r.truncated and r.stop_reason == "completed"
    assert parse_reply(r.text).actions
    await c.aclose()


async def test_responses_incomplete_with_partial_text_is_truncated_not_an_error():
    """The maintainer's failure: status incomplete / max_output_tokens, the visible
    text is a JSON object cut mid-way (the limit also covers hidden reasoning)."""
    cut = json.dumps(PROPOSAL)[:-25]
    c, _ = _resp_client(lambda b: httpx.Response(200, json={
        "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
        "output": [{"type": "reasoning", "content": []},
                   {"type": "message", "content": [
                       {"type": "output_text", "text": cut}]}],
        "usage": {"input_tokens": 5, "output_tokens": 2000}}))
    r = await c.complete("s", "u")
    assert r.truncated and r.stop_reason == "max_output_tokens"
    assert r.text == cut and r.output_tokens == 2000
    await c.aclose()


async def test_responses_incomplete_with_only_reasoning_returns_an_empty_truncated_reply():
    c, _ = _resp_client(lambda b: httpx.Response(200, json={
        "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"},
        "output": [{"type": "reasoning", "content": []}],
        "usage": {"input_tokens": 5, "output_tokens": 2000}}))
    r = await c.complete("s", "u")
    assert r.truncated and r.text == ""          # the caller retries; no "no text" error
    await c.aclose()


async def test_responses_falls_back_when_text_format_is_rejected():
    def reply(b):
        if "text" in b:
            return httpx.Response(400, json={"error": "unknown parameter: text.format"})
        return httpx.Response(200, json={"output_text": json.dumps(PROPOSAL),
                                         "usage": {}})
    c, seen = _resp_client(reply)
    r = await c.complete("s", "u", schema=PROPOSAL_SCHEMA)
    assert r.mode == "text" and not c.structured_ok and len(seen) == 2
    await c.complete("s", "u", schema=PROPOSAL_SCHEMA)
    assert len(seen) == 3 and "text" not in seen[-1]
    await c.aclose()


async def test_responses_refusal_is_an_error():
    c, _ = _resp_client(lambda b: httpx.Response(200, json={
        "status": "completed", "output": [{"type": "message", "content": [
            {"type": "refusal", "refusal": "I cannot help with that"}]}]}))
    with pytest.raises(AgentError, match="refused"):
        await c.complete("s", "u")
    await c.aclose()


async def test_tls_verification_failure_is_a_clear_non_retryable_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        cause = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable "
               "to get local issuer certificate")
        raise httpx.ConnectError("tls", request=request) from cause

    c = OpenAIResponsesClient(base_url="https://llm.corp.example/v1", api_key="k",
                              transport=httpx.MockTransport(handler))
    with pytest.raises(AgentTLSError) as ei:
        await c.complete("s", "u")
    msg = str(ei.value)
    assert "llm.corp.example" in msg and "SSL_CERT_FILE" in msg
    assert ei.value.retryable is False
    await c.aclose()


async def test_rejected_handshake_retries_once_with_p256_key_exchange():
    """A middlebox that drops the default (post-quantum hybrid) ClientHello: the
    client retries once with the key exchange pinned to P-256 and keeps it."""
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            cause = ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF "
                                       "occurred in violation of protocol")
            raise httpx.ConnectError("", request=request) from cause
        return httpx.Response(200, json={
            "output_text": "ok", "usage": {"input_tokens": 1, "output_tokens": 1}})

    c = OpenAIResponsesClient(base_url="https://llm.corp.example/v1", api_key="k",
                              transport=httpx.MockTransport(handler))
    reply = await c.complete("s", "u")
    assert reply.text == "ok" and calls["n"] == 2 and c.tls_fallback
    await c.complete("s", "u")                       # no further fallback round-trip
    assert calls["n"] == 3
    await c.aclose()


async def test_handshake_fallback_is_attempted_once_and_errors_are_readable():
    async def handler(request: httpx.Request) -> httpx.Response:
        cause = ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF")
        raise httpx.ConnectError("", request=request) from cause

    c = OpenAIResponsesClient(base_url="https://llm.corp.example/v1", api_key="k",
                              transport=httpx.MockTransport(handler))
    with pytest.raises(AgentError) as ei:
        await c.complete("s", "u")
    msg = str(ei.value)
    # never the blank "model transport failed: " the UI used to show
    assert "ConnectError" in msg and "SSLEOFError" in msg and "UNEXPECTED_EOF" in msg
    assert c.tls_fallback
    await c.aclose()


async def test_certificate_failures_do_not_trigger_the_handshake_fallback():
    async def handler(request: httpx.Request) -> httpx.Response:
        cause = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED]")
        raise httpx.ConnectError("tls", request=request) from cause

    c = OpenAIResponsesClient(base_url="https://llm.corp.example/v1", api_key="k",
                              transport=httpx.MockTransport(handler))
    with pytest.raises(AgentTLSError):
        await c.complete("s", "u")
    assert not c.tls_fallback
    await c.aclose()


def test_fallback_ssl_context_still_verifies():
    ctx = build_ssl_context("prime256v1")
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


async def test_auth_failures_are_not_retryable():
    tr, _ = _recording(lambda b: httpx.Response(401, json={"error": "bad key"}))
    c = AnthropicClient(api_key="k", transport=tr)
    with pytest.raises(AgentError) as ei:
        await c.complete("s", "u")
    assert ei.value.retryable is False
    await c.aclose()


def test_ssl_context_verifies_and_honours_ca_bundle_env(monkeypatch, tmp_path):
    import certifi
    monkeypatch.setenv("SSL_CERT_FILE", certifi.where())
    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "missing.pem"))
    assert build_ssl_context().verify_mode == ssl.CERT_REQUIRED   # missing file: ignored
