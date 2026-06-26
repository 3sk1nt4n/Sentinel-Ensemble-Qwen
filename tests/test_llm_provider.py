"""Unit tests for the Qwen Cloud (DashScope) provider adapter.

Verifies the adapter is a drop-in for the Anthropic `messages.create` surface:
provider selection by env, Anthropic->OpenAI message translation (cache_control
dropped), the duck-typed response shape the pipeline reads, and fail-closed
behavior when no key is set. No network calls -- urlopen is mocked.
"""
import io
import json
import urllib.error
import urllib.request

import pytest

from sift_sentinel import llm_provider as lp


def _http_error(code, body=b"err", headers=None):
    """Build a urllib HTTPError whose .read() yields *body* (a DashScope 4xx/5xx)."""
    return urllib.error.HTTPError("http://x", code, "err", headers or {},
                                  io.BytesIO(body))


def _fake_urlopen(payload):
    """A urllib.request.urlopen stand-in returning a fixed JSON payload."""
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    def _open(req, timeout=None):
        _open.captured = req
        return _Resp()

    return _open


def test_active_provider_default(monkeypatch):
    monkeypatch.delenv("SIFT_LLM_PROVIDER", raising=False)
    assert lp.active_provider() == "anthropic"
    assert lp.is_qwen() is False


def test_active_provider_qwen(monkeypatch):
    monkeypatch.setenv("SIFT_LLM_PROVIDER", "qwen")
    assert lp.is_qwen() is True
    assert isinstance(lp.make_llm_client(), lp.QwenClient)


def test_flatten_content_str_and_blocks():
    assert lp._flatten_content("hi") == "hi"
    blocks = [
        {"type": "text", "text": "a", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "b"},
    ]
    assert lp._flatten_content(blocks) == "ab"
    assert lp._flatten_content(None) == ""


def test_qwen_create_parses_openai_response(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    payload = {
        "model": "qwen-max",
        "choices": [
            {"message": {"role": "assistant", "content": '{"ok": true}'}},
        ],
        "usage": {"prompt_tokens": 12, "completion_tokens": 7},
    }
    fake = _fake_urlopen(payload)
    monkeypatch.setattr(urllib.request, "urlopen", fake)

    client = lp.QwenClient()
    # Anthropic-style content blocks WITH cache_control must be tolerated
    resp = client.messages.create(
        model="qwen-max",
        max_tokens=64,
        temperature=0,
        timeout=30,
        messages=[{
            "role": "user",
            "content": [{
                "type": "text", "text": "find evil",
                "cache_control": {"type": "ephemeral"},
            }],
        }],
        thinking={"type": "enabled", "budget_tokens": 1024},  # ignored gracefully
    )

    # duck-typed Anthropic response surface the pipeline reads
    assert resp.content[0].text == '{"ok": true}'
    assert resp.usage.input_tokens == 12
    assert resp.usage.output_tokens == 7
    assert resp.usage.cache_read_input_tokens == 0
    assert resp.usage.cache_creation_input_tokens == 0

    # request body is OpenAI-shaped, cache_control dropped, auth header set
    sent = json.loads(fake.captured.data.decode("utf-8"))
    assert sent["model"] == "qwen-max"
    assert sent["messages"][0]["content"] == "find evil"
    assert sent["max_tokens"] == 64
    assert sent["temperature"] == 0
    assert fake.captured.get_header("Authorization") == "Bearer sk-test"


def test_qwen_missing_key_raises(monkeypatch):
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.delenv("QWEN_API_KEY", raising=False)
    client = lp.QwenClient()
    with pytest.raises(OSError):
        client.messages.create(
            model="qwen-max",
            messages=[{"role": "user", "content": "x"}],
        )


def test_qwen_clamps_max_tokens_to_dashscope_cap(monkeypatch):
    """max_tokens above the default 8192 cap is clamped (prevents the qwen-max 400)."""
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.delenv("SIFT_MAX_OUTPUT_TOKENS", raising=False)
    fake = _fake_urlopen({"choices": [{"message": {"content": "{}"}}], "usage": {}})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    lp.QwenClient().messages.create(
        model="qwen3.7-max", max_tokens=16384,
        messages=[{"role": "user", "content": "x"}],
    )
    sent = json.loads(fake.captured.data.decode("utf-8"))
    assert sent["max_tokens"] == 8192


def test_qwen_max_output_tokens_override(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setenv("SIFT_MAX_OUTPUT_TOKENS", "16384")
    fake = _fake_urlopen({"choices": [{"message": {"content": "{}"}}], "usage": {}})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    lp.QwenClient().messages.create(
        model="qwen3.7-max", max_tokens=16384,
        messages=[{"role": "user", "content": "x"}],
    )
    sent = json.loads(fake.captured.data.decode("utf-8"))
    assert sent["max_tokens"] == 16384


def test_qwen_reasoning_content_fallback(monkeypatch):
    """Reasoning models can return empty content with the answer in reasoning_content."""
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    payload = {"choices": [{"message": {"content": "",
                                        "reasoning_content": "the answer"},
                            "finish_reason": "stop"}], "usage": {}}
    fake = _fake_urlopen(payload)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    resp = lp.QwenClient().messages.create(
        model="qwen3-thinking", messages=[{"role": "user", "content": "x"}])
    assert resp.content[0].text == "the answer"


def test_qwen_finish_reason_length_maps_to_max_tokens(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    payload = {"choices": [{"message": {"content": "x"},
                            "finish_reason": "length"}], "usage": {}}
    fake = _fake_urlopen(payload)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    resp = lp.QwenClient().messages.create(
        model="qwen-plus", messages=[{"role": "user", "content": "x"}])
    assert resp.stop_reason == "max_tokens"


def test_qwen_retries_on_429_then_succeeds(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setattr(lp.time, "sleep", lambda *_a, **_k: None)
    ok = {"choices": [{"message": {"content": "ok"}}],
          "usage": {"prompt_tokens": 1, "completion_tokens": 1}}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(ok).encode("utf-8")

    calls = {"n": 0}

    def _open(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(429, b"rate limited")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    resp = lp.QwenClient().messages.create(
        model="qwen-plus", messages=[{"role": "user", "content": "x"}])
    assert resp.content[0].text == "ok"
    assert calls["n"] == 2   # retried exactly once


def test_qwen_http_400_not_retried_and_keeps_body(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setattr(lp.time, "sleep", lambda *_a, **_k: None)
    calls = {"n": 0}

    def _open(req, timeout=None):
        calls["n"] += 1
        raise _http_error(400, b"invalid_parameter: max_tokens exceeds limit")

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    with pytest.raises(OSError) as ei:
        lp.QwenClient().messages.create(
            model="qwen3.7-max", max_tokens=10,
            messages=[{"role": "user", "content": "x"}])
    assert "400" in str(ei.value) and "max_tokens" in str(ei.value)
    assert calls["n"] == 1   # 4xx is not retried


def test_qwen_urlerror_raises_oserror(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setattr(lp.time, "sleep", lambda *_a, **_k: None)

    def _open(req, timeout=None):
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    with pytest.raises(OSError):
        lp.QwenClient().messages.create(
            model="qwen-plus", messages=[{"role": "user", "content": "x"}])


def test_make_llm_client_default_is_anthropic(monkeypatch):
    """Zero-regression: with no provider env, the factory returns the Anthropic SDK."""
    monkeypatch.delenv("SIFT_LLM_PROVIDER", raising=False)
    anthropic = pytest.importorskip("anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert isinstance(lp.make_llm_client(), anthropic.Anthropic)


def test_qwen_retries_on_read_timeout_then_succeeds(monkeypatch):
    """A socket READ timeout raises a bare TimeoutError (NOT a urllib.URLError),
    so it must be caught and retried -- otherwise it escapes unretried and
    silently zeroes the qwen3.7-max ensemble (real bug seen on a paired run)."""
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setattr(lp.time, "sleep", lambda *_a, **_k: None)
    ok = {"choices": [{"message": {"content": "ok"}}],
          "usage": {"prompt_tokens": 1, "completion_tokens": 1}}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(ok).encode("utf-8")

    calls = {"n": 0}

    def _open(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("The read operation timed out")
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    resp = lp.QwenClient().messages.create(
        model="qwen3.7-max", messages=[{"role": "user", "content": "x"}])
    assert resp.content[0].text == "ok"
    assert calls["n"] == 2   # retried once after the read timeout


def test_qwen_read_timeout_exhausts_to_oserror(monkeypatch):
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setattr(lp.time, "sleep", lambda *_a, **_k: None)
    calls = {"n": 0}

    def _open(req, timeout=None):
        calls["n"] += 1
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    with pytest.raises(OSError) as ei:
        lp.QwenClient().messages.create(
            model="qwen3.7-max", messages=[{"role": "user", "content": "x"}])
    assert "timeout" in str(ei.value).lower()
    assert calls["n"] == lp._MAX_ATTEMPTS   # retried up to the cap, then surfaced


def test_qwen_http_timeout_env_honored(monkeypatch):
    """SIFT_HTTP_TIMEOUT must flow through to urlopen so qwen3.7-max gets enough
    time (the old 120s default timed out the entire flagship ensemble)."""
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    monkeypatch.setenv("SIFT_HTTP_TIMEOUT", "600")
    seen = {}
    ok = {"choices": [{"message": {"content": "ok"}}], "usage": {}}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(ok).encode("utf-8")

    def _open(req, timeout=None):
        seen["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    lp.QwenClient().messages.create(
        model="qwen3.7-max", messages=[{"role": "user", "content": "x"}])
    assert seen["timeout"] == 600
