"""Unit tests for the Qwen Cloud (DashScope) provider adapter.

Verifies the adapter is a drop-in for the Anthropic `messages.create` surface:
provider selection by env, Anthropic->OpenAI message translation (cache_control
dropped), the duck-typed response shape the pipeline reads, and fail-closed
behavior when no key is set. No network calls -- urlopen is mocked.
"""
import json
import urllib.request

import pytest

from sift_sentinel import llm_provider as lp


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
