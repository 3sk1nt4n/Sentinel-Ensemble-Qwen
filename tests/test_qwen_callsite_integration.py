"""Integration + cross-provider parity for the Qwen Cloud (DashScope) path.

Unlike test_llm_provider.py (which unit-tests QwenClient in isolation), these
exercise the SUBMISSION seam end to end:

  1. make_llm_client() -> create_message_temp_resilient() (the wrapper every
     pipeline call site uses) -> QwenClient -> extract_response_text(), with
     urlopen mocked, asserting the request that reaches DashScope is
     OpenAI-shaped and the duck-typed response flows back.

  2. normalize_claims() collapses Qwen-vs-Anthropic claim-type drift to identical
     canonical claims, so the (separately-proven deterministic) confirm gate
     produces the same buckets regardless of which provider produced the finding.

No network: urlopen is mocked. Provider stays env-selected.
"""
import json
import urllib.request

from sift_sentinel.llm_provider import make_llm_client, QwenClient
from sift_sentinel.model_roles import (
    create_message_temp_resilient,
    extract_response_text,
)
from sift_sentinel.validation.normalize_claims import normalize_claims


def test_qwen_callsite_through_resilient_wrapper(monkeypatch):
    monkeypatch.setenv("SIFT_LLM_PROVIDER", "qwen")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "sk-test")
    payload = {
        "model": "qwen-plus",
        "choices": [{"message": {"content": '{"findings": []}'}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 9},
    }
    captured = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(payload).encode("utf-8")

    def _open(req, timeout=None):
        captured["req"] = req
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _open)

    client = make_llm_client()
    assert isinstance(client, QwenClient)        # provider=qwen -> DashScope adapter

    # the exact wrapper the pipeline call sites use (coordinator/ensemble/etc.)
    resp = create_message_temp_resilient(client, {
        "model": "qwen-plus",
        "max_tokens": 256,
        "temperature": 0,
        "messages": [{"role": "user", "content": "analyze"}],
    })

    # response flows back through the pipeline's own extractor
    assert extract_response_text(resp) == '{"findings": []}'
    assert resp.usage.input_tokens == 20 and resp.usage.output_tokens == 9

    # the request that hit Alibaba Cloud DashScope was OpenAI-shaped + authed
    sent = json.loads(captured["req"].data.decode("utf-8"))
    assert sent["model"] == "qwen-plus"
    assert sent["messages"][0] == {"role": "user", "content": "analyze"}
    assert sent["max_tokens"] == 256 and sent["temperature"] == 0
    assert captured["req"].get_header("Authorization") == "Bearer sk-test"


def test_normalize_claims_collapses_provider_type_drift():
    """A Qwen-shaped finding (type 'process'/'artifact') and the Anthropic-shaped
    equivalent (type 'pid'/'path') normalize to BYTE-IDENTICAL canonical claims,
    so the (separately-proven deterministic) confirm gate cannot bucket the same
    evidence differently just because a different provider produced it."""
    # identical finding-level context so any context-based rescue is identical too
    common = {"finding_id": "F1", "title": "lateral movement", "description": "", "artifact": ""}
    anthropic_finding = {**common, "claims": [
        {"type": "pid", "value": "4321", "pid": "4321", "source_tools": ["pslist"]},
        {"type": "path", "value": "C:/Windows/Temp/evil.exe", "source_tools": ["mft"]},
    ]}
    qwen_finding = {**common, "claims": [
        {"type": "process", "value": "4321", "pid": "4321", "source_tools": ["pslist"]},   # alias -> pid
        {"type": "artifact", "value": "C:/Windows/Temp/evil.exe", "source_tools": ["mft"]},  # alias -> path
    ]}

    na = normalize_claims([anthropic_finding])[0]["claims"]
    nq = normalize_claims([qwen_finding])[0]["claims"]

    # the core parity guarantee: provider shape-drift collapses to the same thing
    assert na == nq and na, "Qwen and Anthropic shapes must normalize identically"
    # and the Qwen alias type names were actually remapped (not left raw)
    assert {c.get("type") for c in nq}.isdisjoint(
        {"process", "artifact", "ip", "address", "port", "file", "network"})
