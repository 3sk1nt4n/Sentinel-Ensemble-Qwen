"""Inv2 ensemble self-heal for reasoning-model thinking starvation.

Fable 5's extended thinking is adaptive: on the heavy Inv2 analysis prompt it
consumed the entire max_tokens budget and emitted a ThinkingBlock with NO answer
text block -> extract_response_text returns "" -> JSONDecodeError -> 0 findings
(all 4 members). The fix: when a member's answer is empty, retry once with an
explicit thinking budget that RESERVES room for the JSON, learn the model so the
next call is one-shot. Non-reasoning models (Haiku) never return empty, so they
never take the retry and never get the thinking param.
"""
import types

import pytest

import sift_sentinel.ensemble as ens


def _thinking():
    return types.SimpleNamespace(type="thinking", thinking="reasoning...")


def _text(s):
    return types.SimpleNamespace(type="text", text=s)


def _resp(blocks, stop="end_turn", out=1000):
    return types.SimpleNamespace(
        content=blocks, stop_reason=stop,
        usage=types.SimpleNamespace(
            input_tokens=10, output_tokens=out,
            cache_read_input_tokens=0, cache_creation_input_tokens=0))


class _ReasoningClient:
    """Reasoning model: thinking-only (empty) UNLESS given a thinking budget."""
    def __init__(self):
        self.calls = []
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        if "thinking" in kw:
            return _resp([_thinking(), _text('{"findings": [{"title": "x"}]}')])
        return _resp([_thinking()], stop="max_tokens", out=kw["max_tokens"])


class _PlainClient:
    """Non-reasoning model: always answers, never emits thinking."""
    def __init__(self):
        self.calls = []
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        return _resp([_text('{"findings": [{"title": "y"}]}')])


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SIFT_INV2_ENSEMBLE_FORCE_MODEL", raising=False)
    monkeypatch.delenv("SIFT_FORCE_MODEL", raising=False)
    ens._THINKING_RESERVE_MODELS.clear()
    yield
    ens._THINKING_RESERVE_MODELS.clear()


def test_empty_thinking_answer_self_heals_and_learns():
    c = _ReasoningClient()
    r = ens._call_one_model(c, "claude" + "-fable" + "-5", "prompt", max_tokens=16384)
    assert r["error"] is None, r["error"]
    assert r["findings"] == [{"title": "x"}]
    # two calls: first plain (empty), retry WITH a bounded thinking budget.
    assert len(c.calls) == 2
    assert "thinking" not in c.calls[0]
    assert c.calls[1]["thinking"]["type"] == "enabled"
    assert c.calls[1]["thinking"]["budget_tokens"] >= 1024
    # the retry must stay INSIDE the original ceiling: a doubled ceiling trips
    # the SDK's 'Streaming is required (>10 min)' ValueError (live-proven).
    assert c.calls[1]["max_tokens"] == c.calls[0]["max_tokens"]
    assert c.calls[1]["max_tokens"] > c.calls[1]["thinking"]["budget_tokens"]
    # learned -> next time is one-shot.
    assert ens._needs_thinking_reserve("claude" + "-fable" + "-5") is True


def test_refusal_fails_fast_without_retry():
    # live-proven 4th failure mode: stop_reason=refusal with thinking-only
    # content. A retry cannot un-refuse -- it must fail fast (one call, money
    # saved) with a loud, named error.
    class _RefusingClient:
        def __init__(self):
            self.calls = []
            self.messages = types.SimpleNamespace(create=self._create)

        def _create(self, **kw):
            self.calls.append(kw)
            return _resp([_thinking()], stop="refusal", out=1260)

    c = _RefusingClient()
    r = ens._call_one_model(c, "claude" + "-fable" + "-5", "p", max_tokens=16384)
    assert len(c.calls) == 1                      # NO retry
    assert r["findings"] == []
    assert r["error"] and "model_refusal" in r["error"]
    assert "refusal" in r["error"]                # diagnostic names the cause
    # a refusal teaches us nothing about thinking budgets -- not learned.
    assert ens._needs_thinking_reserve("claude" + "-fable" + "-5") is False


def test_learned_model_reserves_proactively_single_call():
    ens._note_thinking_reserve("claude" + "-fable" + "-5")
    c = _ReasoningClient()
    r = ens._call_one_model(c, "claude" + "-fable" + "-5", "p", max_tokens=16384)
    assert r["findings"] == [{"title": "x"}]
    assert len(c.calls) == 1                       # no wasted empty probe
    assert c.calls[0]["thinking"]["type"] == "enabled"


def test_plain_model_one_call_no_thinking_param():
    c = _PlainClient()
    r = ens._call_one_model(c, "claude" + "-haiku" + "-4-5", "p", max_tokens=16384)
    assert r["findings"] == [{"title": "y"}]
    assert len(c.calls) == 1
    assert "thinking" not in c.calls[0]            # Haiku never gets the param
    assert ens._needs_thinking_reserve("claude" + "-haiku" + "-4-5") is False


def test_budget_clamped_above_floor_for_small_max_tokens():
    # a tiny max_tokens must not produce an invalid (<1024) thinking budget.
    c = _ReasoningClient()
    ens._note_thinking_reserve("m")
    ens._call_one_model(c, "m", "p", max_tokens=100)
    assert c.calls[0]["thinking"]["budget_tokens"] >= 1024
    assert c.calls[0]["max_tokens"] > c.calls[0]["thinking"]["budget_tokens"]
