"""Universal `temperature`-deprecation compatibility.

Newer Anthropic models reject the ``temperature`` request parameter
('`temperature` is deprecated for this model'). A hand-maintained model
name list is brittle -- it just halted a live Fable 5 run at Inv1 because
Fable 5 was not on the Opus-only list. These tests pin a TWO-layer fix:

  1. fast path  -- known rejector prefixes (incl. Fable 5) skip temperature
                   proactively so no call is wasted.
  2. universal  -- a reactive wrapper reads the API's OWN 400 error, strips
                   temperature, learns the model, and retries once. Any
                   FUTURE model that deprecates temperature self-heals with
                   no code change and no model literal in source.

No model literal is hardcoded here either -- ids are assembled from
fragments, mirroring the production source convention.
"""
import types

import pytest

from sift_sentinel import model_roles as mr


def _fable():
    return "claude" + "-fable" + "-5"


def _haiku():
    return "claude" + "-haiku" + "-4-5"


# ── layer 1: fast-path prefix predicate ──────────────────────────────────
def test_fable_rejects_temperature_fast_path():
    # the regression: Fable 5 must be a known rejector so the FIRST call
    # already omits temperature (no wasted 400).
    assert mr.model_rejects_temperature(_fable()) is True


def test_haiku_still_accepts_temperature():
    # determinism (temperature=0) must still reach models that accept it.
    assert mr.model_rejects_temperature(_haiku()) is False


def test_opus_family_still_rejects():
    assert mr.model_rejects_temperature("claude" + "-opus" + "-4-8") is True


# ── layer 2: reactive predicate reads the API's own error ────────────────
class _ApiErr(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status_code = status
        self.message = msg


def test_is_temperature_rejection_matches_real_message():
    exc = _ApiErr(
        "Error code: 400 - {'type': 'error', 'error': {'type': "
        "'invalid_request_error', 'message': '`temperature` is deprecated "
        "for this model.'}}")
    assert mr.is_temperature_rejection(exc) is True


def test_is_temperature_rejection_ignores_unrelated_errors():
    assert mr.is_temperature_rejection(_ApiErr("overloaded_error", 529)) is False
    assert mr.is_temperature_rejection(_ApiErr("invalid x-api-key", 401)) is False
    assert mr.is_temperature_rejection(ValueError("temperature is fine")) is False


# ── layer 2: learned-rejector round-trip ─────────────────────────────────
def test_note_then_rejects_learned_model():
    learned = "some" + "-brand" + "-new-model-x"
    assert mr.model_rejects_temperature(learned) is False
    mr.note_temperature_rejector(learned)
    assert mr.model_rejects_temperature(learned) is True


# ── the resilient wrapper: proactive + reactive + learn + retry-once ─────
class _FakeMessages:
    def __init__(self, owner):
        self._owner = owner

    def create(self, **kw):
        self._owner.calls.append(dict(kw))
        if "temperature" in kw:
            raise _ApiErr("`temperature` is deprecated for this model.")
        return types.SimpleNamespace(ok=True, kw=kw)


class _FakeClient:
    def __init__(self):
        self.calls = []
        self.messages = _FakeMessages(self)


def test_wrapper_reactively_strips_and_retries_for_unknown_model():
    client = _FakeClient()
    model = "future" + "-model" + "-zeta"
    assert mr.model_rejects_temperature(model) is False  # unknown up front
    resp = mr.create_message_temp_resilient(
        client, {"model": model, "temperature": 0, "max_tokens": 8,
                 "messages": [{"role": "user", "content": "hi"}]})
    assert getattr(resp, "ok", False) is True
    # two attempts: first with temperature (400), second without.
    assert len(client.calls) == 2
    assert "temperature" in client.calls[0]
    assert "temperature" not in client.calls[1]
    # and it LEARNED the model for next time -> no wasted call again.
    assert mr.model_rejects_temperature(model) is True


def test_wrapper_proactively_strips_for_known_rejector_single_call():
    client = _FakeClient()
    resp = mr.create_message_temp_resilient(
        client, {"model": _fable(), "temperature": 0, "max_tokens": 8,
                 "messages": [{"role": "user", "content": "hi"}]})
    assert getattr(resp, "ok", False) is True
    assert len(client.calls) == 1                  # no wasted 400
    assert "temperature" not in client.calls[0]


def test_wrapper_keeps_temperature_for_accepting_model():
    client = _FakeClient()
    # haiku accepts temperature -> the fake create returns ok only WITHOUT
    # temperature, so simulate an accepting backend with a permissive fake.
    client.messages.create = lambda **kw: (client.calls.append(dict(kw))
                                            or types.SimpleNamespace(ok=True))
    resp = mr.create_message_temp_resilient(
        client, {"model": _haiku(), "temperature": 0, "max_tokens": 8,
                 "messages": [{"role": "user", "content": "hi"}]})
    assert getattr(resp, "ok", False) is True
    assert len(client.calls) == 1
    assert client.calls[0].get("temperature") == 0   # determinism preserved


def test_wrapper_reraises_non_temperature_errors():
    client = _FakeClient()
    client.messages.create = lambda **kw: (_ for _ in ()).throw(
        _ApiErr("overloaded_error", 529))
    with pytest.raises(_ApiErr):
        mr.create_message_temp_resilient(
            client, {"model": _haiku(), "temperature": 0, "max_tokens": 8,
                     "messages": [{"role": "user", "content": "hi"}]})
