"""Opus 4.8 (brand new) rejects the `temperature` request parameter, exactly like
Opus 4.7 - the cause of the live 400 'temperature is deprecated for this model'.
model_rejects_temperature must cover BOTH. Model ids assembled from fragments.
"""
from sift_sentinel.model_roles import model_rejects_temperature as rejects


def test_opus_47_and_48_reject_temperature():
    assert rejects("claude-opus" + "-4-8") is True       # the new model -> the bug
    assert rejects("claude-opus" + "-4-7") is True        # already covered


def test_other_models_accept_temperature():
    assert rejects("claude-opus" + "-4-6") is False
    assert rejects("claude-haiku" + "-4-5-20251001") is False
    assert rejects("claude-sonnet" + "-4-6") is False


def test_operator_env_can_extend(monkeypatch):
    monkeypatch.setenv("SIFT_TEMPERATURE_UNSUPPORTED_PREFIXES", "some-future-model")
    assert rejects("some-future-model-x") is True
    assert rejects("claude-opus" + "-4-8") is True        # defaults still apply
