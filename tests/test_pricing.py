"""Cache-aware token cost.

The naive estimate charges every input token at the base rate, which OVER-states cost
whenever prompt caching is active -- a 4-member ensemble re-reads one shared prompt, and
those cache-read tokens bill at ~10% of base (creation bills at 125%). This makes the
reported '~$X' track the real Anthropic bill. Universal: model-aware rates, env-override.
"""
import pytest

from sift_sentinel.pricing import resolve_rates, cache_aware_cost_usd


def test_model_rates():
    assert resolve_rates("claude-opus-4-8") == (15.0, 75.0)
    assert resolve_rates("claude-sonnet-4-6") == (3.0, 15.0)
    assert resolve_rates("claude-haiku-4-5") == (1.0, 5.0)


def test_unknown_model_defaults_to_haiku_rate():
    assert resolve_rates("some-small-model") == (1.0, 5.0)


def test_uncached_only_matches_naive_estimate():
    # uncached input + output == the old naive formula
    c = cache_aware_cost_usd(15.0, 75.0, uncached_input=715778, output=60822)
    assert abs(c - (715778 / 1e6 * 15.0 + 60822 / 1e6 * 75.0)) < 1e-9
    assert abs(c - 15.298) < 0.01


def test_cache_read_is_ten_percent_of_base():
    full = cache_aware_cost_usd(15.0, 75.0, uncached_input=700000, output=0)
    cached = cache_aware_cost_usd(15.0, 75.0, uncached_input=0, cache_read=700000, output=0)
    assert abs(cached - full * 0.10) < 1e-9


def test_cache_creation_is_125_percent_of_base():
    base = cache_aware_cost_usd(15.0, 75.0, uncached_input=100000, output=0)
    cc = cache_aware_cost_usd(15.0, 75.0, uncached_input=0, cache_creation=100000, output=0)
    assert abs(cc - base * 1.25) < 1e-9


def test_caching_lowers_cost_vs_treating_cache_as_uncached():
    # the bug: 600k cache-read tokens charged as if uncached
    naive = cache_aware_cost_usd(15.0, 75.0, uncached_input=600000, output=60000)
    real = cache_aware_cost_usd(15.0, 75.0, uncached_input=0, cache_read=600000, output=60000)
    assert real < naive


def test_env_override(monkeypatch):
    monkeypatch.setenv("SIFT_PRICE_INPUT_PER_MTOK", "2.0")
    monkeypatch.setenv("SIFT_PRICE_OUTPUT_PER_MTOK", "8.0")
    assert resolve_rates("claude-opus-4-8") == (2.0, 8.0)


def test_never_raises_on_bad_input():
    assert cache_aware_cost_usd(15.0, 75.0, uncached_input=None, output=None) == 0.0
