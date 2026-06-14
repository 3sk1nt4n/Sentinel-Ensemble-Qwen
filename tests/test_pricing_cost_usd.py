"""pricing.cost_usd: one model-aware, cache-aware USD number from a token_usage
dict. Replaces four hardcoded Sonnet-rate ($3/$15) inline calcs in run_pipeline
that mispriced every non-Sonnet run (an Opus run was understated ~5x)."""
import math

from sift_sentinel.pricing import cost_usd


def _tu(**kw):
    base = {"total_input": 0, "total_output": 0,
            "total_cache_read": 0, "total_cache_creation": 0}
    base.update(kw)
    return base


def test_opus_cache_aware_matches_hand_math():
    # the real acme run telemetry: cache WRITTEN, never READ.
    tu = _tu(total_input=59, total_output=64990,
             total_cache_creation=1039700, total_cache_read=0)
    got = cost_usd(tu, "claude-opus-4-8")
    want = (59/1e6*15 + 1039700/1e6*15*1.25 + 0 + 64990/1e6*75)
    assert math.isclose(got, want, rel_tol=1e-9)
    assert got > 24 and got < 25                       # ~$24.37, not the $4 Sonnet would give


def test_model_rates_differ():
    tu = _tu(total_input=1_000_000, total_output=1_000_000)
    opus = cost_usd(tu, "claude-opus-4-8")
    haiku = cost_usd(tu, "claude-haiku-4-5")
    sonnet = cost_usd(tu, "claude-sonnet-4-6")
    assert opus == 15 + 75              # $90
    assert haiku == 1 + 5               # $6
    assert sonnet == 3 + 15             # $18
    assert opus > sonnet > haiku


def test_cache_read_is_cheap():
    # a read (0.10x) costs far less than a creation (1.25x) for the same tokens.
    read = cost_usd(_tu(total_cache_read=1_000_000), "claude-opus-4-8")
    create = cost_usd(_tu(total_cache_creation=1_000_000), "claude-opus-4-8")
    assert math.isclose(read, 1_000_000/1e6*15*0.10)
    assert create > read * 10


def test_empty_or_unknown_model_falls_back_haiku_and_never_raises():
    assert cost_usd(_tu(total_output=1_000_000), "") == 5
    assert cost_usd(_tu(total_output=1_000_000), None) == 5
    assert cost_usd({}, "claude-opus-4-8") == 0.0
    assert cost_usd(None, "claude-opus-4-8") == 0.0    # never raises
