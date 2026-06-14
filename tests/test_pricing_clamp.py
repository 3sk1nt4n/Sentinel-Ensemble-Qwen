"""The cost banner's PRIMARY figure must equal the REAL Anthropic bill
(cache-aware), never a hypothetical.

Behavior change (2026-06-10): the prior contract pinned the primary to the
*uncached* estimate and forbade showing any figure above it. That HID the
true cost on a run where cache WRITES (1.25x) were not amortised by reads --
the banner showed ~$1.22 while the real bill was ~$1.44. Honesty over optics:
we now lead with the real cache-aware cost and annotate how caching moved it.
The preserved invariant is ARITHMETIC CORRECTNESS -- the primary equals
``cache_aware_cost_usd`` exactly, and figures are non-negative.
"""
from __future__ import annotations

import re

from sift_sentinel.pricing import (
    cache_aware_cost_usd,
    format_cost,
    resolve_rates,
    uncached_cost_usd,
)

_MODEL = "claude-haiku-4-5-20251001"


def _nums(s):
    return [float(x) for x in re.findall(r"\$([0-9]+\.[0-9]{2})", s)]


def _real(uin, out, cr, cc):
    ri, ro = resolve_rates(_MODEL)
    return cache_aware_cost_usd(ri, ro, uncached_input=uin, output=out,
                                cache_read=cr, cache_creation=cc)


def test_primary_equals_real_billed_cost_with_cache_writes():
    # cache_creation only, zero reads -> real bill > uncached hypothetical.
    # The PRIMARY figure must be the real (higher) bill, not the hypothetical.
    out = format_cost(_MODEL, uncached_input=1000, output=1000,
                      cache_read=0, cache_creation=5000)
    nums = _nums(out)
    assert nums, out
    assert abs(nums[0] - _real(1000, 1000, 0, 5000)) < 0.01, out
    assert "no reuse this run" in out, out


def test_real_saving_is_shown():
    # large cache_read -> caching genuinely cheaper -> real primary < uncached
    out = format_cost(_MODEL, uncached_input=1000, output=500,
                      cache_read=200000, cache_creation=0)
    nums = _nums(out)
    assert "with prompt caching" in out, out
    assert len(nums) == 2 and nums[0] < nums[1], out
    assert abs(nums[0] - _real(1000, 500, 200000, 0)) < 0.01, out


def test_no_cache_tokens_single_figure():
    out = format_cost(_MODEL, uncached_input=1000, output=1000,
                      cache_read=0, cache_creation=0)
    assert "caching" not in out
    assert len(_nums(out)) == 1


def test_primary_always_matches_cache_aware_and_nonnegative():
    for cr, cc in [(0, 100000), (10, 100000), (200000, 0), (0, 0)]:
        out = format_cost(_MODEL, uncached_input=2000, output=800,
                          cache_read=cr, cache_creation=cc)
        nums = _nums(out)
        assert all(n >= 0 for n in nums), out
        assert abs(nums[0] - _real(2000, 800, cr, cc)) < 0.01, (cr, cc, out)


def test_live_run_numbers_render_as_real_bill():
    # The exact base-hosta-01 live-run token mix: banner must read ~$1.44.
    out = format_cost(_MODEL, uncached_input=76631, output=51776,
                      cache_read=0, cache_creation=881993)
    assert _nums(out)[0] == 1.44, out
