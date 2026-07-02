"""Cache-aware token cost estimate.

The naive estimate charges every input token at the base rate. That OVER-states cost
whenever prompt caching is active: a 4-member ensemble re-reads ONE shared prompt, and
those cache-read tokens bill at ~10% of base (cache *writes* bill at 125%). So we report
the uncached figure AND, in brackets, the with-prompt-caching figure -- the latter tracks
the real provider bill.

Rates are per-million-tokens, model-aware, env-overridable (SIFT_PRICE_*).
"""
from __future__ import annotations

import os

# (input, output) USD per MTok, base / uncached rate.
_MODEL_RATES = {
    "opus": (15.0, 75.0),
    "sonnet": (3.0, 15.0),
    "haiku": (1.0, 5.0),
}
# cache HIT multiplier vs base input rate. Default 0.10 (Anthropic ephemeral).
# Qwen/DashScope automatic context-cache hits bill at a different (provider-set)
# rate, so make it env-overridable to track the real cached-token cost.
try:
    _CACHE_READ_MULT = float(os.environ.get("SIFT_CACHE_READ_MULT") or 0.10)
except (TypeError, ValueError):
    _CACHE_READ_MULT = 0.10
_CACHE_WRITE_MULT = 1.25       # 5-minute cache WRITE: 125% of the base input rate

# Approximate Alibaba Cloud DashScope (international / Singapore) list rates,
# USD/MTok, for the cost READOUT only -- these are ESTIMATES, not an invoice.
# Pin your real console rates via SIFT_PRICE_INPUT/OUTPUT_PER_MTOK. Matched by
# substring (FIRST match wins), so more-specific keys must come first:
# "3.7-max" before the generic "max", and "vl-max" before "max".
_QWEN_RATES = {
    "3.7-max": (2.5, 7.5),   # qwen3.7-max list price (50% launch promo expired 2026-06-22)
    "vl-max": (1.6, 6.4),
    "max": (1.6, 6.4),       # qwen-max / qwen3-max class
    "plus": (0.4, 1.2),
    "turbo": (0.05, 0.2),
    "long": (0.5, 2.0),
}
_QWEN_DEFAULT = (0.4, 1.2)     # qwen-plus-class default for unrecognised qwen ids


def _qwen_rate(ml: str) -> tuple[float, float]:
    for key, rate in _QWEN_RATES.items():
        if key in ml:
            return rate
    return _QWEN_DEFAULT


def resolve_rates(model: str) -> tuple[float, float]:
    """(input, output) USD/MTok for a model string. Env SIFT_PRICE_* overrides both."""
    ml = str(model or "").lower()
    if "opus" in ml:
        base = _MODEL_RATES["opus"]
    elif "sonnet" in ml:
        base = _MODEL_RATES["sonnet"]
    elif "qwen" in ml:
        base = _qwen_rate(ml)
    else:
        base = _MODEL_RATES["haiku"]
    p_in = os.environ.get("SIFT_PRICE_INPUT_PER_MTOK")
    p_out = os.environ.get("SIFT_PRICE_OUTPUT_PER_MTOK")
    return (float(p_in) if p_in else base[0], float(p_out) if p_out else base[1])


def _n(x) -> float:
    try:
        return float(x or 0)
    except Exception:
        return 0.0


def cache_aware_cost_usd(rate_in: float, rate_out: float, *, uncached_input,
                         output, cache_read=0, cache_creation=0) -> float:
    """Actual billed cost: uncached input @ base + cache-creation @125% + cache-read @10%
    + output @ base. Never raises."""
    return (
        _n(uncached_input) / 1e6 * rate_in
        + _n(cache_creation) / 1e6 * rate_in * _CACHE_WRITE_MULT
        + _n(cache_read) / 1e6 * rate_in * _CACHE_READ_MULT
        + _n(output) / 1e6 * rate_out
    )


def uncached_cost_usd(rate_in: float, rate_out: float, *, uncached_input,
                      output, cache_read=0, cache_creation=0) -> float:
    """Worst case: every prompt token (incl. what was actually cached) at the FULL input
    rate -- i.e. what it would cost with NO prompt caching. Never raises."""
    total_in = _n(uncached_input) + _n(cache_read) + _n(cache_creation)
    return total_in / 1e6 * rate_in + _n(output) / 1e6 * rate_out


def format_cost(model: str, *, uncached_input, output, cache_read=0,
                cache_creation=0) -> str:
    """Render the cost line. The PRIMARY figure is always the REAL billed cost
    (cache-aware: uncached input @ base + cache writes @125% + cache reads @10%
    + output @ base) -- it must equal the actual provider bill, never a
    hypothetical. The bracket explains how caching moved that number:

      * caching SAVED money (reads amortised the writes):
            ~$8.61 with prompt caching (~$15.30 uncached)
      * caching ACTIVE but no reuse yet (writes billed, reads=0 -> net overhead):
            ~$1.44 (incl. prompt-cache writes, no reuse this run)
      * no caching at all:
            ~$0.34

    Universal arithmetic, no case data. Honesty over optics: when cache writes
    were not amortised the real bill is HIGHER than the no-cache hypothetical,
    and we show that real (higher) number rather than hiding it."""
    r_in, r_out = resolve_rates(model)
    real = cache_aware_cost_usd(r_in, r_out, uncached_input=uncached_input,
                                output=output, cache_read=cache_read,
                                cache_creation=cache_creation)
    if not (_n(cache_read) > 0 or _n(cache_creation) > 0):
        return "~$%.2f est. (token-based)" % real
    no_cache = uncached_cost_usd(r_in, r_out, uncached_input=uncached_input,
                                 output=output, cache_read=cache_read,
                                 cache_creation=cache_creation)
    # Token-based ESTIMATE -- not a guaranteed invoice. The provider may apply
    # server-side caching/credits our usage counters don't see, so the actual
    # billed amount can be LOWER than this token-derived figure. The pinned
    # phrases "with prompt caching" / "no reuse this run" are kept (cost-clamp
    # contract) and wrapped with the est./caveat framing.
    if real < no_cache:
        return ("~$%.2f est. with prompt caching (~$%.2f uncached) "
                "-- actual billed cost may be lower" % (real, no_cache))
    return ("~$%.2f est. (incl. prompt-cache writes, no reuse this run) "
            "-- actual billed cost may be lower" % real)


def cost_usd(token_usage, model: str) -> float:
    """Cache-aware USD cost for a token_usage dict at *model*'s real rates.

    One number, model-aware -- the single replacement for hardcoded per-token
    rate literals scattered across renderers (which baked in Sonnet rates and
    mispriced every other model). Never raises: a missing dict or unknown model
    yields 0.0 / Haiku-rate respectively.
    """
    if not isinstance(token_usage, dict):
        return 0.0
    r_in, r_out = resolve_rates(model or "")
    return cache_aware_cost_usd(
        r_in, r_out,
        uncached_input=token_usage.get("total_input", 0),
        output=token_usage.get("total_output", 0),
        cache_read=token_usage.get("total_cache_read", 0),
        cache_creation=token_usage.get("total_cache_creation", 0),
    )
