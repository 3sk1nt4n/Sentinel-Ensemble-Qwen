"""Slot 31I-alpha: catalog token estimate and soft 10k ceiling."""

import math

from sift_sentinel.tool_semantics import (
    estimate_catalog_tokens,
    format_grouped_inv1_tool_catalog,
)

_SOFT_CEILING = 10000


def test_estimate_is_ceil_len_over_4():
    assert estimate_catalog_tokens("") == 0
    for text in ("abcd", "x" * 17, "tool catalog text"):
        assert estimate_catalog_tokens(text) == math.ceil(len(text) / 4)


def test_estimate_non_negative_int():
    assert isinstance(estimate_catalog_tokens("hello"), int)
    assert estimate_catalog_tokens("") == 0


def test_synthetic_catalog_under_soft_ceiling():
    reg = {f"vol_tool_{i}": (None, "memory") for i in range(60)}
    cat = format_grouped_inv1_tool_catalog(reg)
    assert estimate_catalog_tokens(cat) <= _SOFT_CEILING


def test_live_registry_catalog_under_soft_ceiling():
    # Real registry must also stay within the soft ceiling. Universal
    # property only -- no assertion on specific tool names.
    import sift_sentinel.coordinator as c
    from sift_sentinel.tools.capabilities import get_capability

    selectable = (
        set(c._TOOL_REGISTRY) - c._NON_WINDOWS_TOOLS - {"vol_mftscan"}
    )
    reg = {n: c._TOOL_REGISTRY[n] for n in selectable}
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    est = estimate_catalog_tokens(cat)
    assert est <= _SOFT_CEILING, f"catalog token estimate {est} > soft ceiling"
