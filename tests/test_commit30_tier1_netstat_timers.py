"""Commit 30: vol_netstat + vol_timers tier-1 fallback.

L30-1 structural: tier-1 _VOL_CANONICAL_ALIASES count grew from 21 to 23
L30-2 behavioral: vol_netstat resolves to windows.netstat.NetStat
L30-3 behavioral: vol_timers resolves to windows.timers.Timers
"""
from __future__ import annotations


def test_L30_1_hardcoded_fallback_count_23():
    """Structural: tier-1 grows from 21 to 23 with C30 additions."""
    from sift_sentinel.tools.common import _VOL_CANONICAL_ALIASES
    assert len(_VOL_CANONICAL_ALIASES) == 23, (
        f"tier-1 count is {len(_VOL_CANONICAL_ALIASES)}, expected 23 "
        f"(21 baseline + vol_netstat + vol_timers)"
    )
    assert "vol_netstat" in _VOL_CANONICAL_ALIASES
    assert "vol_timers" in _VOL_CANONICAL_ALIASES
    assert _VOL_CANONICAL_ALIASES["vol_netstat"] == "windows.netstat.NetStat"
    assert _VOL_CANONICAL_ALIASES["vol_timers"] == "windows.timers.Timers"


def test_L30_2_vol_netstat_resolves_to_windows_variant():
    """Behavioral: VOLATILITY_PLUGINS['vol_netstat'] is windows.netstat.NetStat.
    Pre-C30 resolved to mac.netstat.Netstat via discovery first-wins."""
    from sift_sentinel.tools.common import VOLATILITY_PLUGINS
    assert VOLATILITY_PLUGINS.get("vol_netstat") == "windows.netstat.NetStat", (
        f"vol_netstat: {VOLATILITY_PLUGINS.get('vol_netstat')!r}, "
        f"expected windows.netstat.NetStat"
    )


def test_L30_3_vol_timers_resolves_to_windows_variant():
    """Behavioral: VOLATILITY_PLUGINS['vol_timers'] is windows.timers.Timers.
    Same collision pattern as vol_netstat."""
    from sift_sentinel.tools.common import VOLATILITY_PLUGINS
    assert VOLATILITY_PLUGINS.get("vol_timers") == "windows.timers.Timers", (
        f"vol_timers: {VOLATILITY_PLUGINS.get('vol_timers')!r}, "
        f"expected windows.timers.Timers"
    )
