"""C30 V3 side-test: real-data dispatch verification.

Property-based per slot 28. Verifies:
- vol_netstat dispatches to windows.netstat.NetStat at runtime
- vol_timers dispatches to windows.timers.Timers at runtime
- Every tier-1 _VOL_CANONICAL_ALIASES entry resolves per tier-1 path
  (proves C30 additions use tier-1 code path, not bypass)
- Environmental guard: vol --help still exposes both windows variants
"""
from __future__ import annotations


def test_vol_netstat_dispatches_windows_variant_runtime():
    """Property: vol_netstat resolves to windows.netstat.NetStat post-C30."""
    from sift_sentinel.tools.common import VOLATILITY_PLUGINS
    assert VOLATILITY_PLUGINS.get("vol_netstat") == "windows.netstat.NetStat", (
        f"vol_netstat mis-resolved: {VOLATILITY_PLUGINS.get('vol_netstat')!r}"
    )


def test_vol_timers_dispatches_windows_variant_runtime():
    """Property: vol_timers resolves to windows.timers.Timers via tier-1 override."""
    from sift_sentinel.tools.common import VOLATILITY_PLUGINS
    assert VOLATILITY_PLUGINS.get("vol_timers") == "windows.timers.Timers", (
        f"vol_timers mis-resolved: {VOLATILITY_PLUGINS.get('vol_timers')!r}"
    )


def test_tier1_hardcoded_override_semantics_preserved():
    """Regression: every _VOL_CANONICAL_ALIASES entry resolves in
    VOLATILITY_PLUGINS to the tier-1 path. Proves C30 additions take
    tier-1 code path rather than bypassing the merge logic."""
    from sift_sentinel.tools.common import VOLATILITY_PLUGINS, _VOL_CANONICAL_ALIASES
    for name, expected in _VOL_CANONICAL_ALIASES.items():
        assert VOLATILITY_PLUGINS.get(name) == expected, (
            f"tier-1 override broken: {name} = "
            f"{VOLATILITY_PLUGINS.get(name)}, expected {expected}"
        )


def test_vol_help_exposes_windows_variants():
    """Environmental property: vol --help still lists both windows
    variants C30 targets. If this fails on a future Vol3 version, the
    tier-1 tier wins regardless (safety net), but dynamic discovery
    would stop matching the tier-1 path and namespace assumptions
    would need reconsideration."""
    import subprocess
    result = subprocess.run(
        ["vol", "--help"], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"vol --help rc={result.returncode}"
    assert "windows.netstat.NetStat" in result.stdout, (
        "vol --help no longer exposes windows.netstat.NetStat"
    )
    assert "windows.timers.Timers" in result.stdout, (
        "vol --help no longer exposes windows.timers.Timers"
    )
