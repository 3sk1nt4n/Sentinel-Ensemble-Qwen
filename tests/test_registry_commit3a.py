"""Commit 3a Vol3 Linux/Mac plugin expansion tests.

Asserts discovery extended from Windows-only to all OS families.
"""
from __future__ import annotations

from sift_sentinel.coordinator import _TOOL_REGISTRY
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tools.common import VOLATILITY_PLUGINS


def test_registry_has_140_or_more_tools():
    """Post-3a should exceed 140 tools (120 Commit 2 baseline + Linux/Mac gains)."""
    assert len(_TOOL_REGISTRY) >= 140, (
        f"Expected >=140 tools after Commit 3a, got {len(_TOOL_REGISTRY)}"
    )


def test_volatility_plugins_includes_linux():
    """VOLATILITY_PLUGINS must now include linux.* plugins."""
    linux = [v for v in VOLATILITY_PLUGINS.values() if v.startswith("linux.")]
    assert len(linux) > 0, (
        f"Expected linux.* plugins in VOLATILITY_PLUGINS, got {len(linux)}"
    )


def test_linux_vol3_plugins_registered_sample():
    """Spot-check common Linux plugins are now in registry."""
    expected_samples = {"vol_bash", "vol_lsof", "vol_psaux", "vol_lsmod"}
    missing = expected_samples - set(_TOOL_REGISTRY.keys())
    assert not missing, f"Missing Linux Vol3 plugins: {missing}"


def test_linux_plugin_has_linux_applicability():
    """Linux Vol3 plugins must have linux_evidence in applicable_when."""
    cap = get_capability("vol_bash")
    assert cap is not None, "vol_bash should have a capability entry"
    applicable = cap.get("applicable_when", [])
    assert "linux_evidence" in applicable, (
        f"vol_bash applicable_when={applicable}, expected linux_evidence"
    )


def test_all_vol3_registered_plugins_have_capabilities():
    """Every vol_* tool in registry must have capability declaration."""
    vol_tools = [k for k in _TOOL_REGISTRY if k.startswith("vol_")]
    missing = [t for t in vol_tools if get_capability(t) is None]
    assert not missing, f"Vol3 tools missing capabilities: {missing}"


def test_no_duplicate_vol_entries():
    """Registry keys must be unique (paranoia check)."""
    vol_tools = [k for k in _TOOL_REGISTRY if k.startswith("vol_")]
    assert len(vol_tools) == len(set(vol_tools)), (
        f"Duplicate vol_* tools: {len(vol_tools)} vs {len(set(vol_tools))}"
    )
