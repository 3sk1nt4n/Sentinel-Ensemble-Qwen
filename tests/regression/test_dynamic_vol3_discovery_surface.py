"""31I-gamma: Vol3 surface is dynamic-only.

The production surface must be derived from runtime discovery. Canonical
aliases are allowed only when their plugin paths were discovered. If
discovery is unavailable, no undiscovered Vol3 plugin is advertised.
"""
import pytest

from sift_sentinel.tools import common

@pytest.fixture(autouse=True)
def _restore_real_vol3_runtime_state():
    """Prevent synthetic discovery tests from leaking common.py globals."""
    real_plugins = dict(common.VOLATILITY_PLUGINS)
    real_active = common.VOL3_DISCOVERY_ACTIVE
    real_discovered_count = common.VOL3_DISCOVERED_PLUGIN_COUNT
    real_alias_fallback_count = common.VOL3_ALIAS_FALLBACK_COUNT

    yield

    common.VOLATILITY_PLUGINS.clear()
    common.VOLATILITY_PLUGINS.update(real_plugins)
    common.VOL3_DISCOVERY_ACTIVE = real_active
    common.VOL3_DISCOVERED_PLUGIN_COUNT = real_discovered_count
    common.VOL3_ALIAS_FALLBACK_COUNT = real_alias_fallback_count



def _rebuild(monkeypatch, discovered, raw_paths):
    monkeypatch.setattr(
        common, "_discover_volatility_windows_plugins",
        lambda: dict(discovered),
    )
    monkeypatch.setattr(
        common, "_discover_vol_plugin_paths",
        lambda: list(raw_paths),
    )
    return common._build_volatility_plugins()


def test_canonical_windows_alias_wins_short_name_collision(monkeypatch):
    canonical_path = common._VOL_CANONICAL_ALIASES["vol_pstree"]
    linux_collision_path = "linux.pstree.PsTree"
    novel_path = "windows.example.NovelPlugin"

    surface = _rebuild(
        monkeypatch,
        {
            "vol_pstree": linux_collision_path,
            "windows_pstree": canonical_path,
            "vol_novelplugin": novel_path,
        },
        [linux_collision_path, canonical_path, novel_path],
    )

    assert common.VOL3_DISCOVERY_ACTIVE is True
    assert common.VOL3_ALIAS_FALLBACK_COUNT == 0
    assert surface["vol_pstree"] == canonical_path
    assert "vol_novelplugin" in surface
    assert linux_collision_path not in surface.values()


def test_missing_canonical_path_is_not_advertised(monkeypatch):
    missing_name, missing_path = next(iter(common._VOL_CANONICAL_ALIASES.items()))
    novel_path = "windows.example.DynamicOnly"

    surface = _rebuild(
        monkeypatch,
        {"vol_dynamic_only": novel_path},
        [novel_path],
    )

    assert common.VOL3_DISCOVERY_ACTIVE is True
    assert common.VOL3_ALIAS_FALLBACK_COUNT == 0
    assert missing_name not in surface
    assert missing_path not in surface.values()
    assert surface == {"vol_dynamic_only": novel_path}


def test_discovery_unavailable_returns_empty_dynamic_surface(monkeypatch):
    surface = _rebuild(monkeypatch, {}, [])

    assert surface == {}
    assert common.VOL3_DISCOVERY_ACTIVE is False
    assert common.VOL3_DISCOVERED_PLUGIN_COUNT == 0
    assert common.VOL3_ALIAS_FALLBACK_COUNT == 0


def test_surface_values_are_subset_of_runtime_discovery(monkeypatch):
    canonical_name, canonical_path = next(iter(common._VOL_CANONICAL_ALIASES.items()))
    novel_path = "windows.example.RuntimeOnly"
    raw_paths = [canonical_path, novel_path]

    surface = _rebuild(
        monkeypatch,
        {
            "dynamic_canonical_name": canonical_path,
            "vol_runtime_only": novel_path,
        },
        raw_paths,
    )

    assert canonical_name in surface
    assert set(surface.values()).issubset(set(raw_paths))
    assert common.VOL3_ALIAS_FALLBACK_COUNT == 0


def test_real_runtime_canonical_aliases_preferred_when_available():
    raw_paths = set(common._discover_vol_plugin_paths())

    mismatches = []
    for canonical_name, plugin_path in common._VOL_CANONICAL_ALIASES.items():
        if plugin_path not in raw_paths:
            continue
        actual = common.VOLATILITY_PLUGINS.get(canonical_name)
        if actual != plugin_path:
            mismatches.append((canonical_name, plugin_path, actual))

    assert not mismatches

