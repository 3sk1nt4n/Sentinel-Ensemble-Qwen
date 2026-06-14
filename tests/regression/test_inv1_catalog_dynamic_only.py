"""Slot 31I-gamma: the Inv1 catalog advertises only registered tools.

Builds the catalog from the live registry, parses advertised tool
names, and asserts advertised_tools is a subset of _TOOL_REGISTRY with
zero fake/phantom advertisements. Also covers a synthetic registry so
the property holds dataset-agnostically.
"""

import re

import sift_sentinel.coordinator as c
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tool_semantics import format_grouped_inv1_tool_catalog

_CATALOG_LINE = re.compile(r"(?m)^- (\S+) — .*\| platform=")


def _advertised(catalog_text):
    return set(_CATALOG_LINE.findall(catalog_text))


def test_live_catalog_subset_of_registry():
    reg = dict(c._TOOL_REGISTRY)
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    advertised = _advertised(cat)
    registry_keys = set(reg)
    fake = advertised - registry_keys
    assert fake == set(), f"fake advertised tools: {sorted(fake)}"
    assert advertised <= registry_keys


def test_live_catalog_fake_count_is_zero():
    reg = dict(c._TOOL_REGISTRY)
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    fake_advertised_tool_count = len(_advertised(cat) - set(reg))
    assert fake_advertised_tool_count == 0


def test_selectable_windows_catalog_subset_of_registry():
    selectable = (
        set(c._TOOL_REGISTRY) - c._NON_WINDOWS_TOOLS - {"vol_mftscan"}
    )
    reg = {n: c._TOOL_REGISTRY[n] for n in selectable}
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    advertised = _advertised(cat)
    assert advertised <= set(reg)
    assert len(advertised - set(reg)) == 0


def test_synthetic_registry_no_phantom_advertised():
    synth = {
        "vol_pstree": (object(), "memory"),
        "vol_malfind": (object(), "memory"),
        "get_amcache": (object(), "disk"),
        "run_yara": (None, "sift_native"),
    }
    cat = format_grouped_inv1_tool_catalog(synth)
    advertised = _advertised(cat)
    assert advertised == set(synth)
    assert "vol_phantom_unregistered" not in advertised


def test_every_registry_tool_advertised_exactly_once():
    reg = dict(c._TOOL_REGISTRY)
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    lines = _CATALOG_LINE.findall(cat)
    assert len(lines) == len(set(lines))  # no duplicates
    assert set(lines) == set(reg)  # complete coverage, no invention
