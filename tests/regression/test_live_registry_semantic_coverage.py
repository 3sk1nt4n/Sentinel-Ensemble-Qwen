"""Slot 31I-alpha: universal semantic properties over the REAL
_TOOL_REGISTRY. Asserts only invariants -- no hardcoded tool names,
no required tool, no run-specific evidence.
"""

import re

import sift_sentinel.coordinator as c
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tool_semantics import (
    SEMANTIC_BUCKETS,
    get_tool_semantics,
    iter_tool_semantics,
    format_grouped_inv1_tool_catalog,
)

_CATALOG_LINE = re.compile(r"(?m)^- (\S+) - .*\| platform=")


def test_every_registered_tool_resolves_to_semantic_dict():
    sem = iter_tool_semantics(c._TOOL_REGISTRY, get_capability)
    assert set(sem) == set(c._TOOL_REGISTRY)
    for name, s in sem.items():
        assert set(s) == {
            "tool_name", "platforms", "evidence_domains", "buckets",
            "detects", "cost", "notes",
        }


def test_buckets_non_empty_iterable_not_str_or_dict_and_in_vocab():
    for name in c._TOOL_REGISTRY:
        b = get_tool_semantics(
            name, c._TOOL_REGISTRY[name], get_capability(name),
        )["buckets"]
        assert not isinstance(b, (str, dict))
        assert isinstance(b, tuple) and len(b) >= 1
        assert all(x in SEMANTIC_BUCKETS for x in b)


def test_catalog_advertised_subset_of_registry():
    selectable = (
        set(c._TOOL_REGISTRY) - c._NON_WINDOWS_TOOLS - {"vol_mftscan"}
    )
    reg = {n: c._TOOL_REGISTRY[n] for n in selectable}
    cat = format_grouped_inv1_tool_catalog(reg, get_capability)
    advertised = set(_CATALOG_LINE.findall(cat))
    assert advertised <= set(c._TOOL_REGISTRY)
    assert advertised <= selectable


def test_platforms_and_cost_are_well_formed():
    for name in c._TOOL_REGISTRY:
        s = get_tool_semantics(
            name, c._TOOL_REGISTRY[name], get_capability(name),
        )
        assert isinstance(s["platforms"], tuple) and s["platforms"]
        assert s["cost"] in {"low", "medium", "high"}
