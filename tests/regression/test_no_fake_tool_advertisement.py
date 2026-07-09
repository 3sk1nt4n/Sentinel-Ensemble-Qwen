"""Slot 31I-alpha: the Inv1 catalog advertises only registered tools.

A fake tool = a name in the rendered catalog string not present in the
registry passed to the renderer. The catalog parser keys off the stable
rendered line format (``- <name> - ... | platform=``) so prose bullets
in the surrounding prompt are never mistaken for tools.
"""

import re

from sift_sentinel.tool_semantics import format_grouped_inv1_tool_catalog

_CATALOG_LINE = re.compile(r"(?m)^- (\S+) - .*\| platform=")


def parse_tool_names_from_catalog(catalog_text):
    return set(_CATALOG_LINE.findall(catalog_text))


_SYNTH_REGISTRY = {
    "vol_pstree": (object(), "memory"),
    "vol_malfind": (object(), "memory"),
    "vol_netscan": (object(), "memory"),
    "get_amcache": (object(), "disk"),
    "sleuthkit_fls": (None, "sleuthkit"),
    "run_yara": (None, "sift_native"),
}


def test_advertised_tools_are_subset_of_registry():
    cat = format_grouped_inv1_tool_catalog(_SYNTH_REGISTRY)
    advertised = parse_tool_names_from_catalog(cat)
    registry_tools = set(_SYNTH_REGISTRY)
    phantoms = advertised - registry_tools
    assert phantoms == set(), f"phantom tools advertised: {phantoms}"


def test_every_registry_tool_is_advertised_once():
    cat = format_grouped_inv1_tool_catalog(_SYNTH_REGISTRY)
    lines = _CATALOG_LINE.findall(cat)
    assert sorted(lines) == sorted(_SYNTH_REGISTRY)
    assert len(lines) == len(set(lines))  # rendered exactly once


def test_unregistered_name_never_leaks_into_catalog():
    # A name that is NOT in the registry must not appear as a tool line
    # even though it resembles a real Volatility plugin.
    cat = format_grouped_inv1_tool_catalog(_SYNTH_REGISTRY)
    advertised = parse_tool_names_from_catalog(cat)
    assert "vol_phantom_unregistered" not in advertised


def test_empty_registry_yields_only_section_headers():
    cat = format_grouped_inv1_tool_catalog({})
    assert parse_tool_names_from_catalog(cat) == set()
    assert "MEMORY / PROCESS" in cat
    assert "GENERIC / UNCATEGORIZED" in cat
