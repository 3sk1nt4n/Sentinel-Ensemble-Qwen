"""Slot 31I-beta: generic Windows abuse event-code semantics.

Event IDs/families are generic DFIR baselines (not evidence-specific
findings). Tests use the real registry only to locate EVTX-capable
tools; they assert universal properties, not run outcomes.
"""

import sift_sentinel.coordinator as c
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tool_semantics import (
    EVENT_CODE_FAMILIES,
    event_code_semantics,
    get_tool_semantics,
)

# Canonical, well-known DFIR Event IDs (logon / process / service /
# log-clear / powershell). Not tied to any dataset.
_CANONICAL_IDS = {4624, 4625, 4688, 7045, 1102, 4104, 4698}


def test_event_code_families_well_formed():
    assert len(EVENT_CODE_FAMILIES) >= 8
    for fam, meta in EVENT_CODE_FAMILIES.items():
        assert isinstance(fam, str) and fam
        assert isinstance(meta["channel"], str) and meta["channel"]
        ids = meta["event_ids"]
        assert isinstance(ids, tuple) and ids
        assert all(isinstance(e, int) and e > 0 for e in ids)
        assert isinstance(meta["summary"], str) and meta["summary"]


def test_canonical_ids_present_somewhere_in_families():
    all_ids = set()
    for meta in EVENT_CODE_FAMILIES.values():
        all_ids.update(meta["event_ids"])
    assert _CANONICAL_IDS.issubset(all_ids)


def _evtx_capable_registered_tools():
    found = []
    for name, entry in c._TOOL_REGISTRY.items():
        ec = event_code_semantics(name, get_capability(name), entry)
        if ec["event_code_capable"]:
            found.append(name)
    return found


def test_some_registered_tool_is_evtx_capable():
    # The registry must expose at least one EVTX-capable tool;
    # no specific tool name is required.
    assert _evtx_capable_registered_tools()


def test_evtx_capable_tools_expose_families_and_ids():
    for name in _evtx_capable_registered_tools():
        ec = event_code_semantics(name, get_capability(name),
                                  c._TOOL_REGISTRY[name])
        assert ec["families"]
        assert _CANONICAL_IDS.issubset(set(ec["event_ids"]))
        sem = get_tool_semantics(
            name, c._TOOL_REGISTRY[name], get_capability(name),
        )
        assert "evtx" in sem["detects"]
        assert "event_code_hunting" in sem["detects"]
        assert any(d.startswith("event_family:")
                   for d in sem["detects"])


def test_non_evtx_tool_is_inert():
    ec = event_code_semantics(
        "vol_pstree", get_capability("vol_pstree"),
        c._TOOL_REGISTRY.get("vol_pstree"),
    )
    assert ec["event_code_capable"] is False
    assert ec["families"] == ()
    assert ec["event_ids"] == ()


def test_schema_key_set_unchanged():
    sem = get_tool_semantics(
        "parse_event_logs", c._TOOL_REGISTRY["parse_event_logs"],
        get_capability("parse_event_logs"),
    )
    assert set(sem) == {
        "tool_name", "platforms", "evidence_domains", "buckets",
        "detects", "cost", "notes",
    }


def test_evtx_tools_expose_required_windows_event_ids_runtime_contract():
    """EVTX tools expose event-code guidance without changing descriptor schema."""
    from sift_sentinel.coordinator import _TOOL_REGISTRY, get_capability
    from sift_sentinel.tool_semantics import get_tool_semantics, event_code_semantics

    required = {
        1102,
        4103, 4104,
        4624, 4625, 4648, 4672, 4688,
        4697, 4698, 4702,
        4720, 4728, 4732, 4740, 4776,
        5140, 5145,
        5857, 5858, 5860, 5861,
        7045,
    }

    expected_schema = {
        "tool_name", "platforms", "evidence_domains", "buckets",
        "detects", "cost", "notes",
    }

    evtx_tools = sorted(
        name for name in _TOOL_REGISTRY
        if name in {"parse_event_logs", "run_evtxecmd", "run_evtx_dump"}
        or "evtx" in name.lower()
    )

    assert evtx_tools, "expected at least one registered EVTX-capable tool"

    seen_from_helper: set[int] = set()
    seen_from_detects: set[int] = set()

    for name in evtx_tools:
        sem = get_tool_semantics(name, _TOOL_REGISTRY[name], get_capability(name))

        # Locked descriptor schema: event-code hints must not add top-level keys.
        assert set(sem) == expected_schema

        buckets = set(sem.get("buckets", ()))
        assert "evtx" in buckets or "event_logs" in buckets

        for tag in sem.get("detects", ()):
            text = str(tag)
            if text.startswith("event_id:"):
                seen_from_detects.add(int(text.split(":", 1)[1]))

        meta = event_code_semantics(name)

        for value in meta.get("event_ids", ()):
            seen_from_helper.add(int(value))
        for value in meta.get("windows_event_ids", ()):
            seen_from_helper.add(int(value))

        families = meta.get("event_code_families") or meta.get("families")
        assert isinstance(families, dict)
        assert families

        for family_name, event_ids in families.items():
            assert isinstance(family_name, str) and family_name
            assert isinstance(event_ids, tuple)
            assert event_ids
            assert all(isinstance(event_id, int) for event_id in event_ids)
            assert all(1000 <= event_id <= 9999 for event_id in event_ids)

    assert required <= seen_from_helper
    assert required <= seen_from_detects

