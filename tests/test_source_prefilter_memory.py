"""SIFT_SOURCE_PREFILTER_V1 symmetric memory filter: a disk-only run (no memory
image) omits memory-required tools from the Inv1/ReAct catalogs, exactly as a
memory-only run omits disk-required tools. Universal: keyed on each tool's
applicable_when capability, never a hardcoded tool name.
"""
import os
import pytest
from sift_sentinel import coordinator as C


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SIFT_HAS_MEMORY", raising=False)
    monkeypatch.delenv("SIFT_HAS_DISK", raising=False)


def test_has_memory_reader_defaults_present(monkeypatch):
    assert C._sift_has_memory_v1() is True          # absent -> conservative present
    monkeypatch.setenv("SIFT_HAS_MEMORY", "0")
    assert C._sift_has_memory_v1() is False
    monkeypatch.setenv("SIFT_HAS_MEMORY", "1")
    assert C._sift_has_memory_v1() is True


def _mem_only_and_disk_only():
    mem_only = disk_only = None
    for t in C._TOOL_REGISTRY:
        aw = (C.get_capability(t) or {}).get("applicable_when") or []
        if "memory_evidence" in aw and "disk_evidence" not in aw:
            mem_only = mem_only or t
        if "disk_evidence" in aw and "memory_evidence" not in aw:
            disk_only = disk_only or t
    return mem_only, disk_only


def test_disk_only_drops_memory_required_keeps_disk():
    mem_only, disk_only = _mem_only_and_disk_only()
    assert mem_only and disk_only            # registry has both classes
    # disk-only run: has_disk=True, has_memory=False
    drop = C._source_inapplicable_tools_v1(True, False)
    assert mem_only in drop                  # memory-required tool omitted
    assert disk_only not in drop             # disk tool kept


def test_memory_only_drops_disk_required_keeps_memory():
    mem_only, disk_only = _mem_only_and_disk_only()
    # memory-only run: has_disk=False, has_memory=True
    drop = C._source_inapplicable_tools_v1(False, True)
    assert disk_only in drop                 # disk-required tool omitted
    assert mem_only not in drop              # memory tool kept


def test_paired_run_drops_nothing_for_source():
    drop = C._source_inapplicable_tools_v1(True, True)
    assert drop == set()                     # both sources present -> no source drop
