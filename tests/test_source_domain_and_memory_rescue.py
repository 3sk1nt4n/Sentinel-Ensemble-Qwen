"""Two universal fixes from a live disk-only run review:

A. Step-0 memory rescue: a file whose NAME carries a memory role-shape
   (host-a-memory.img) and that fsstat says is NOT a filesystem must classify
   as MEMORY even when the vol3 probe fails/times out (cold multi-GB image,
   old-OS symbols). Deterministic name-SHAPE (OS-neutral role markers), never
   a case name. Kill-switch: SIFT_MEMORY_NAME_SHAPE_RESCUE=0.

B. Disk-only domain discipline: when no memory image is present the Inv1
   catalog, the post-selection list, and the injection-corroborator pairing
   must all exclude memory-required tools, and Step-3 SSDT must report
   not_applicable (never "degraded"). Kill-switch: SIFT_SOURCE_CATALOG_FILTER=0.
"""

import os
import subprocess
import sys

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard.engine import (  # noqa: E402
    Probes,
    RealProbes,
    onboard,
)


class _ColdVol3Probes(Probes):
    """Memory probe always fails (what a cold/old image looks like to vol3)."""

    def __init__(self, files):
        self._files = files

    def discover(self, p):
        return list(self._files)

    def archive_kind(self, p):
        return None

    def has_filesystem(self, p):
        return p.lower().endswith((".e01", ".ex01"))

    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": "Windows 10"}

    def memory_info(self, p):
        return None                       # vol3 probe failed / timed out

    def mount(self, disk, method, mp):
        return (True, "") if method == "raw@0" else (False, "x")

    def health(self, mem):
        return True, [], {}


def _run_onboard(files):
    probes = _ColdVol3Probes(files)
    return onboard("/c", on_event=lambda e: None, ai=None, probes=probes)


def test_memory_name_shape_rescue_pairs_with_disk(monkeypatch):
    monkeypatch.setenv("SIFT_MEMORY_NAME_SHAPE_RESCUE", "1")
    cases = _run_onboard(["/c/host-a-cdrive.E01", "/c/host-a-memory.img"])
    assert len(cases) == 1
    c = cases[0]
    assert c.memory_path and c.memory_path.endswith("host-a-memory.img")
    assert c.disk_path and c.disk_path.endswith("host-a-cdrive.E01")


def test_memory_rescue_kill_switch_preserves_old_behavior(monkeypatch):
    monkeypatch.setenv("SIFT_MEMORY_NAME_SHAPE_RESCUE", "0")
    cases = _run_onboard(["/c/host-a-cdrive.E01", "/c/host-a-memory.img"])
    assert len(cases) == 1
    assert cases[0].memory_path is None          # old behavior: silently dropped


def test_no_memory_shape_stays_unclassified(monkeypatch):
    # A non-filesystem file WITHOUT a memory role marker must NOT be rescued.
    monkeypatch.setenv("SIFT_MEMORY_NAME_SHAPE_RESCUE", "1")
    cases = _run_onboard(["/c/host-a-cdrive.E01", "/c/host-a-data.bin"])
    assert len(cases) == 1
    assert cases[0].memory_path is None


def test_real_memory_probe_timeout_returns_none(monkeypatch):
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="vol3", timeout=120)

    import sift_sentinel.onboard.engine as eng
    monkeypatch.setattr(eng.subprocess, "run", _boom)
    assert RealProbes().memory_info("/nonexistent.img") is None


# ---- B. disk-only domain discipline ----------------------------------------

def test_filter_tool_descriptions_drops_memory_tools(monkeypatch):
    from sift_sentinel.coordinator import filter_tool_descriptions_by_source
    monkeypatch.setenv("SIFT_SOURCE_CATALOG_FILTER", "1")
    monkeypatch.setenv("SIFT_HAS_DISK", "1")
    monkeypatch.setenv("SIFT_HAS_MEMORY", "0")
    avail = [
        {"name": "tool_vol_pstree", "description": "x"},
        {"name": "tool_get_amcache", "description": "y"},
    ]
    names = {t["name"] for t in filter_tool_descriptions_by_source(avail)}
    assert "tool_get_amcache" in names
    assert "tool_vol_pstree" not in names


def test_filter_tool_descriptions_kill_switch(monkeypatch):
    from sift_sentinel.coordinator import filter_tool_descriptions_by_source
    monkeypatch.setenv("SIFT_SOURCE_CATALOG_FILTER", "0")
    monkeypatch.setenv("SIFT_HAS_MEMORY", "0")
    avail = [{"name": "tool_vol_pstree", "description": "x"}]
    assert filter_tool_descriptions_by_source(avail) == avail


def test_strip_selection_drops_memory_tools(monkeypatch):
    from sift_sentinel.coordinator import strip_source_inapplicable_selection
    monkeypatch.setenv("SIFT_SOURCE_CATALOG_FILTER", "1")
    monkeypatch.setenv("SIFT_HAS_DISK", "1")
    monkeypatch.setenv("SIFT_HAS_MEMORY", "0")
    kept, dropped = strip_source_inapplicable_selection(
        ["vol_pstree", "get_amcache", "vol_malfind"]
    )
    assert kept == ["get_amcache"]
    assert set(dropped) == {"vol_pstree", "vol_malfind"}


def test_pair_injection_corroborators_noop_without_memory(monkeypatch):
    from sift_sentinel.coordinator import pair_injection_corroborators
    monkeypatch.setenv("SIFT_HAS_MEMORY", "0")
    sel = ["vol_malfind", "get_amcache"]
    assert pair_injection_corroborators(list(sel)) == sel


def test_step_03_ssdt_not_applicable_without_image(tmp_path, monkeypatch):
    from sift_sentinel.coordinator import step_03_ssdt
    trust = step_03_ssdt(tmp_path, None)
    assert trust == "not_applicable"
