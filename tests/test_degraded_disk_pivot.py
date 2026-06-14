"""Degraded-memory disk pivot: when the memory profile is DEGRADED (corrupted
kernel metadata -> metadata-walker plugins return nothing) AND a disk is present,
the high-value DISK tool injection gets extra budget so the full disk set lands
-- the same 'pivot to where the evidence is' the disk-only path already does.

ADDITIVE ONLY: memory tools are never removed/blacklisted (the nocheat rule
forbids a degraded broken-tool list). Universal: profile-health boolean +
disk-present, no tool list. Kill-switch SIFT_DEGRADED_DISK_PIVOT=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.coordinator import degraded_disk_tool_budget as B  # noqa: E402


def test_healthy_profile_no_change():
    assert B(35, degraded=False, disk_present=True, env={}) == 35


def test_degraded_without_disk_no_change():
    # nothing to pivot to -- memory-only degraded keeps the base budget
    assert B(35, degraded=True, disk_present=False, env={}) == 35


def test_degraded_with_disk_raises_budget():
    out = B(35, degraded=True, disk_present=True, env={})
    assert out > 35
    assert out <= 35 + 12          # bounded headroom


def test_headroom_is_configurable_and_bounded():
    assert B(35, degraded=True, disk_present=True, env={"SIFT_DEGRADED_DISK_HEADROOM": "4"}) == 39
    # clamp absurd values
    assert B(35, degraded=True, disk_present=True, env={"SIFT_DEGRADED_DISK_HEADROOM": "999"}) == 35 + 12
    assert B(35, degraded=True, disk_present=True, env={"SIFT_DEGRADED_DISK_HEADROOM": "-5"}) == 35


def test_kill_switch_restores_base():
    for v in ("0", "false", "no", "off"):
        assert B(35, degraded=True, disk_present=True, env={"SIFT_DEGRADED_DISK_PIVOT": v}) == 35


def test_never_lowers_budget():
    # additive only -- never returns less than the base cap
    assert B(35, degraded=True, disk_present=True, env={}) >= 35
