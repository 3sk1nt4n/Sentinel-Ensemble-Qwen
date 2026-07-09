"""Filesystem-level SleuthKit tools must sweep mmls partition offsets on a
full-disk image (offset 0 is the partition table, not a filesystem). Regression
for fls/tsk_recover failing 'Cannot determine file system type' on DC01-style
partitioned disks. Universal / dataset-agnostic.
"""
from unittest import mock

from sift_sentinel.tools import generic


class _P:
    def __init__(self, rc, out="", err=""):
        self.returncode = rc; self.stdout = out; self.stderr = err


def _fake_run_factory(by_offset):
    """by_offset: dict {offset_or_None: _P}. Reads -o from the argv."""
    def _run(cmd, *a, **k):
        off = None
        if "-o" in cmd:
            off = int(cmd[cmd.index("-o") + 1])
        return by_offset.get(off, _P(1, "", "Cannot determine file system type"))
    return _run


def test_partitioned_disk_aggregates_offsets():
    # offset 0 fails; two NTFS partitions each return rows -> aggregated.
    by = {None: _P(1, "", "Cannot determine file system type"),
          2048: _P(0, "r/r 4-1: sysreserved\n"),
          718848: _P(0, "r/r 5-1: windows\n")}
    with mock.patch.object(generic, "_SLEUTHKIT_COMMANDS", ["fls"], create=True), \
         mock.patch("sift_sentinel.tools.disk._mmls_partition_offsets", return_value=[2048, 718848]), \
         mock.patch("subprocess.run", side_effect=_fake_run_factory(by)):
        out = generic.run_sleuthkit("fls", "/e/disk.E01")
    assert out.get("record_count", 0) == 2          # both partitions' rows
    assert out.get("returncode") == 0
    assert out.get("failure_mode") is None


def test_raw_single_fs_image_uses_whole_image():
    # No partition table: mmls returns [] -> whole-image (offset None) works.
    by = {None: _P(0, "r/r 5-1: file\n")}
    with mock.patch.object(generic, "_SLEUTHKIT_COMMANDS", ["fls"], create=True), \
         mock.patch("sift_sentinel.tools.disk._mmls_partition_offsets", return_value=[]), \
         mock.patch("subprocess.run", side_effect=_fake_run_factory(by)):
        out = generic.run_sleuthkit("fls", "/e/part.dd")
    assert out.get("record_count", 0) == 1
    assert out.get("returncode") == 0


def test_all_offsets_fail_preserves_error_envelope():
    by = {None: _P(1, "", "Cannot determine file system type")}
    with mock.patch.object(generic, "_SLEUTHKIT_COMMANDS", ["fls"], create=True), \
         mock.patch("sift_sentinel.tools.disk._mmls_partition_offsets", return_value=[2048]), \
         mock.patch("subprocess.run", side_effect=_fake_run_factory(by)):
        out = generic.run_sleuthkit("fls", "/e/disk.E01")
    assert out.get("failure_mode") == "runtime_error"
    assert "file system type" in (out.get("error", "").lower())


def test_caller_pinned_offset_disables_auto():
    # If the caller already passed -o, we must NOT auto-sweep (mmls not consulted).
    by = {4096: _P(0, "r/r 5-1: pinned\n")}
    m = mock.Mock(return_value=[2048, 718848])
    with mock.patch.object(generic, "_SLEUTHKIT_COMMANDS", ["fls"], create=True), \
         mock.patch("sift_sentinel.tools.disk._mmls_partition_offsets", m), \
         mock.patch("subprocess.run", side_effect=_fake_run_factory(by)):
        out = generic.run_sleuthkit("fls", "/e/disk.E01", args=["-o", "4096"])
    assert out.get("record_count", 0) == 1
    m.assert_not_called()


def test_kill_switch_disables_offset_sweep(monkeypatch):
    monkeypatch.setenv("SIFT_SLEUTHKIT_OFFSET", "0")
    by = {None: _P(1, "", "Cannot determine file system type")}
    m = mock.Mock(return_value=[2048])
    with mock.patch.object(generic, "_SLEUTHKIT_COMMANDS", ["fls"], create=True), \
         mock.patch("sift_sentinel.tools.disk._mmls_partition_offsets", m), \
         mock.patch("subprocess.run", side_effect=_fake_run_factory(by)):
        generic.run_sleuthkit("fls", "/e/disk.E01")
    m.assert_not_called()
