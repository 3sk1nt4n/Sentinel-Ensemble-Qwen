"""Full-disk EWF/image classification: a partition-table disk (filesystem at a
non-zero offset) must classify as DISK, not get set aside as memory-only.

Regression for the real bug where a full C: drive .E01 (NTFS at sector 2048)
returned has_filesystem()=False because fsstat only probes offset 0. The mmls
escalation rescues it. Dataset-agnostic: partition-table structure only.
"""
from unittest import mock

from sift_sentinel.onboard.engine import RealProbes


def _run(stdout="", stderr=""):
    return mock.Mock(stdout=stdout, stderr=stderr)


def test_fsstat_at_offset0_still_classifies_disk(monkeypatch):
    p = RealProbes()
    monkeypatch.setattr(p, "_fsstat_target", lambda path: path)
    # fsstat @0 succeeds (bare single-partition image, e.g. base-wkstn)
    with mock.patch("subprocess.run", return_value=_run("File System Type: NTFS\n")):
        assert p.has_filesystem("/e/part.img") is True


def test_full_disk_partition_table_rescued_by_mmls(monkeypatch):
    p = RealProbes()
    monkeypatch.setattr(p, "_fsstat_target", lambda path: path)
    mmls_out = (
        "DOS Partition Table\n"
        "      Slot      Start        End          Length       Description\n"
        "002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)\n"
        "003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)\n"
    )
    def fake_run(cmd, *a, **k):
        # fsstat @0 fails on a full-disk image; mmls reveals the NTFS partitions
        if "fsstat" in cmd:
            return _run(stderr="Cannot determine file system type\n")
        if "mmls" in cmd:
            return _run(stdout=mmls_out)
        return _run()
    with mock.patch("subprocess.run", side_effect=fake_run):
        assert p.has_filesystem("/e/CDrive.E01") is True


def test_truly_non_image_stays_false(monkeypatch):
    p = RealProbes()
    monkeypatch.setattr(p, "_fsstat_target", lambda path: path)
    def fake_run(cmd, *a, **k):
        if "fsstat" in cmd:
            return _run(stderr="Cannot determine file system type\n")
        if "mmls" in cmd:
            return _run(stderr="Cannot determine partition type\n")
        return _run()
    with mock.patch("subprocess.run", side_effect=fake_run):
        assert p.has_filesystem("/e/notes.pdf") is False
