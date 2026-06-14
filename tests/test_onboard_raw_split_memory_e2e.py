"""End-to-end: a raw split-memory image next to a disk is onboarded as MEMORY,
not swallowed by the extractor.

Reproduces the live layout that failed: two sibling subdirs, one holding the
disk (.E01), the other holding a raw memory dump as a split .001 (no magic) plus
small sidecars. With the real archive.detect_archive in the loop, the pre-fix
code classified the .001 as a SPLIT archive, extracted nothing, and produced a
disk-only case with NO memory. After the fix the .001 reaches classification,
is rescued as memory (vol3 simulated to time out), and pairs to the disk by host.

Universal: synthetic zero-byte images + generic host names; no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard import archive as A          # noqa: E402
from sift_sentinel.onboard.engine import onboard, Probes, _host_token  # noqa: E402


class RealArchiveFake(Probes):
    """Fakes the heavy tools (fsstat/vol/mount) but uses the REAL magic-based
    archive detection -- the component that decides extract-vs-classify."""

    def __init__(self, root):
        self._root = root

    def discover(self, p):
        out = []
        for base, _d, files in os.walk(self._root):
            for f in sorted(files):
                out.append(os.path.join(base, f))
        return out

    def archive_kind(self, p):
        return A.detect_archive(p)                       # the real decision
    def extract(self, p):
        return []                                        # a mis-detected split yields nothing
    def magic(self, p):
        return A.magic_hex(p, 16)
    def has_filesystem(self, p):
        return p.lower().endswith(".e01")                # only the disk has a FS
    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": ""}
    def memory_info(self, p):
        return None                                      # vol3 times out on the cold dump
    def mount(self, disk, method, mp):
        return (True, "") if method == "raw@0" else (False, "x")
    def health(self, mem):
        return True, [], {"KeNumberProcessors": "2"}
    def cleanup(self):
        pass
    def disk_os(self, mp):
        return None


def test_raw_split_memory_is_onboarded_with_its_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    case = tmp_path / "host7-dc"
    (case / "host7-c-drive").mkdir(parents=True)
    (case / "host7-memory").mkdir(parents=True)
    (case / "host7-c-drive" / "host7-c-drive.E01").write_bytes(b"\x00" * 4096)
    (case / "host7-c-drive" / "host7-c-drive.E01.txt").write_bytes(b"meta\n")
    (case / "host7-memory" / "host7-memory-raw.001").write_bytes(b"\x00" * 4096)
    (case / "host7-memory" / "host7-memory-raw.001.txt").write_bytes(b"meta\n")

    cases = onboard(str(case), on_event=lambda e: None, ai=None,
                    probes=RealArchiveFake(str(case)))

    assert len(cases) == 1
    c = cases[0]
    assert c.memory_path and c.memory_path.endswith("host7-memory-raw.001")
    assert c.disk_path and c.disk_path.endswith("host7-c-drive.E01")
    assert _host_token(c.memory_path) == _host_token(c.disk_path)
