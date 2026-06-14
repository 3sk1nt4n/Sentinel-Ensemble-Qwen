"""Content-signature memory probe: classify memory by PROBING bytes, not the name.

The onboarding spec: "tell memory / disk / documents apart by PROBING them (not
by file name)". A Windows crash dump and a LiME capture are provable from their
offset-0 magic alone -- no vol3 symbols, no 120s timeout, and ZERO false
positives on disk images (a disk carries a boot sector / partition table at
offset 0, never these magics). This lets a memory image with an unhelpful name
be classified the instant it is read.

Universal: offset-0 magic only, no case data. Kill-switch
SIFT_MEMORY_SIGNATURE_PROBE=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard.engine import RealProbes, onboard, Probes  # noqa: E402

PAGEDUMP = b"PAGEDUMP" + b"\x00" * 56
PAGEDU64 = b"PAGEDU64" + b"\x00" * 56
LIME = b"EMiL" + b"\x00" * 60                 # LiME header magic 0x4C694D45 (LE)
NTFS_BOOT = b"\xeb\x52\x90NTFS    " + b"\x00" * 48   # a disk boot sector
ZEROS = b"\x00" * 64


def _w(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_crashdump_magic_is_memory(tmp_path):
    rp = RealProbes()
    assert rp.memory_signature(_w(tmp_path, "a.bin", PAGEDUMP)) == "crashdump"
    assert rp.memory_signature(_w(tmp_path, "b.bin", PAGEDU64)) == "crashdump"


def test_lime_magic_is_memory(tmp_path):
    assert RealProbes().memory_signature(_w(tmp_path, "c.bin", LIME)) == "lime"


def test_disk_boot_and_zeros_are_not_memory_by_signature(tmp_path):
    rp = RealProbes()
    assert rp.memory_signature(_w(tmp_path, "disk.bin", NTFS_BOOT)) is None
    assert rp.memory_signature(_w(tmp_path, "raw.bin", ZEROS)) is None


def test_abc_default_is_none(tmp_path):
    # an unimplemented probe fails closed (so existing fakes never misclassify)
    assert Probes().memory_signature(_w(tmp_path, "x.bin", PAGEDUMP)) is None


def test_signature_routes_to_memory_in_classify(tmp_path, monkeypatch):
    # a crash dump with a NON-memory name is still classified MEMORY by content
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class P(Probes):
        def discover(self, p): return ["/e/acquisition-7.bin", "/e/host-cdrive.E01"]
        def archive_kind(self, p): return None
        def has_filesystem(self, p): return p.lower().endswith(".e01")
        def fs_facts(self, p): return {"fstype": "NTFS", "volume": "", "version": ""}
        def memory_info(self, p): return None
        def memory_signature(self, p):
            return "crashdump" if p.endswith(".bin") else None
        def mount(self, d, m, mp): return (True, "") if m == "raw@0" else (False, "x")
        def health(self, mem): return True, [], {"KeNumberProcessors": "2"}
        def cleanup(self): pass
        def disk_os(self, mp): return None

    events = []
    cases = onboard("/e", on_event=events.append, ai=None, probes=P())
    assert len(cases) == 1
    assert cases[0].memory_path == "/e/acquisition-7.bin"
    assert any(e.data.get("probe", "").startswith("signature")
               for e in events if e.data.get("role") == "MEMORY")


def test_kill_switch_disables_signature_routing(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    monkeypatch.setenv("SIFT_MEMORY_SIGNATURE_PROBE", "0")

    class P(Probes):
        def discover(self, p): return ["/e/acquisition-7.bin", "/e/host-cdrive.E01"]
        def archive_kind(self, p): return None
        def has_filesystem(self, p): return p.lower().endswith(".e01")
        def fs_facts(self, p): return {"fstype": "NTFS", "volume": "", "version": ""}
        def memory_info(self, p): return None
        def memory_signature(self, p): return "crashdump" if p.endswith(".bin") else None
        def mount(self, d, m, mp): return (True, "") if m == "raw@0" else (False, "x")
        def health(self, mem): return True, [], {"KeNumberProcessors": "2"}
        def cleanup(self): pass
        def disk_os(self, mp): return None

    cases = onboard("/e", on_event=lambda e: None, ai=None, probes=P())
    # signature routing OFF -> the .bin is not memory (no name word, vol3 None) ->
    # disk-only case, memory unresolved
    assert cases and cases[0].memory_path is None
