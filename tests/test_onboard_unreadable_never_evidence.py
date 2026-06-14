"""A broken symlink or zero-byte file must NEVER be classified as evidence.

Live bug: an evidence folder contained ``<host>-memory.zip`` as a BROKEN
symlink (target deleted). Every content probe failed silently -- no magic, no
fsstat, no vol3 -- and the name-shape rescue then classified it MEMORY on the
filename alone. Index pairing handed it the host's disk, orphaning the real
vol3-confirmed image as a separate memory-only case: one host became two
cases, with an unreadable 'memory'.

Fix: before any classification, a candidate that is a broken link
(``os.path.lexists`` and not ``os.path.exists``) or has size 0 is set aside
with an honest 'unreadable' reason. Pure filesystem primitives -- no names.
Synthetic fake paths used by tests (which do not lexist at all) are unaffected,
preserving the probes-decide contract for injected paths.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard.engine import onboard, Probes, _host_token  # noqa: E402


class FSProbes(Probes):
    """Walks a real tmp dir; vol3 confirms .raw, fsstat confirms .e01."""

    def __init__(self, root):
        self._root = root

    def discover(self, p):
        out = []
        for base, _d, files in os.walk(self._root):
            for f in sorted(files):
                out.append(os.path.join(base, f))
        return out

    def archive_kind(self, p):
        return None
    def extract(self, p):
        return []
    def has_filesystem(self, p):
        return p.lower().endswith(".e01")
    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": ""}
    def memory_info(self, p):
        return {"NtMajorVersion": "10"} if p.lower().endswith(".raw") else None
    def mount(self, d, m, mp):
        return (True, "") if m == "raw@0" else (False, "x")
    def health(self, mem):
        return True, [], {"KeNumberProcessors": "2"}
    def cleanup(self):
        pass
    def disk_os(self, mp):
        return None


def _case_dir(tmp_path):
    d = tmp_path / "alpha-case"
    d.mkdir()
    (d / "alpha-memory.raw").write_bytes(b"\x00" * 4096)
    (d / "alpha-cdrive.e01").write_bytes(b"\x00" * 4096)
    return d


def test_broken_symlink_memory_never_classified(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    d = _case_dir(tmp_path)
    os.symlink(str(tmp_path / "gone" / "alpha-memory.zip"),
               str(d / "alpha-memory.zip"))            # broken link, memory name
    events = []
    cases = onboard(str(d), on_event=events.append, ai=None, probes=FSProbes(str(d)))
    assert len(cases) == 1                              # ONE case, not two
    c = cases[0]
    assert c.memory_path.endswith("alpha-memory.raw")   # the REAL image paired
    assert c.disk_path.endswith("alpha-cdrive.e01")
    assert not any((e.data.get("role") == "MEMORY"
                    and "zip" in str(e.data.get("name", "")))
                   for e in events), "broken link must never classify as MEMORY"
    assert any("unreadable" in str(e.detail).lower() or
               e.data.get("reason") == "unreadable" for e in events
               if e.phase == "CLASSIFY"), "must be set aside with an honest reason"


def test_zero_byte_file_never_classified(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    d = _case_dir(tmp_path)
    (d / "alpha-memdump.raw").write_bytes(b"")           # 0 bytes, memory name
    cases = onboard(str(d), on_event=lambda e: None, ai=None, probes=FSProbes(str(d)))
    assert len(cases) == 1
    assert cases[0].memory_path.endswith("alpha-memory.raw")


def test_injected_fake_paths_still_probe(monkeypatch):
    # fake paths that do not lexist at all keep the probes-decide contract
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class Fake(FSProbes):
        def __init__(self):
            pass
        def discover(self, p):
            return ["/e/host-memory.raw", "/e/host-cdrive.e01"]
    cases = onboard("/e", on_event=lambda e: None, ai=None, probes=Fake())
    assert len(cases) == 1
    assert cases[0].memory_path == "/e/host-memory.raw"
