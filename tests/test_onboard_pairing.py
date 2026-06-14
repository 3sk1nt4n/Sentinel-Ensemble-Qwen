"""Step-0 pairing + hygiene: memory and disk images pair by SHARED HOST TOKEN
(never by sorted index); symlink aliases collapse to one case; known non-image
forensic artifacts are kept quietly, not flagged UNKNOWN. All host names here are
GENERIC placeholders (alpha/bravo/...), never case-specific evidence.
"""
import os
import pytest
from sift_sentinel.onboard.engine import (
    _host_token, _pair_by_host, _is_non_image_artifact, onboard, Probes,
)


class ListProbes(Probes):
    """Role by suffix; each entry discovers to itself. No real tools."""
    def discover(self, p): return [p]
    def archive_kind(self, p): return None
    def has_filesystem(self, p): return p.lower().endswith((".e01", ".dd"))
    def fs_facts(self, p): return {"fstype": "NTFS", "volume": "", "version": ""}
    def memory_info(self, p):
        return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                if p.lower().endswith((".raw", ".img")) else None)
    def mount(self, disk, method, mp): return (True, "") if method == "raw@0" else (False, "x")
    def health(self, mem): return True, [], {"KeNumberProcessors": "4"}
    def cleanup(self): pass
    def disk_os(self, mp): return None


# ── host token normalization ───────────────────────────────────────────────
def test_host_token_strips_role_and_separators():
    assert _host_token("alpha-memory.img") == "alpha"
    assert _host_token("alpha-cdrive.E01") == "alpha"
    assert _host_token("bravo-mem.raw") == _host_token("bravo-cdrive.E01") == "bravo"


def test_host_token_normalizes_hyphen_variants():
    # 'delta-01' vs 'delta01' must resolve to the SAME host
    assert _host_token("delta-01-memory.img") == _host_token("delta01-cdrive.E01")


def test_host_token_c_drive_leaves_no_stray_c():
    assert _host_token("echo-host-c-drive.E01") == _host_token("echo-host-memory-raw")


# ── pairing by host, not by index ──────────────────────────────────────────
def test_pair_by_host_not_by_index():
    # disks deliberately sorted in a DIFFERENT order than memories
    memories = [("/e/alpha-memory.img", {}), ("/e/bravo-memory.img", {}),
                ("/e/charlie-memory.img", {})]
    disks = ["/e/bravo-cdrive.E01", "/e/charlie-cdrive.E01", "/e/alpha-cdrive.E01"]
    pairs = _pair_by_host(memories, disks)
    by = {_host_token(m[0]): d for m, d in pairs if m and d}
    assert _host_token(by["alpha"]) == "alpha"      # alpha mem -> alpha disk
    assert _host_token(by["bravo"]) == "bravo"
    assert _host_token(by["charlie"]) == "charlie"


def test_pair_by_host_single_source_hosts():
    memories = [("/e/alpha-memory.img", {}), ("/e/lonely-memory.img", {})]
    disks = ["/e/alpha-cdrive.E01", "/e/orphan-cdrive.E01"]
    pairs = _pair_by_host(memories, disks)
    # alpha paired; lonely is mem-only; orphan is disk-only
    assert (("/e/alpha-memory.img", {}), "/e/alpha-cdrive.E01") in [
        (m, d) for m, d in pairs]
    assert any(m and not d and _host_token(m[0]) == "lonely" for m, d in pairs)
    assert any(d and not m and _host_token(d) == "orphan" for m, d in pairs)


def test_onboard_multihost_pairs_correctly(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class MultiHost(ListProbes):
        def discover(self, p):
            return ["/e/alpha-memory.img", "/e/bravo-cdrive.E01",
                    "/e/bravo-memory.img", "/e/charlie-cdrive.E01",
                    "/e/charlie-memory.img", "/e/alpha-cdrive.E01"]
    cases = onboard("/e", on_event=lambda e: None, ai=None, probes=MultiHost())
    assert len(cases) == 3
    for c in cases:                                  # every case is self-consistent
        assert _host_token(c.memory_path) == _host_token(c.disk_path)


# ── symlink alias dedup ────────────────────────────────────────────────────
def test_symlink_aliases_collapse_to_one_case(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    real = tmp_path / "host-memory.raw"; real.write_bytes(b"x" * 4096)
    alias = tmp_path / "alias-memory.raw"; os.symlink(real, alias)

    class P(ListProbes):
        def discover(self, p): return [str(real), str(alias)]
    cases = onboard(str(tmp_path), on_event=lambda e: None, ai=None, probes=P())
    assert len(cases) == 1                            # alias deduped by realpath


# ── known non-image artifacts ──────────────────────────────────────────────
def test_artifact_recognizer():
    for n in ("triage.mans", "plaso_proto.000001", "case-bodyfile",
              "srum.db", "events.evtx", "cap.pcapng"):
        assert _is_non_image_artifact(n), n
    for n in ("host-memory.raw", "host-cdrive.E01", "mem.img"):
        assert not _is_non_image_artifact(n), n


def test_artifacts_kept_quietly_not_unknown(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class P(ListProbes):
        def discover(self, p):
            return ["/e/host-memory.raw", "/e/triage.mans",
                    "/e/plaso_proto.000001", "/e/case-bodyfile"]
    events = []
    cases = onboard("/e", on_event=events.append, ai=None, probes=P())
    assert len(cases) == 1                            # only the image is a case
    assert not any(e.data.get("role") == "UNKNOWN" for e in events)
    # artifacts now roll into the single 'set aside' summary (3 = mans+plaso+body)
    setaside = [e for e in events if e.data.get("role") == "SETASIDE"]
    assert setaside and setaside[0].data.get("count") == 3


# ── duplicate-copy dedup + mount ladder + no-Notes card ─────────────────────
def test_duplicate_copies_collapse_to_one_case(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class Dup(ListProbes):
        def discover(self, p):
            # same host's memory + disk appear as COPIES in two folders
            return ["/a/host-memory.img", "/a/host-cdrive.E01",
                    "/b/host-memory.img", "/b/host-cdrive.E01"]
    cases = onboard("/x", on_event=lambda e: None, ai=None, probes=Dup())
    assert len(cases) == 1                      # not two identical cards


def test_mount_ladder_tries_offset_before_dmpad():
    from sift_sentinel.onboard.engine import MOUNT_LADDER
    assert MOUNT_LADDER == ("raw@0", "ntfs_offsets", "dmpad")

    tried = []

    class OffsetOnly(ListProbes):
        def discover(self, p): return ["/e/h-memory.img", "/e/h-cdrive.E01"]
        def mount(self, disk, method, mp):
            tried.append(method)
            return (True, "") if method == "ntfs_offsets" else (False, "no vol")
    cases = onboard("/e", on_event=lambda e: None, ai=None, probes=OffsetOnly())
    assert cases[0].mount_method == "ntfs_offsets"
    assert tried[:2] == ["raw@0", "ntfs_offsets"]   # raw@0 first, then offsets


def test_card_has_no_notes_row():
    import re as _re
    from sift_sentinel.onboard import presenter
    from sift_sentinel.onboard.engine import CaseManifest
    m = CaseManifest(
        case_id="c", os="Windows XP (NT 5.1)", os_source="memory",
        memory_path="/e/h-memory.raw", memory_health="HEALTHY",
        memory_health_facts={}, disk_path="/e/h-cdrive.E01", disk_mounted=True,
        mount_method="raw@0", mount_path="/mnt/c", reference_docs=[],
        documents=["/e/brief.pptx", "/e/timeline.xlsx"],
        os_profile={"memory": "Windows XP (NT 5.1)", "agree": False})
    card = _re.sub(r"\x1b\[[0-9;]*m", "", presenter.case_card(m, color=False))
    assert "Notes" not in card
    assert "brief.pptx" not in card             # docs no longer clutter the card
    assert "Scope" in card and "Basis" in card  # the kept rows remain


# ── extraction robustness: disk-full / bad archive never crashes onboarding ──
def test_disk_full_during_extract_does_not_crash(monkeypatch):
    import errno as _errno
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class DiskFull(ListProbes):
        def discover(self, p):
            # a loose memory image + disk sit next to a (huge) archive
            return ["/e/host-memory.img", "/e/host-cdrive.E01", "/e/evidence.zip"]
        def archive_kind(self, p):
            return "ZIP" if p.endswith(".zip") else None
        def extract(self, p):
            raise OSError(_errno.ENOSPC, "No space left on device")
    events = []
    cases = onboard("/e", on_event=events.append, ai=None, probes=DiskFull())
    # onboarding survived and still produced the case from the loose images
    assert len(cases) == 1
    assert cases[0].memory_path and cases[0].disk_path
    # a clear no-space WARN was emitted, not a traceback
    warns = [e for e in events if e.phase == "EXTRACT" and e.status == "WARN"]
    assert any(e.data.get("error") == "no_space" for e in warns)


def test_corrupt_archive_is_skipped_not_fatal(monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")

    class Corrupt(ListProbes):
        def discover(self, p):
            return ["/e/host-memory.img", "/e/host-cdrive.E01", "/e/bad.7z"]
        def archive_kind(self, p):
            return "7Z" if p.endswith(".7z") else None
        def extract(self, p):
            raise ValueError("corrupt header")          # any failure, not OSError
    cases = onboard("/e", on_event=lambda e: None, ai=None, probes=Corrupt())
    assert len(cases) == 1                               # survived, used loose images


# ── disk-space preflight: abort cleanly, never crash with Errno 28 ──────────
def test_low_disk_space_aborts_cleanly(monkeypatch):
    import sift_sentinel.onboard.engine as eng
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    monkeypatch.setattr(eng, "_tmp_free_bytes", lambda: 100 * (1 << 20))  # 100 MB free
    monkeypatch.setenv("SIFT_ONBOARD_MIN_FREE_MB", "1024")                 # need 1 GB

    class P(ListProbes):
        def discover(self, p): return ["/e/host-memory.img", "/e/host-cdrive.E01"]
    events = []
    cases = onboard("/e", on_event=events.append, ai=None, probes=P())
    assert cases == []                                # aborted, no crash
    err = [e for e in events if e.phase == "ERROR" and e.status == "FAIL"]
    assert err and "disk space" in err[0].detail.lower()


def test_enough_disk_space_proceeds(monkeypatch):
    import sift_sentinel.onboard.engine as eng
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    monkeypatch.setattr(eng, "_tmp_free_bytes", lambda: 50 * (1 << 30))   # 50 GB free

    class P(ListProbes):
        def discover(self, p): return ["/e/host-memory.img", "/e/host-cdrive.E01"]
    cases = onboard("/e", on_event=lambda e: None, ai=None, probes=P())
    assert len(cases) == 1                            # plenty of space -> normal run
