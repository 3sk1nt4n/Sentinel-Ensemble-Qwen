"""Two live-proven Step 6 data-loss fixes (acme Fable/Opus runs).

1. run_mftecmd '1 record' bug: coordinator passed the MOUNT ROOT DIRECTORY as
   MFTECmd's -f argument (SIFT_MFT_MOUNT_ROOT_PATH_V1). MFTECmd needs the $MFT
   FILE; with a directory it produces no CSV rows and the wrapper emits one
   'complete_no_data' placeholder -- masquerading as data ('1 records') while
   477,567 real FILE records (measured on the live E01 via icat+MFTECmd: 469MB
   $MFT -> 602k CSV rows in 3.5s) were silently lost, including the $FN
   timestamps that enable timestomp detection.
   Fix: resolve_mft_source() returns a real $MFT file -- mount-exposed if
   present, else icat-extracted (TSK reads raw/E01; signature-validated,
   cached). run_mftecmd refuses directories outright (honest error, no
   placeholder).

2. vol_hollowprocesses 0 records: it walks every process like its siblings
   (malfind measured 3m04s) but was left on the 90s DEFAULT timeout -> timed
   out with 0 records on every live run. Same fix as psscan/netscan/psxview
   (the documented VOL_TIMEOUTS pattern): HEAVY tier so it can COMPLETE.
"""
import os
import types

from sift_sentinel.tools.common import (
    VOL_TIMEOUT_HEAVY,
    VOL_TIMEOUTS,
)
from sift_sentinel.tools import disk as disk_mod
from sift_sentinel.tools import generic as gen


# ── fix 2: hollowprocesses completes instead of timing out ──────────────
def test_hollowprocesses_gets_heavy_timeout():
    assert VOL_TIMEOUTS.get("vol_hollowprocesses") == VOL_TIMEOUT_HEAVY, (
        "vol_hollowprocesses walks every process (sibling of malfind, "
        "measured 3m04s) -- on the 90s default it times out with 0 records "
        "every run; it must ride the HEAVY tier so it can COMPLETE."
    )


# ── fix 1: $MFT source resolution ────────────────────────────────────────
def test_mount_exposed_mft_file_wins(tmp_path):
    mft = tmp_path / "$MFT"
    mft.write_bytes(b"FILE0" + b"\x00" * 100)
    got = disk_mod.resolve_mft_source(str(tmp_path), "", out_dir=str(tmp_path))
    assert got == str(mft)


def test_extracts_via_icat_when_mount_hides_mft(tmp_path, monkeypatch):
    # ntfs-3g mounts do NOT expose $MFT; the resolver must extract it from the
    # disk image via icat (signature-validated). Fake the icat run.
    disk_img = tmp_path / "disk.e01"
    disk_img.write_bytes(b"EWF")
    mount = tmp_path / "mnt"
    mount.mkdir()

    def _fake_run(cmd, **kw):
        if cmd[0] == "icat":
            with open(cmd[-2] if cmd[-1] == "0" and False else kw["stdout"].name, "wb"):
                pass  # unused branch guard
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    def _fake_icat(image, offset, out_path, timeout=300):
        with open(out_path, "wb") as f:
            f.write(b"FILE0" + b"\x00" * 4096)
        return True

    monkeypatch.setattr(disk_mod, "_icat_extract", _fake_icat)
    got = disk_mod.resolve_mft_source(
        str(mount), str(disk_img), out_dir=str(tmp_path / "out"))
    assert got and os.path.isfile(got)
    with open(got, "rb") as f:
        assert f.read(4) == b"FILE"


def test_extraction_cached_second_call_no_rerun(tmp_path, monkeypatch):
    disk_img = tmp_path / "disk.raw"
    disk_img.write_bytes(b"X")
    calls = []

    def _fake_icat(image, offset, out_path, timeout=300):
        calls.append(offset)
        with open(out_path, "wb") as f:
            f.write(b"FILE0" + b"\x00" * 4096)
        return True

    monkeypatch.setattr(disk_mod, "_icat_extract", _fake_icat)
    out = str(tmp_path / "out")
    a = disk_mod.resolve_mft_source("", str(disk_img), out_dir=out)
    b = disk_mod.resolve_mft_source("", str(disk_img), out_dir=out)
    assert a == b
    assert len(calls) == 1                      # cached, not re-extracted


def test_bad_signature_rejected(tmp_path, monkeypatch):
    disk_img = tmp_path / "disk.raw"
    disk_img.write_bytes(b"X")

    def _fake_icat(image, offset, out_path, timeout=300):
        with open(out_path, "wb") as f:
            f.write(b"JUNK" + b"\x00" * 4096)   # not an MFT
        return True

    monkeypatch.setattr(disk_mod, "_icat_extract", _fake_icat)
    got = disk_mod.resolve_mft_source("", str(disk_img),
                                      out_dir=str(tmp_path / "out"))
    assert got == ""                            # honest empty, no junk path


def test_no_source_returns_empty():
    assert disk_mod.resolve_mft_source("", "", out_dir="/tmp/nonexistent-x") == ""


# ── run_mftecmd refuses directories (defense in depth) ──────────────────
def test_run_mftecmd_rejects_directory(tmp_path):
    r = gen.run_mftecmd(str(tmp_path))
    assert r.get("record_count", 0) == 0
    assert "directory" in (r.get("error") or "").lower()
