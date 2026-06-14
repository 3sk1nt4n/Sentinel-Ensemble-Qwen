"""A split RAW IMAGE (.001) is NOT a split ARCHIVE — it must reach classification.

Bug (a live paired run): a 2.68GB raw memory dump named "...memory-raw.001"
(all-zero header, no magic) was classified by detect_archive() as "SPLIT" purely
from its ``.001`` extension, routed into the extractor, found to contain no
archive, and silently dropped -- so the whole case ran disk-only and lost every
memory detection. The same path also produced the user-visible "not unzipping".

Fix: a BARE ``.001`` is a split archive only when its offset-0 magic is a known
archive magic (zip/7z/rar/...). Explicit ``.zip.001``/``.7z.001``/``.rar.001``
naming stays definitive. A raw-image ``.001`` (memory or disk: zeros, MBR, NTFS)
has no archive magic -> NOT an archive -> flows to disk/memory classification.
Magic-first, universal, no case data. Kill-switch SIFT_SPLIT_REQUIRE_MAGIC=0
restores the legacy extension-only behavior.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.onboard import archive as A  # noqa: E402

ZIP = b"\x50\x4b\x03\x04" + b"\x00" * 28
SEVENZ = b"\x37\x7a\xbc\xaf\x27\x1c" + b"\x00" * 26
RAR = b"\x52\x61\x72\x21\x1a\x07" + b"\x00" * 26
ZEROS = b"\x00" * 4096                       # raw memory dump header (no magic)
MBR = b"\x00" * 510 + b"\x55\xaa" + b"\x00" * 3584   # a disk split: still no offset-0 archive magic


def _w(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_raw_memory_001_is_not_a_split_archive(tmp_path):
    mem = _w(tmp_path, "host-memory-raw.001", ZEROS)
    assert A._is_split_first(mem) is False
    assert A.detect_archive(mem) is None        # flows to classification, not extract


def test_disk_split_001_is_not_a_split_archive(tmp_path):
    disk = _w(tmp_path, "host-disk.001", MBR)
    assert A._is_split_first(disk) is False
    assert A.detect_archive(disk) is None


def test_real_zip_split_001_is_still_extracted(tmp_path):
    z = _w(tmp_path, "evidence.001", ZIP)
    assert A._is_split_first(z) is True
    assert A.detect_archive(z) == "SPLIT"


def test_real_7z_and_rar_split_001_still_extracted(tmp_path):
    assert A._is_split_first(_w(tmp_path, "eviz.001", SEVENZ)) is True
    assert A._is_split_first(_w(tmp_path, "evir.001", RAR)) is True


def test_explicit_archive_split_naming_is_definitive(tmp_path):
    # .zip.001 / .7z.001 / .rar.001 -> SPLIT even without readable magic
    for n in ("backup.zip.001", "dump.7z.001", "pack.rar.001"):
        assert A._is_split_first(_w(tmp_path, n, ZEROS)) is True


def test_kill_switch_restores_legacy_extension_only(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_SPLIT_REQUIRE_MAGIC", "0")
    mem = _w(tmp_path, "host-memory-raw.001", ZEROS)
    assert A._is_split_first(mem) is True        # legacy: any .001 is a split archive
