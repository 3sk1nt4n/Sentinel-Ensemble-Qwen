"""Dataset-agnostic discovery proof.

Builds a synthetic evidence directory with RANDOM names containing:
  (a) a fabricated tiny FAT filesystem image (via mkfs.vfat), and
  (b) a "memory-like" raw file (a planted content marker) nested inside a
      zip-in-7z.
A content-only probe set (classifies by reading bytes, never by name/extension)
drives engine.onboard. The test asserts the two are discovered, the archive
nest is recursively extracted, and they are paired into ONE case purely from
probe verdicts.

Nothing here references any real dataset - that absence is the agnosticism
proof. The engine itself never branches on filename/extension; it trusts only
probe results, which is what this exercises end-to-end.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
import zipfile

import pytest

from sift_sentinel.onboard.engine import Probes, onboard

_SEVENZ = shutil.which("7z") or shutil.which("7za")
_MKFS = shutil.which("mkfs.vfat") or shutil.which("mkfs.fat")

pytestmark = pytest.mark.skipif(
    not (_SEVENZ and _MKFS),
    reason="needs the 7z and mkfs.vfat binaries to fabricate real artifacts",
)


class ContentProbes(Probes):
    """Classifies strictly by file CONTENT (random names are irrelevant)."""

    def discover(self, path):
        out = []
        for root, _d, files in os.walk(path):
            out.extend(os.path.join(root, f) for f in sorted(files))
        return out

    def magic(self, path):
        try:
            with open(path, "rb") as fh:
                return fh.read(8).hex()
        except OSError:
            return ""

    def archive_kind(self, path):
        m = self.magic(path)
        if m.startswith("504b0304"):
            return "ZIP"
        if m.startswith("377abcaf271c"):
            return "7Z"
        return None

    def extract(self, path):
        dest = os.path.join(os.path.dirname(path),
                            "_ex_" + uuid.uuid4().hex[:8])
        os.makedirs(dest, exist_ok=True)
        kind = self.archive_kind(path)
        if kind == "ZIP":
            with zipfile.ZipFile(path) as zf:
                zf.extractall(dest)
        elif kind == "7Z":
            subprocess.run([_SEVENZ, "x", f"-o{dest}", "-y", path],
                           capture_output=True, text=True, timeout=120)
        kids = []
        for root, _d, files in os.walk(dest):
            kids.extend(os.path.join(root, f) for f in files)
        return sorted(kids)

    def has_filesystem(self, path):
        try:
            with open(path, "rb") as fh:
                boot = fh.read(512)
        except OSError:
            return False
        return len(boot) >= 512 and boot[510:512] == b"\x55\xaa" and b"FAT" in boot

    def fs_facts(self, path):
        return {"fstype": "FAT", "volume": "", "version": ""}

    def memory_info(self, path):
        try:
            with open(path, "rb") as fh:
                head = fh.read(64)
        except OSError:
            return None
        if b"MEMDUMP" in head:                # planted memory marker
            return {"NtMajorVersion": "6", "NtMinorVersion": "1",
                    "KeNumberProcessors": "2"}
        return None

    def mount(self, disk, method, mountpoint):
        return False, "fabricated test image - not mounted"

    def health(self, mem):
        return True, [], {"KeNumberProcessors": "2"}

    def cleanup(self):
        pass


def test_discovery_pairs_disk_and_memory_purely_by_probe(tmp_path, monkeypatch):
    # Synthetic images are tiny; probe everything (the 50 MB floor is for real runs).
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    scan = tmp_path / f"case_{uuid.uuid4().hex[:8]}"
    scan.mkdir()
    staging = tmp_path / "staging"          # sibling: NOT inside the scan tree
    staging.mkdir()

    # (a) real tiny FAT image, random name, in the scan directory
    disk_name = f"{uuid.uuid4().hex[:10]}.bin"
    disk_path = scan / disk_name
    subprocess.run([_MKFS, "-C", str(disk_path), "512"],
                   check=True, capture_output=True)

    # (b) memory-like raw (planted marker) nested inside zip-in-7z, random name
    mem_name = f"{uuid.uuid4().hex[:10]}.dat"
    (staging / mem_name).write_bytes(b"MEMDUMP-NTKRNL\x00" + b"\x00" * 8192)
    inner_zip = staging / f"{uuid.uuid4().hex[:8]}.zip"
    with zipfile.ZipFile(inner_zip, "w") as zf:
        zf.write(staging / mem_name, arcname=mem_name)
    outer_7z = scan / f"{uuid.uuid4().hex[:8]}.7z"
    r = subprocess.run([_SEVENZ, "a", "-y", str(outer_7z), inner_zip.name],
                       cwd=str(staging), capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr

    cases = onboard(str(scan), on_event=lambda e: None, ai=None,
                    probes=ContentProbes())

    assert len(cases) == 1
    c = cases[0]
    # Disk found at top level by FS probe (random name, no meaningful extension).
    assert c.disk_path is not None
    assert os.path.basename(c.disk_path) == disk_name
    # Memory recovered from the zip-in-7z by recursive extraction + content probe.
    assert c.memory_path is not None
    assert os.path.basename(c.memory_path) == mem_name
    # OS derived from the memory probe alone, dataset-agnostically.
    assert "NT 6.1" in c.os
    assert c.os_source == "memory"
    # Honest: we never claimed to mount the fabricated image.
    assert c.disk_mounted is False
    # Fully deterministic: the AI advisor never fired.
    assert c.ai_consultations == []


def test_memory_only_directory_makes_a_case(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFT_ONBOARD_IMAGE_FLOOR_MB", "0")
    scan = tmp_path / f"memonly_{uuid.uuid4().hex[:8]}"
    scan.mkdir()
    mem_name = f"{uuid.uuid4().hex[:10]}.raw"
    (scan / mem_name).write_bytes(b"MEMDUMP-X\x00" + b"\x00" * 4096)
    cases = onboard(str(scan), on_event=lambda e: None, ai=None,
                    probes=ContentProbes())
    assert len(cases) == 1
    assert os.path.basename(cases[0].memory_path) == mem_name
    assert cases[0].disk_path is None        # memory-only is supported
