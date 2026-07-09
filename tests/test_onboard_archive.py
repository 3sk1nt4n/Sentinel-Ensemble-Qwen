"""Archive coverage matrix + multi-case + banner-guidance rendering (synthetic).

Builds one tiny archive of EACH supported type wrapping a 1 KB-ish dummy
"image" and asserts archive.extract_all recovers the dummy for every type.
Rows whose CREATION tool is absent are SKIPPED (honest), not failed.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import shutil
import subprocess
import tarfile
import uuid
import zipfile

import pytest

from sift_sentinel.onboard import archive, presenter
from sift_sentinel.onboard.engine import Phase, PhaseEvent, Probes, Status, onboard

_SEVENZ = shutil.which("7z") or shutil.which("7za")
_RAR = shutil.which("rar")


def _dummy(tmp):
    """Incompressible 64 KB dummy 'image' (so split archives make >1 volume)."""
    data = os.urandom(64 * 1024)
    src = tmp / "img.raw"
    src.write_bytes(data)
    return src, data


# ── builders: return archive path, or None to SKIP (creation tool absent) ──
def _b_zip(tmp, src):
    out = tmp / "a.zip"
    with zipfile.ZipFile(out, "w") as z:
        z.write(src, "img.raw")
    return out


def _b_7z(tmp, src):
    if not _SEVENZ:
        return None
    out = tmp / "a.7z"
    subprocess.run([_SEVENZ, "a", "-y", str(out), src.name],
                   cwd=str(tmp), capture_output=True)
    return out if out.exists() else None


def _b_gzip(tmp, src):
    out = tmp / "blob.gz"
    with gzip.open(out, "wb") as f:
        f.write(src.read_bytes())
    return out


def _b_bz2(tmp, src):
    out = tmp / "blob.bz2"
    with bz2.open(out, "wb") as f:
        f.write(src.read_bytes())
    return out


def _b_xz(tmp, src):
    out = tmp / "blob.xz"
    with lzma.open(out, "wb") as f:
        f.write(src.read_bytes())
    return out


def _b_tar(tmp, src, mode="w", name="a.tar"):
    out = tmp / name
    with tarfile.open(out, mode) as t:
        t.add(src, arcname="img.raw")
    return out


def _b_targz(tmp, src):
    return _b_tar(tmp, src, "w:gz", "a.tar.gz")


def _b_tarbz2(tmp, src):
    return _b_tar(tmp, src, "w:bz2", "a.tar.bz2")


def _b_tarxz(tmp, src):
    return _b_tar(tmp, src, "w:xz", "a.tar.xz")


def _b_rar(tmp, src):
    if not _RAR:
        return None
    out = tmp / "a.rar"
    subprocess.run([_RAR, "a", "-y", out.name, src.name],
                   cwd=str(tmp), capture_output=True)
    return out if out.exists() else None


def _b_split(tmp, src):
    if not _SEVENZ:
        return None
    subprocess.run([_SEVENZ, "a", "-y", "-v32k", "a.7z", src.name],
                   cwd=str(tmp), capture_output=True)
    first = tmp / "a.7z.001"
    return first if first.exists() else None


_BUILDERS = {
    "zip": _b_zip, "7z": _b_7z, "gzip": _b_gzip, "bzip2": _b_bz2, "xz": _b_xz,
    "tar": _b_tar, "tar.gz": _b_targz, "tar.bz2": _b_tarbz2, "tar.xz": _b_tarxz,
    "rar": _b_rar, "split.001": _b_split,
}


@pytest.mark.parametrize("fmt", list(_BUILDERS))
def test_extract_all_recovers_dummy_for_every_format(tmp_path, fmt):
    src, data = _dummy(tmp_path)
    arc = _BUILDERS[fmt](tmp_path, src)
    if arc is None:
        pytest.skip(f"{fmt}: creation tool not installed")
    leaves = archive.extract_all(str(arc))
    recovered = [p for p in leaves if _read(p) == data]
    assert recovered, f"{fmt}: extract_all did not recover the dummy (leaves={leaves})"


def _read(p):
    try:
        with open(p, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def test_zero_block_raw_not_detected_as_tar(tmp_path):
    # A leading zero block reads as an empty tar to tarfile.is_tarfile() - which
    # previously caused a memory image to be "extracted" and destroyed. It must
    # be left as a leaf now.
    import tarfile as _tf
    p = tmp_path / "mem.raw"
    p.write_bytes(b"\x00" * 4096)
    assert _tf.is_tarfile(str(p)) is True          # the trap that fooled us
    assert archive.detect_archive(str(p)) is None  # ...but we don't fall for it
    assert archive.extract_all(str(p)) == [str(p)]  # kept intact


# ── multi-case: 2 memory + 2 disk -> 2 cases ───────────────────────────────
class MultiProbes(Probes):
    def discover(self, p):
        # Host-correlated names: each memory image has a same-host disk. Pairing
        # is by SHARED HOST TOKEN (hosta/hostb), not by sorted index position.
        return ["/syn/hosta-memory.img", "/syn/hostb-memory.img",
                "/syn/hosta-cdrive.e01", "/syn/hostb-cdrive.e01"]

    def archive_kind(self, p):
        return None

    def has_filesystem(self, p):
        return p.endswith(".e01")

    def fs_facts(self, p):
        return {"fstype": "NTFS", "volume": "", "version": ""}

    def memory_info(self, p):
        return ({"NtMajorVersion": "10", "NtMinorVersion": "0"}
                if p.endswith(".img") else None)

    def mount(self, disk, method, mp):
        return (True, "") if method == "raw@0" else (False, "x")

    def health(self, mem):
        return True, [], {}

    def cleanup(self):
        pass


def test_two_memory_two_disk_reports_two_cases():
    events = []
    cases = onboard("/syn/case_dir", on_event=events.append, ai=None,
                    probes=MultiProbes())
    assert len(cases) == 2
    multi = [e for e in events
             if e.phase == Phase.DISCOVER and e.data.get("multi_case")]
    assert multi and multi[0].data["memory"] == 2 and multi[0].data["disk"] == 2
    # Each case paired one memory with one disk.
    assert all(c.memory_path and c.disk_path for c in cases)


# ── banner guidance + multi-case notice render in plain (non-TTY) mode ─────
def test_guidance_renders_plain_non_tty():
    g = presenter.guidance(color=False)
    assert "\x1b[" not in g
    assert "one folder" in g.lower() and "one case" in g.lower()


def test_multi_case_notice_renders_plain():
    buf = io.StringIO()
    presenter.render_event(
        PhaseEvent(Phase.DISCOVER, Status.WARN, "multiple cases detected",
                   {"multi_case": True, "memory": 2, "disk": 2}),
        color=False, file=buf)
    out = buf.getvalue()
    assert "\x1b[" not in out
    assert "more than one case" in out
    assert "2 memory" in out and "2 disks" in out
