"""Human label for the evidence sample shown in the summary banners.

The label is the COMMON NAME of the sample pair -- the shared stem of the memory + disk
file basenames, trimmed at the role token (``...-memory.img`` / ``...-cdrive.E01``) --
NOT the parent folder (which is a generic bucket like ``evidence/all-cases``). It also
carries each artefact's on-disk size. Universal / dataset-agnostic: derived from the
file names + sizes the run was given, no case literal.

  win7-64-host01-memory.img + win7-64-host01-cdrive.E01
      -> "win7-64-host01  (memory 3.4 GB + disk 16 GB)"
"""
from __future__ import annotations

import os
import re

_EXT_RE = re.compile(r"\.(img|raw|mem|dmp|dump|e01|ex01|s01|aff4|vmem|bin|001)$", re.IGNORECASE)
# A trailing role token a sample pair differs by: memory/disk/drive/image/dump/raw/...
_ROLE_RE = re.compile(
    r"[-_. ]*(memory|mem|ram|cdrive|c[-_ ]?drive|harddisk|hdd|disk|drive|image|dump|raw|vmem|e01)\d*$",
    re.IGNORECASE)
_GENERIC_DIRS = {"evidence", "all-cases", "cases", "mnt", "media", "tmp", "case", "samples"}


def _stem(basename: str) -> str:
    s = _EXT_RE.sub("", basename or "")
    s = _ROLE_RE.sub("", s)
    return s.strip("-_. ")


def sample_name(image_path=None, disk_path=None, disk_mount=None) -> str:
    """The sample's common name from the file basenames -- never the parent folder.
    Falls back to the file's own directory (minus a '-case' suffix) only when no usable
    name can be derived, and never to a generic bucket folder."""
    bns = [os.path.basename(str(p).rstrip("/")) for p in (image_path, disk_path) if p]
    if len(bns) >= 2:
        cp = os.path.commonprefix(bns)
        name = _stem(cp) if len(cp) >= 3 else _stem(bns[0])
        if name:
            return name
    if bns:
        name = _stem(bns[0])
        if name:
            return name
    for p in (image_path, disk_path, disk_mount):
        if not p:
            continue
        parts = [x for x in str(p).replace("\\", "/").split("/") if x]
        if len(parts) >= 2:
            d = re.sub(r"[-_ ]?case$", "", parts[-2], flags=re.IGNORECASE).strip("-_. ")
            if d and d.lower() not in _GENERIC_DIRS:
                return d
    return ""


def human_size(n) -> str:
    """A compact size like '3.4 GB' / '16 GB' / '720 MB'. '' when unknown/zero."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    if units[i] in ("B", "KB"):
        s = "%d" % round(n)
    else:
        s = ("%.1f" % n).rstrip("0").rstrip(".")
    return "%s %s" % (s, units[i])


def _size_of(path) -> int:
    try:
        return os.path.getsize(str(path))
    except OSError:
        return 0


def sample_sources(image_path=None, disk_path=None, disk_mount=None) -> list:
    """['memory 3.4 GB', 'disk 16 GB'] -- the size is omitted when a file can't be
    stat'd (e.g. a mount-only disk, or a synthetic path under test)."""
    out = []
    if image_path:
        sz = human_size(_size_of(image_path))
        out.append("memory %s" % sz if sz else "memory")
    if disk_path or disk_mount:
        sz = human_size(_size_of(disk_path)) if disk_path else ""
        out.append("disk %s" % sz if sz else "disk")
    return out


def sample_label(summary=None, image_path=None, disk_path=None, disk_mount=None) -> str:
    """Full banner label: ``<name>  (memory 3.4 GB + disk 16 GB)``. An explicit
    ``summary['sample']`` wins over the derived name."""
    s = (summary or {}).get("sample") if isinstance(summary, dict) else None
    name = str(s) if s else sample_name(image_path, disk_path, disk_mount)
    srcs = sample_sources(image_path, disk_path, disk_mount)
    if name and srcs:
        return "%s  (%s)" % (name, " + ".join(srcs))
    return name or (" + ".join(srcs) if srcs else "unknown")


__all__ = ["sample_label", "sample_name", "sample_sources", "human_size"]
