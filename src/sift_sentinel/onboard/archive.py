"""File-type intelligence for onboarding.

Two jobs, both by content first / extension second:

  * Tell DOCUMENTS apart from evidence ARCHIVES. Office/OpenXML/ODF/PDF/EPUB
    files are end-user artifacts - they are ZIPs under the hood but must NEVER
    be exploded into their parts. ``is_document`` detects them by extension OR
    by the OpenXML ``[Content_Types].xml`` / ODF ``mimetype`` marker / ``%PDF``.

  * Universally extract TRUE containers (zip/7z/gzip/bzip2/xz/tar[.gz|.bz2|.xz]/
    rar and split multi-part .001…) by MAGIC bytes, preferring the ``7z`` CLI
    and falling back to the Python stdlib. ``extract_all`` recurses (zip→7z→raw)
    with a depth guard, and leaves documents and EWF segments intact.

EWF segments (.e01/.e02…) are NOT extracted here - they are handed to ewf as a
single image by the disk path.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from typing import Optional

# ── File-type sets ──────────────────────────────────────────────────────────
DOC_EXTENSIONS = {
    ".pptx", ".docx", ".xlsx", ".ppt", ".doc", ".xls", ".odt", ".ods",
    ".odp", ".pdf", ".epub", ".vsdx", ".one",
}
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".emf", ".wmf", ".bmp", ".tif", ".tiff",
    ".ico", ".svg",
}
TEXT_EXTENSIONS = {
    ".xml", ".html", ".htm", ".txt", ".json", ".csv", ".rels", ".md", ".log",
    ".ini", ".yaml", ".yml", ".thmx",
}
FONT_EXTENSIONS = {".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon"}
JUNK_EXTENSIONS = IMAGE_EXTENSIONS | TEXT_EXTENSIONS | FONT_EXTENSIONS

# Archive magic prefixes (hex at offset 0).
_ARCHIVE_MAGIC = [
    ("504b0304", "ZIP"), ("504b0506", "ZIP"), ("504b0708", "ZIP"),
    ("377abcaf271c", "7Z"),
    ("1f8b", "GZIP"),
    ("425a68", "BZIP2"),
    ("fd377a585a00", "XZ"),
    ("526172211a07", "RAR"),
]
_JUNK_MAGIC = ("89504e47", "ffd8ff", "47494638", "424d", "49492a00",
               "4d4d002a")  # png, jpg, gif, bmp, tiff(le/be)

# kind -> (cli tool, apt package) for honest "missing tool" messages.
TOOL_FOR = {
    "7Z": ("7z", "p7zip-full"), "RAR": ("7z", "p7zip-full"),
    "SPLIT": ("7z", "p7zip-full"),
}


class ArchiveError(Exception):
    """Base archive failure."""


class ArchiveToolMissing(ArchiveError):
    """A recognized container needs a CLI tool that is not installed."""

    def __init__(self, kind: str, tool: str, pkg: str) -> None:
        self.kind, self.tool, self.pkg = kind, tool, pkg
        super().__init__(f"{kind} needs `{tool}` - sudo apt install {pkg}")


def magic_hex(path: str, n: int = 16) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(n).hex()
    except OSError:
        return ""


def _have_7z() -> Optional[str]:
    return shutil.which("7z") or shutil.which("7za")


# ── Documents vs junk ─────────────────────────────────────────────────────
def _zip_has_doc_marker(path: str) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except Exception:
        return False
    return "[Content_Types].xml" in names or "mimetype" in names


def is_document(path: str) -> bool:
    """True for end-user documents that must be kept, never extracted."""
    if os.path.splitext(path)[1].lower() in DOC_EXTENSIONS:
        return True
    head = magic_hex(path, 4)
    if head.startswith("504b03"):          # a ZIP - but is it an OOXML/ODF doc?
        return _zip_has_doc_marker(path)
    if head.startswith("25504446"):        # %PDF
        return True
    return False


def is_junk(path: str) -> bool:
    """True for small non-evidence: images, text/markup, fonts."""
    if os.path.splitext(path)[1].lower() in JUNK_EXTENSIONS:
        return True
    m = magic_hex(path, 8)
    return any(m.startswith(p) for p in _JUNK_MAGIC)


# ── Archive detection ───────────────────────────────────────────────────────
def _is_split_first(path: str) -> bool:
    """True only for the FIRST PART of a real multi-part ARCHIVE.

    A bare ``.001`` is ambiguous: it is the first segment of either a split
    ARCHIVE (zip/7z/rar) or a split RAW IMAGE (an FTK/dd memory or disk dump).
    Only the former is extractable -- treating a raw-image ``.001`` as an archive
    sends a memory/disk image into the extractor, where it is silently lost and
    the case runs without it. So a bare ``.001`` is a split archive ONLY when its
    offset-0 magic is a known archive magic; explicit ``.zip.001`` / ``.7z.001`` /
    ``.rar.001`` naming stays definitive. Magic-first, universal, no case data.
    Kill-switch SIFT_SPLIT_REQUIRE_MAGIC=0 restores the legacy extension-only
    behavior."""
    low = path.lower()
    if low.endswith((".zip.001", ".7z.001", ".rar.001")):
        return True
    if not low.endswith(".001"):
        return False
    if os.environ.get("SIFT_SPLIT_REQUIRE_MAGIC", "1") == "0":
        return True                         # legacy: any .001 is a split archive
    m = magic_hex(path, 16)
    return any(m.startswith(p) for p, _kind in _ARCHIVE_MAGIC)


def is_ewf(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".e01", ".ex01", ".s01", ".l01"):
        return True
    return magic_hex(path, 3) in ("455646", "4c5646")  # "EVF" / "LVF"


def _looks_like_tar(path: str) -> bool:
    """Uncompressed tar has no offset-0 magic. Detect by the POSIX ``ustar``
    magic at offset 257 (or a .tar name). We deliberately do NOT use
    tarfile.is_tarfile() as a blanket fallback - it false-positives on large
    raw images (a leading zero block reads as an empty/short tar), which would
    catastrophically "extract" and destroy a memory image."""
    try:
        with open(path, "rb") as fh:
            fh.seek(257)
            if fh.read(5) == b"ustar":
                return True
    except OSError:
        return False
    return path.lower().endswith(".tar")


def detect_archive(path: str) -> Optional[str]:
    """Return an EXTRACTABLE archive type, or None.

    Documents and EWF segments return None (documents are kept as leaves; EWF
    is handed to ewf, not extracted).
    """
    if is_document(path) or is_ewf(path):
        return None
    if _is_split_first(path):
        return "SPLIT"
    m = magic_hex(path, 16)
    for prefix, kind in _ARCHIVE_MAGIC:
        if m.startswith(prefix):
            return kind
    if _looks_like_tar(path):
        return "TAR"
    return None


# ── Extraction ───────────────────────────────────────────────────────────────
def _list_files(root: str) -> list:
    out = []
    for base, _dirs, files in os.walk(root):
        out.extend(os.path.join(base, f) for f in files)
    return sorted(out)


def _tar_extractall(tf: tarfile.TarFile, dest: str) -> None:
    try:
        tf.extractall(dest, filter="data")     # py3.12 safe filter
    except TypeError:
        tf.extractall(dest)


def _try_tar(path: str, dest: str) -> bool:
    try:
        with tarfile.open(path) as tf:         # auto-detects gz/bz2/xz/plain
            _tar_extractall(tf, dest)
        return True
    except (tarfile.TarError, OSError, EOFError):
        return False


def _decompress_single(path: str, dest: str, opener) -> None:
    base = os.path.basename(path)
    for suf in (".gz", ".bz2", ".bzip2", ".xz", ".lzma"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)]
            break
    else:
        base = base + ".out"
    out = os.path.join(dest, base or "decompressed.out")
    with opener(path, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst)


def _seven_zip(path: str, dest: str) -> bool:
    tool = _have_7z()
    if not tool:
        return False
    r = subprocess.run([tool, "x", f"-o{dest}", "-y", path],
                       capture_output=True, text=True, timeout=1800)
    return r.returncode == 0


def _extract_one(path: str, kind: str, dest: str) -> list:
    """Extract ONE container level into dest. Raises ArchiveToolMissing."""
    os.makedirs(dest, exist_ok=True)
    if kind == "ZIP":
        with zipfile.ZipFile(path) as zf:
            zf.extractall(dest)
    elif kind == "TAR":
        if not _try_tar(path, dest):
            return []
    elif kind in ("GZIP", "BZIP2", "XZ"):
        opener = {"GZIP": gzip.open, "BZIP2": bz2.open, "XZ": lzma.open}[kind]
        if not _try_tar(path, dest):       # could be tar.gz / .tbz / .txz
            _decompress_single(path, dest, opener)
    elif kind in ("7Z", "RAR", "SPLIT"):
        if not _seven_zip(path, dest):
            if not _have_7z():
                tool, pkg = TOOL_FOR.get(kind, ("7z", "p7zip-full"))
                raise ArchiveToolMissing(kind, tool, pkg)
            return []                       # 7z present but couldn't open it
    else:
        return []
    return _list_files(dest)


def extract_all(path: str, dest_root: Optional[str] = None,
                _depth: int = 0, _max_depth: int = 8) -> list:
    """Recursively extract ``path`` to its non-archive leaves.

    Documents and EWF segments are returned as-is (never extracted). Non-archive
    files are returned as themselves. Raises ArchiveToolMissing when a container
    is recognized but its tool is absent.
    """
    if _depth >= _max_depth:
        return [path]
    if is_document(path):
        return [path]
    kind = detect_archive(path)
    if not kind:
        return [path]
    dest = tempfile.mkdtemp(prefix="sift-ex-", dir=dest_root)
    children = _extract_one(path, kind, dest)
    if not children:
        return [path]                       # opened nothing -> treat as leaf
    leaves: list = []
    for child in children:
        leaves.extend(extract_all(child, dest_root, _depth + 1, _max_depth))
    return sorted(leaves)
