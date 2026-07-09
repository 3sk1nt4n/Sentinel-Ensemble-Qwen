"""Step-Zero onboarding engine - emits PhaseEvents from REAL probes.

Design contract (ZEROFAKE-UI):
  * The engine performs the deterministic onboarding (discover -> extract ->
    classify -> os-detect -> mount-ladder -> health -> manifest) and calls
    ``on_event`` AFTER each real probe returns, carrying the actual probe
    result in ``PhaseEvent.data``. It never narrates work that did not occur.
  * All I/O lives behind the ``Probes`` seam. ``RealProbes`` shells out to the
    court-vetted tools (xxd/fsstat/vol/ntfs-3g/dmsetup); tests inject a fake.
    This keeps the engine fully usable headless (no TTY, no sudo) for CI.
  * The presenter only renders the events; it is never imported here.

Lesson baked in from a prior live onboarding probe (see prior onboarding run):
``fsstat``'s ``Version:`` field is the NTFS *format generation* (NTFS 3.1 is
labelled "Windows XP" on every modern Windows), NOT the operating system. So
OS detection is taken from memory ``windows.info`` and the disk version string
is never treated as an OS source.
"""
from __future__ import annotations

import errno
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import archive


# ── Vocabulary ─────────────────────────────────────────────────────────────
class Phase:
    DISCOVER = "DISCOVER"
    EXTRACT = "EXTRACT"
    CLASSIFY = "CLASSIFY"
    OS_DETECT = "OS_DETECT"
    MOUNT = "MOUNT"
    HEALTH = "HEALTH"
    MANIFEST = "MANIFEST"
    READY = "READY"
    ERROR = "ERROR"
    ADVISE = "ADVISE"          # optional AI escape hatch (verify-before-act)
    ALL = frozenset({
        DISCOVER, EXTRACT, CLASSIFY, OS_DETECT, MOUNT,
        HEALTH, MANIFEST, READY, ERROR, ADVISE,
    })


class Status:
    START = "START"
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    SUBSTEP = "SUBSTEP"
    ALL = frozenset({START, OK, WARN, FAIL, SUBSTEP})


# ── Typed errors ────────────────────────────────────────────────────────────
class OnboardError(Exception):
    """Unrecoverable onboarding failure (no usable evidence)."""


class InvalidPhaseEvent(ValueError):
    """A PhaseEvent was constructed with an unknown phase or status."""


# ── Structured progress event ───────────────────────────────────────────────
@dataclass
class PhaseEvent:
    phase: str
    status: str
    detail: str = ""
    data: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.phase not in Phase.ALL:
            raise InvalidPhaseEvent(f"unknown phase {self.phase!r}")
        if self.status not in Status.ALL:
            raise InvalidPhaseEvent(f"unknown status {self.status!r}")
        if self.data is None:
            self.data = {}


# ── The verified case summary ────────────────────────────────────────────────
@dataclass
class CaseManifest:
    case_id: str
    os: str
    os_source: str                       # "memory" | "disk" | "disk+memory" | "none"
    memory_path: Optional[str]
    memory_health: Optional[str]         # "HEALTHY" | "DEGRADED" | None
    memory_health_facts: dict
    disk_path: Optional[str]
    disk_mounted: bool
    mount_method: Optional[str]          # "raw@0" | "dmpad" | None
    mount_path: Optional[str]
    reference_docs: list
    # Both OS signals + honest agreement (see detect_os). Defaulted so existing
    # construct sites stay valid; populated by onboard().
    os_profile: dict = field(default_factory=dict)
    # Audit trail of any AI-advisor consultations. EMPTY when the run was fully
    # deterministic - that emptiness is the proof the AI was off the critical path.
    ai_consultations: list = field(default_factory=list)
    # Reference documents (Office/PDF/etc.) found alongside the evidence: kept
    # for the analyst, never analyzed.
    documents: list = field(default_factory=list)


# Mount strategy ladder, tried in order until one yields a Windows volume:
#   raw@0        -- NTFS at offset 0 (a bare volume image)
#   ntfs_offsets -- NTFS inside a partition: read mmls, try each partition start
#                   (the usual reason a full-disk E01 won't mount at offset 0)
#   dmpad        -- device-mapper zero-pad for a truncated tail
MOUNT_LADDER = ("raw@0", "ntfs_offsets", "dmpad")

# Friendly OS labels for NT major.minor (honest: NT version always appended).
_NT_LABELS = {
    (10, 0): "Windows 10 / Server 2016+",
    (6, 3): "Windows 8.1 / Server 2012 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 0): "Windows Vista / Server 2008",
    (5, 2): "Windows XP x64 / Server 2003",
    (5, 1): "Windows XP",
}

_ARCHIVE_MAGIC = {
    "504b0304": "ZIP",
    "377abcaf271c": "7Z",
    "1f8b": "GZIP",
}

# Containers we recognize by magic but cannot open deterministically - these
# are the only files that trigger the EXTRACT AI-consult point.
_CONTAINER_MAGIC = {
    "526172211a07": "RAR",        # Rar!\x1a\x07
    "7668647866696c65": "VHDX",   # "vhdxfile"
}


# ── I/O seam ─────────────────────────────────────────────────────────────────
class Probes:
    """Interface the engine drives. Subclass for real I/O or for tests."""

    def discover(self, path: str) -> list:
        raise NotImplementedError

    def archive_kind(self, path: str) -> Optional[str]:
        raise NotImplementedError

    def extract(self, path: str) -> list:
        raise NotImplementedError

    def has_filesystem(self, path: str) -> bool:
        raise NotImplementedError

    def fs_facts(self, path: str) -> dict:
        raise NotImplementedError

    def memory_info(self, path: str) -> Optional[dict]:
        raise NotImplementedError

    def mount(self, disk: str, method: str, mountpoint: str) -> tuple:
        raise NotImplementedError

    def health(self, mem: str) -> tuple:
        raise NotImplementedError

    def cleanup(self) -> None:
        return None

    # -- escalation probes (used only at AI-consult points) ------------------
    # Safe no-op defaults: an unimplemented escalation can NEVER verify an AI
    # suggestion, so it fails closed. RealProbes overrides with real tooling.
    def magic(self, path: str) -> str:
        return ""

    def extract_as(self, path: str, method: str) -> list:
        return []

    def deep_classify(self, path: str, role: str):
        return None

    def deep_os(self, path: str, family: str):
        return None

    def disk_os(self, mount_path) -> Optional[str]:
        # Real disk OS read FRESH from the mounted SOFTWARE hive. Default None
        # (-> "undetermined"); RealProbes overrides. NEVER a hardcoded value.
        return None

    def memory_signature(self, path: str) -> Optional[str]:
        # Fast, symbol-free CONTENT probe: a memory-format tag
        # ('crashdump'/'lime') when offset-0 magic proves a memory capture, else
        # None. Default None so unimplemented fakes fail closed; RealProbes reads
        # the bytes. This is the spec's "probe them, not by name" for magic'd
        # formats -- no vol3, no timeout, zero FP on disk images.
        return None


class RealProbes(Probes):
    """Court-vetted CLI tooling. Read-only; tracks devices for cleanup.

    Not exercised by the unit suite (needs sudo/real evidence); it encodes the
    exact ladder proven on a live image in a prior onboarding run.
    """

    def __init__(self) -> None:
        self._tmpdirs: list[str] = []
        self._ex_root: Optional[str] = None  # shared extraction root
        self._ewf: dict[str, str] = {}     # disk path -> ewf1 target
        self._mounts: list[str] = []       # mountpoints to umount
        self._dm: list[str] = []           # dm device names
        self._loops: list[str] = []        # loop devices

    # -- discovery / archives ------------------------------------------------
    def discover(self, path: str) -> list:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            return []
        if os.path.isfile(path):
            return [path]
        # Directory: recurse so nested evidence is found regardless of layout.
        found: list[str] = []
        for root, _dirs, files in os.walk(path):
            for n in sorted(files):
                if not n.startswith("."):
                    found.append(os.path.join(root, n))
        return found

    def _magic(self, path: str) -> str:
        try:
            with open(path, "rb") as fh:
                return fh.read(8).hex()
        except OSError:
            return ""

    def archive_kind(self, path: str) -> Optional[str]:
        # Documents/EWF return None here (kept as leaves); only true extractable
        # containers get a kind. Universal, magic-byte based.
        return archive.detect_archive(path)

    def extract(self, path: str) -> list:
        if self._ex_root is None:
            self._ex_root = tempfile.mkdtemp(prefix="sift-onboard-ex-")
            self._tmpdirs.append(self._ex_root)
        # Resource guardrail: reclaim STALE scratch from finished prior runs, then a
        # free-space preflight. A multi-GB evidence FOLDER stat's as a ~4 KB dir entry,
        # so size its real contents (dir_size) -- otherwise the check passes and the
        # 44 GB copy fills the disk before dying. If still short after pruning, raise
        # ENOSPC UP FRONT (onboard() narrates it) rather than half-filling the disk.
        try:
            from sift_sentinel.onboard.resource_guard import dir_size as _rg_size
            from sift_sentinel.onboard.resource_guard import prune_stale_scratch as _rg_prune
            _rg_prune(keep_active={self._ex_root})
            need = _rg_size(path)                      # true size of file OR folder
            free = shutil.disk_usage(self._ex_root).free
            if need and free < need + (512 << 20):     # contents size + 512 MB margin
                raise OSError(errno.ENOSPC,
                              "insufficient free space to extract this evidence "
                              "(need ~%d MB, have %d MB; clear old /tmp/sift-* dirs)"
                              % (need >> 20, free >> 20))
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ENOSPC:
                raise
            # a sizing error (e.g. stat failed) -> fall through and let extract try
        # extract_all recurses to the non-archive leaves; may raise
        # archive.ArchiveToolMissing, which onboard() narrates honestly.
        return archive.extract_all(path, dest_root=self._ex_root)

    # -- classification ------------------------------------------------------
    def _ewf_mount(self, path: str) -> Optional[str]:
        if path in self._ewf:
            return self._ewf[path]
        if not self._magic(path).startswith(("4576", "4556")):
            return None  # not EWF/E01
        # Disk-full / permission failures here must NOT crash onboarding -- fall back
        # to the raw path (fsstat can still try at offset 0). _fsstat_target ORs to it.
        try:
            mp = tempfile.mkdtemp(prefix="sift-ewf-")
        except OSError:
            return None
        self._tmpdirs.append(mp)
        try:
            subprocess.run(["sudo", "ewfmount", "-X", "allow_other", path, mp],
                           capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return None
        target = os.path.join(mp, "ewf1")
        if os.path.exists(target):
            self._ewf[path] = target
            self._mounts.append(mp)  # ewfmount uses fuse; umount to release
            return target
        return None

    def _fsstat_target(self, path: str) -> str:
        return self._ewf_mount(path) or path

    def has_filesystem(self, path: str) -> bool:
        target = self._fsstat_target(path)
        r = subprocess.run(["sudo", "fsstat", target],
                           capture_output=True, text=True, timeout=60)
        if "File System Type" in (r.stdout + r.stderr):
            return True
        # fsstat at offset 0 MISSES a full-disk image: a partition table puts the
        # filesystem at a non-zero offset (e.g. NTFS at sector 2048), so fsstat
        # reports "Cannot determine file system type". Escalate to mmls -- a
        # partition table naming an NTFS/FAT/exFAT volume IS a disk; the
        # ntfs_offsets mount ladder then mounts at the real partition offset.
        # (A bare single-partition image has its FS at offset 0 and already
        # passed above; this rescues the common full-disk .E01/.dd shape.)
        # Dataset-agnostic: partition-table structure only, no case specifics.
        try:
            m = subprocess.run(["sudo", "mmls", target],
                               capture_output=True, text=True, timeout=60)
            out = m.stdout + m.stderr
            if any(fs in out for fs in ("NTFS", "exFAT", "FAT", "Linux (0x83)", "Basic data")):
                return True
        except (OSError, subprocess.SubprocessError):
            pass
        return False

    def fs_facts(self, path: str) -> dict:
        target = self._fsstat_target(path)
        r = subprocess.run(["sudo", "fsstat", target],
                           capture_output=True, text=True, timeout=60)
        facts = {"fstype": "", "volume": "", "version": ""}
        for line in (r.stdout + r.stderr).splitlines():
            low = line.lower()
            if "file system type" in low:
                facts["fstype"] = line.split(":", 1)[-1].strip()
            elif "volume name" in low:
                facts["volume"] = line.split(":", 1)[-1].strip()
            elif "version" in low and ":" in line:
                facts["version"] = line.split(":", 1)[-1].strip()
        return facts

    def memory_info(self, path: str) -> Optional[dict]:
        from sift_sentinel.config import VOL_CMD
        try:
            r = subprocess.run([*VOL_CMD, "-f", path, "windows.info"],
                               capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            # Cold multi-GB image / old-OS symbols can exceed the probe budget.
            # Never crash the scan -- the name-shape rescue below still
            # classifies role-marked memory files; the pipeline's own profile
            # check (longer budget, symbol cache) resolves the profile later.
            return None
        info: dict[str, str] = {}
        for line in (r.stdout + r.stderr).splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                info[parts[0].strip()] = parts[1].strip()
        has_nt = ("NtMajorVersion" in info) or ("Major/Minor" in info)
        return info if has_nt else None

    # -- mount ladder --------------------------------------------------------
    def mount(self, disk: str, method: str, mountpoint: str) -> tuple:
        target = self._fsstat_target(disk)
        os.makedirs(mountpoint, exist_ok=True)
        opts = "ro,force,streams_interface=windows,show_sys_files"
        if method == "raw@0":
            subprocess.run(["sudo", "mount", "-t", "ntfs-3g", "-o", opts,
                            target, mountpoint],
                           capture_output=True, text=True, timeout=120)
            if os.path.isdir(os.path.join(mountpoint, "Windows")):
                self._mounts.append(mountpoint)
                return True, ""
            subprocess.run(["sudo", "umount", mountpoint],
                           capture_output=True, text=True)
            return False, "no NTFS volume at offset 0"
        if method == "ntfs_offsets":
            # NTFS volume INSIDE a partition table: read mmls, try mounting at
            # each partition's byte offset. This is the usual reason a full-disk
            # E01 won't mount at offset 0 (the volume starts at sector 2048 etc.).
            r = subprocess.run(["sudo", "mmls", target],
                               capture_output=True, text=True, timeout=60)
            offsets: list[int] = []
            for line in r.stdout.splitlines():
                m = re.match(r"\s*\d+:\s+\S+\s+(\d+)\s+\d+\s+\d+\s+(.*)$", line)
                if not m:
                    continue
                start, desc = int(m.group(1)), m.group(2).lower()
                if start > 0 and ("ntfs" in desc or "basic data" in desc
                                  or "0x07" in desc or "07 " in desc):
                    offsets.append(start * 512)
            for off in offsets:
                subprocess.run(["sudo", "mount", "-t", "ntfs-3g", "-o",
                                f"{opts},offset={off}", target, mountpoint],
                               capture_output=True, text=True, timeout=120)
                if os.path.isdir(os.path.join(mountpoint, "Windows")):
                    self._mounts.append(mountpoint)
                    return True, ""
                subprocess.run(["sudo", "umount", mountpoint],
                               capture_output=True, text=True)
            return False, "no NTFS volume at any partition offset"
        if method == "dmpad":
            try:
                sz = int(subprocess.run(["sudo", "blockdev", "--getsize64",
                                         target], capture_output=True,
                                        text=True, timeout=30).stdout or
                         os.path.getsize(target))
            except (ValueError, OSError):
                return False, "cannot size device"
            sectors = sz // 512
            loop = subprocess.run(["sudo", "losetup", "-r", "-f", "--show",
                                   target], capture_output=True,
                                  text=True, timeout=30).stdout.strip()
            if not loop:
                return False, "losetup failed"
            self._loops.append(loop)
            dm = f"sift_onboard_{os.path.basename(mountpoint)}"
            table = (f"0 {sectors} linear {loop} 0\n"
                     f"{sectors} 65536 zero\n")
            subprocess.run(["sudo", "dmsetup", "create", dm],
                           input=table, capture_output=True, text=True)
            self._dm.append(dm)
            subprocess.run(["sudo", "mount", "-t", "ntfs-3g", "-o", opts,
                            f"/dev/mapper/{dm}", mountpoint],
                           capture_output=True, text=True, timeout=120)
            if os.path.isdir(os.path.join(mountpoint, "Windows")):
                self._mounts.append(mountpoint)
                return True, ""
            return False, "dm-zero-pad mount failed"
        return False, f"unknown method {method}"

    # -- health --------------------------------------------------------------
    def health(self, mem: str) -> tuple:
        # Onboarding pre-gate BEFORE trusting the fail-open health function.
        if not mem or not os.path.exists(mem) or os.path.getsize(mem) < (1 << 20):
            return False, ["missing_or_empty"], {}
        from sift_sentinel.coordinator import check_profile_health
        return check_profile_health(mem)

    # -- escalation probes ---------------------------------------------------
    def magic(self, path: str) -> str:
        return self._magic(path)

    def extract_as(self, path: str, method: str) -> list:
        if method in ("not_an_archive", "vhdx_is_disk"):
            return [path]  # hand it downstream as a raw candidate
        if method == "join_001_segments":
            base = path[:-4] if path.lower().endswith(".001") else path
            segs, i = [], 1
            while os.path.exists(f"{base}.{i:03d}"):
                segs.append(f"{base}.{i:03d}")
                i += 1
            if len(segs) < 2:
                return []
            dest = tempfile.mkdtemp(prefix="sift-join-")
            self._tmpdirs.append(dest)
            out = os.path.join(dest, os.path.basename(base) + ".joined")
            try:
                with open(out, "wb") as w:
                    for seg in segs:
                        with open(seg, "rb") as r:
                            shutil.copyfileobj(r, w)
                return [out]
            except OSError:
                return []
        if method == "split_rar":
            dest = tempfile.mkdtemp(prefix="sift-rar-")
            self._tmpdirs.append(dest)
            for tool in (["unrar", "x", "-y", path, dest],
                         ["7z", "x", f"-o{dest}", "-y", path]):
                if subprocess.run(tool, capture_output=True, text=True,
                                  timeout=600).returncode == 0:
                    break
            kids = []
            for root, _d, files in os.walk(dest):
                kids.extend(os.path.join(root, f) for f in files)
            return sorted(kids)
        return []

    def deep_classify(self, path: str, role: str):
        if role == "DISK":  # mmls escalates past an offset-0 fsstat miss
            target = self._fsstat_target(path)
            r = subprocess.run(["sudo", "mmls", target],
                               capture_output=True, text=True, timeout=60)
            if "Slot" in r.stdout or re.search(r"\b\d{10}\b", r.stdout):
                return ("DISK", None)
            return None
        if role == "MEMORY":
            info = self.memory_info(path)
            return ("MEMORY", info) if info else None
        return None

    def deep_os(self, path: str, family: str):
        # Honest stub: confirming a disk OS family needs a SOFTWARE-hive read,
        # which is not wired. Return None rather than echo an unverified guess.
        return None

    def memory_signature(self, path: str) -> Optional[str]:
        """Symbol-free content probe: a Windows crash dump or a LiME capture is
        provable from its offset-0 magic alone -- no vol3, no 120s timeout, and
        zero FP on disk images (which carry a boot sector / partition table at
        offset 0, never these magics)."""
        try:
            with open(path, "rb") as fh:
                head = fh.read(8)
        except OSError:
            return None
        if head[:8] in (b"PAGEDUMP", b"PAGEDU64"):   # Windows crash dump (x86/x64)
            return "crashdump"
        if head[:4] == b"EMiL":                       # LiME header magic 0x4C694D45 (LE)
            return "lime"
        return None

    @staticmethod
    def _parse_software(hive_path: str) -> Optional[str]:
        try:
            from Registry import Registry
            reg = Registry.Registry(hive_path)
            key = reg.open(r"Microsoft\Windows NT\CurrentVersion")
            vals = {v.name(): v.value() for v in key.values()}
        except Exception:
            return None
        product = vals.get("ProductName")
        if not product:
            return None
        maj = vals.get("CurrentMajorVersionNumber")
        if maj is not None:                    # Win10+ split version fields
            ver = f"{maj}.{vals.get('CurrentMinorVersionNumber') or 0}"
        else:
            ver = str(vals.get("CurrentVersion") or "").strip()
        return f"{product} (NT {ver})" if ver else str(product)

    def disk_os(self, mount_path) -> Optional[str]:
        """Real disk OS from THIS mount's SOFTWARE hive (ProductName + NT ver).
        Returns None (-> "undetermined") if unreadable. Never fsstat's NTFS
        'Version' label (which is "Windows XP" for every NTFS 3.1 volume)."""
        if not mount_path:
            return None
        hive = os.path.join(mount_path, "Windows", "System32", "config", "SOFTWARE")
        parsed = self._parse_software(hive)    # direct read (if mount readable)
        if parsed is not None:
            return parsed
        # Root-owned fuse mount: copy the hive out via sudo, then parse.
        tmp = tempfile.mkdtemp(prefix="sift-hive-")
        self._tmpdirs.append(tmp)
        dst = os.path.join(tmp, "SOFTWARE")
        r = subprocess.run(["sudo", "cp", hive, dst],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return None
        subprocess.run(["sudo", "chmod", "a+r", dst], capture_output=True, text=True)
        return self._parse_software(dst)

    # -- teardown ------------------------------------------------------------
    def cleanup(self) -> None:
        for mp in reversed(self._mounts):
            subprocess.run(["sudo", "umount", mp], capture_output=True, text=True)
        for dm in reversed(self._dm):
            subprocess.run(["sudo", "dmsetup", "remove", dm],
                           capture_output=True, text=True)
        for loop in reversed(self._loops):
            subprocess.run(["sudo", "losetup", "-d", loop],
                           capture_output=True, text=True)
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)
        self._mounts.clear()
        self._dm.clear()
        self._loops.clear()
        # Reset the EWF mount cache too: cleanup() just umounted the ewf fuse
        # mount, so a surviving disk->.../ewf1 entry would hand the NEXT onboard a
        # stale, unmounted target -> fsstat fails -> the disk is misclassified
        # "unrecognized" and the case finds nothing. This is the B=back /
        # A=onboard-another re-probe bug. The next onboard re-mounts ewf fresh.
        if hasattr(self, "_ewf"):
            self._ewf.clear()
        # Reset extraction tracking so the SAME engine can re-extract cleanly on the
        # next case (per-run cleanup in a multi-case session). Without this a stale
        # _ex_root points at the just-removed dir and the next extract fails.
        self._tmpdirs.clear()
        self._ex_root = None


# ── OS label helper ──────────────────────────────────────────────────────────
def _os_from_memory(info: dict) -> Optional[str]:
    maj = info.get("NtMajorVersion")
    minor = info.get("NtMinorVersion")
    if maj is None and "Major/Minor" in info:
        mm = info["Major/Minor"].split(".")
        maj, minor = (mm + ["0"])[0], (mm + ["0"])[1] if len(mm) > 1 else "0"
    if maj is None:
        return None
    try:
        key = (int(maj), int(minor if minor is not None else 0))
    except (TypeError, ValueError):
        return None
    label = _NT_LABELS.get(key, "Windows")
    return f"{label} (NT {key[0]}.{key[1]})"


def _nt_token(os_str: str) -> Optional[str]:
    """Extract a normalized 'nt X.Y' token if the string carries one."""
    m = re.search(r"nt\s*(\d+)\.(\d+)", os_str.lower())
    return f"nt {m.group(1)}.{m.group(2)}" if m else None


def _family_token(os_str: str) -> str:
    """Coarse Windows family token: 'windows 10', 'windows xp', etc."""
    head = os_str.lower().split("(")[0].split("/")[0].strip()
    parts = head.split()
    return " ".join(parts[:2]) if len(parts) >= 2 else head


def _same_family(a: str, b: str) -> bool:
    na, nb = _nt_token(a), _nt_token(b)
    if na and nb:
        return na == nb
    return _family_token(a) == _family_token(b)


def detect_os(memory_os: Optional[str], disk_os: Optional[str]) -> dict:
    """Combine memory- and disk-derived OS signals into an os_profile.

    Memory (vol3 ``windows.info``) is authoritative. The disk signal is a weak
    hint (``fsstat`` reports the NTFS *format generation* - "Windows XP" on
    every modern NTFS - not the OS) and is NEVER allowed to assert agreement it
    cannot support. ``agree`` is True only when BOTH signals exist and resolve
    to the same Windows family; on mismatch both sources are surfaced and
    ``agree`` is False (no "disk+memory agree" claim).
    """
    chosen = memory_os or disk_os
    agree = bool(memory_os and disk_os and _same_family(memory_os, disk_os))
    if agree:
        source = "disk+memory"
    elif memory_os:
        source = "memory"
    elif disk_os:
        source = "disk"
    else:
        source = "none"
    return {
        "os": chosen or "unknown",
        "memory": memory_os,
        "disk": disk_os,
        "source": source,
        "agree": agree,
    }


def _safe_size(path: str) -> Optional[int]:
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _tmp_free_bytes() -> Optional[int]:
    """Free bytes on the temp filesystem (where extraction + ewf/dm mounts live).
    None if it can't be read."""
    try:
        return shutil.disk_usage(tempfile.gettempdir()).free
    except OSError:
        return None


def _min_free_bytes() -> int:
    """Refuse to start onboarding with less than this much temp space free
    (default 1 GB; configurable via SIFT_ONBOARD_MIN_FREE_MB)."""
    try:
        mb = float(os.environ.get("SIFT_ONBOARD_MIN_FREE_MB", "1024"))
    except ValueError:
        mb = 1024.0
    return int(mb * (1 << 20))


def _image_floor_bytes() -> int:
    """Min size for a leaf to be worth disk-vs-memory probing. Configurable via
    SIFT_ONBOARD_IMAGE_FLOOR_MB (default 50 MB; set 0 to probe everything)."""
    try:
        mb = float(os.environ.get("SIFT_ONBOARD_IMAGE_FLOOR_MB", "50"))
    except ValueError:
        mb = 50.0
    return int(mb * 1024 * 1024)


def _too_small_to_probe(path: str) -> bool:
    """True only when the real on-disk size is below the floor. Unknown size
    (virtual/injected paths) is NOT filtered - the probes decide."""
    sz = _safe_size(path)
    return sz is not None and sz < _image_floor_bytes()


_STEM_EXTS = (".zip", ".7z", ".gz", ".bz2", ".xz", ".tar", ".rar", ".001",
              ".e01", ".ex01", ".raw", ".img", ".mem", ".dd", ".bin")


def _stem(name: str) -> str:
    """Name without a trailing image/archive extension, for de-dup matching."""
    base = name
    for ext in _STEM_EXTS:
        if base.lower().endswith(ext):
            return base[: -len(ext)]
    return base


def _case_id(path: str) -> str:
    base = os.path.basename(os.path.normpath(path)) or "case"
    for ext in (".zip", ".7z", ".gz", ".e01", ".raw", ".img", ".mem"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
    return base or "case"


# Known forensic-artifact files that are NOT raw memory/disk images: triage
# packages, timeline stores, bodyfiles, sqlite DBs, segmented-storage protos,
# packet/event captures. Recognized so they are KEPT as a quiet one-line note
# instead of being probed and flagged with a scary per-file ⚠ UNKNOWN.
_NON_IMAGE_ARTIFACT_RE = re.compile(
    r"(\.mans$|\.plaso$|[._]plaso|plaso_proto|\.body$|bodyfile$|"
    r"\.sqlite\d?$|\.db$|\.json$|\.csv$|\.evtx$|\.pcapng?$|\.vmsn$)",
    re.IGNORECASE,
)


def _is_non_image_artifact(name: str) -> bool:
    return bool(_NON_IMAGE_ARTIFACT_RE.search(os.path.basename(str(name))))


# Role markers stripped from a filename to expose the HOST identity. Compound
# disk markers (c-drive) come first so 'drive' alone never leaves a stray 'c'.
_ROLE_MARKERS = (
    "cdrive", "c-drive", "c_drive", "ddrive", "d-drive",
    "physmem", "memdump", "memimage", "memraw", "memory", "ram",
    "drive", "disk", "image", "dump", "mem", "raw",
)


def _host_token(name: str) -> str:
    """Normalized host identity from a filename: drop the image/archive
    extension, drop any role marker (memory/cdrive/...), keep only alphanumerics.

    So 'base-dc-memory.img' and 'base-dc-cdrive.E01' both yield 'basedc', and
    'host-01-mem.raw' / 'host01-cdrive.E01' both yield 'host01'. Universal: pairs
    a memory image to its disk by SHARED HOST, never by sorted list position."""
    base = os.path.basename(str(name)).lower()
    for ext in _STEM_EXTS:
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    for w in sorted(_ROLE_MARKERS, key=len, reverse=True):
        base = re.sub(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", "", base)
    return re.sub(r"[^a-z0-9]", "", base)


# Memory-role subset of _ROLE_MARKERS: a non-filesystem file whose NAME carries
# one of these (token-bounded) is overwhelmingly a memory image even when the
# vol3 probe fails/times out. OS-neutral role words -- never case names.
_MEM_ROLE_MARKERS = ("physmem", "memdump", "memimage", "memraw",
                     "memory", "ram", "mem")

# UNAMBIGUOUS memory-image extensions -- formats no disk image uses. A file that
# ends with one of these is a memory capture by FORMAT even when its name has no
# role word and the vol3 probe times out. (.raw/.img/.dd are SHARED with disk
# images, so they are deliberately EXCLUDED here -- those stay probe- and
# role-word-gated, never classified memory by extension alone.)
_MEM_EXTS = (".vmem", ".dmp", ".mem", ".lime")


def _memory_role_name_shape(name: str) -> bool:
    """Deterministic memory rescue used ONLY after fsstat said not-a-filesystem
    and vol3 found no profile. Matches an unambiguous memory EXTENSION or a memory
    role WORD in the name. Kill-switch: SIFT_MEMORY_NAME_SHAPE_RESCUE=0."""
    if os.environ.get("SIFT_MEMORY_NAME_SHAPE_RESCUE", "1") == "0":
        return False
    base = os.path.basename(str(name)).lower()
    if base.endswith(_MEM_EXTS):            # unambiguous memory format by extension
        return True
    for ext in _STEM_EXTS:
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return any(
        re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", base)
        for w in _MEM_ROLE_MARKERS
    )


def _dedupe_by_basename(items: list, key=lambda x: x) -> list:
    """Collapse entries that share a filename (case-insensitive), keeping the
    first. realpath-dedup already removes symlinks/aliases; this removes true
    COPIES of the same image living in different folders -- the cause of the
    identical CASE 17 == CASE 18 duplicate cards. Same basename == same evidence."""
    seen: set = set()
    out: list = []
    for it in items:
        b = os.path.basename(str(key(it))).lower()
        if b not in seen:
            seen.add(b)
            out.append(it)
    return out


def _pair_by_host(memories: list, disks: list) -> list:
    """Pair memory+disk into cases by SHARED HOST TOKEN (not by index).

    ``memories`` is a list of (path, info) tuples; ``disks`` a list of paths.
    Returns ordered (mem_tuple|None, disk_path|None) pairings: each host that has
    BOTH a memory and a disk becomes one paired case; memory-only and disk-only
    hosts become single-source cases. Order = first appearance, so output is
    stable and matches the order the analyst dropped files in."""
    mem_by: dict = {}
    for m in memories:
        mem_by.setdefault(_host_token(m[0]), []).append(m)
    disk_by: dict = {}
    for d in disks:
        disk_by.setdefault(_host_token(d), []).append(d)
    order: list = []
    seen: set = set()
    for src in (memories, disks):
        for it in src:
            t = _host_token(it[0] if isinstance(it, tuple) else it)
            if t not in seen:
                seen.add(t)
                order.append(t)
    _best = os.environ.get("SIFT_PAIR_BEST_MEMORY", "1").strip().lower() not in (
        "0", "false", "no", "off")
    pairings: list = []
    for t in order:
        ms = list(mem_by.get(t, []))
        ds = disk_by.get(t, [])
        if _best and len(ms) > 1:
            # A host with >1 memory candidate is usually one capture in two
            # forms (an archive + its extracted image). Rank by analysis
            # strength so the DISK pairs with the strongest, and DROP a
            # strictly-weaker duplicate (an unanalyzable archive of an image we
            # already have). Equally-strong memories are all kept -- they may be
            # distinct captures, never silently dropped.
            ms.sort(key=_memory_strength, reverse=True)
            top = _memory_strength(ms[0])
            ms = [m for m in ms if _memory_strength(m) == top
                  or not _is_archive_memory(m)]
        for i in range(max(len(ms), len(ds))):   # same host -> index is correct here
            pairings.append((ms[i] if i < len(ms) else None,
                             ds[i] if i < len(ds) else None))
    return pairings


def _is_archive_memory(m) -> bool:
    """True when a memory candidate is an ARCHIVE container (zip/7z/gz/...) rather
    than a directly-analyzable raw image -- extension SHAPE only, no name list."""
    p = (m[0] if isinstance(m, (tuple, list)) else str(m)).lower()
    return p.endswith((".zip", ".7z", ".gz", ".bz2", ".xz", ".rar", ".tar",
                       ".zip.001", ".7z.001"))


def _memory_strength(m) -> tuple:
    """Rank a (path, info) memory candidate for pairing: vol3-confirmed (non-empty
    info from windows.info) outranks a name-shape-only rescue, and a real image
    outranks an archive container. Higher tuple sorts first. Universal."""
    info = m[1] if isinstance(m, (tuple, list)) and len(m) > 1 else None
    return (1 if info else 0, 0 if _is_archive_memory(m) else 1)


# ── Orchestration ────────────────────────────────────────────────────────────
def _looks_like_unknown_container(magic_hex: str) -> bool:
    if not magic_hex:
        return False
    if any(magic_hex.startswith(p) for p in _ARCHIVE_MAGIC):
        return False  # already handled by the deterministic extractor
    return any(magic_hex.startswith(p) for p in _CONTAINER_MAGIC)


def consult_and_verify(ai, consultations, phase, question, evidence, choices,
                       verifier, on_event=None):
    """Off-critical-path AI escape hatch with verify-before-act.

    Returns the verifier's result ONLY when a real probe confirmed the AI's
    suggestion; otherwise None. Always records an audit entry in
    ``consultations`` (when the advisor was actually consulted). Never narrates
    success unless ``verifier`` returned non-None. Mutates no engine state.
    """
    try:
        if ai is None or not ai.available():
            return None
    except Exception:
        return None

    def _emit(status, detail, **data):
        if on_event is not None:
            on_event(PhaseEvent(Phase.ADVISE, status, detail, dict(data)))

    _emit(Status.START,
          "Hit something my probes don't recognize - asking the AI advisor…",
          phase=phase)
    try:
        s = ai.advise(question, evidence, choices)
    except Exception:
        s = {}
    if not isinstance(s, dict):
        s = {}
    sug = s.get("suggestion")
    record = {"phase": phase, "question": question, "suggestion": sug,
              "confidence": s.get("confidence"), "verified": False,
              "action_taken": None}

    if sug in (None, "", "insufficient_evidence"):
        consultations.append(record)
        _emit(Status.FAIL,
              "advisor returned no usable suggestion → marking UNSUPPORTED",
              suggestion=sug)
        return None

    _emit(Status.SUBSTEP, f"suggested: {sug} → verifying with a probe…",
          suggestion=sug)
    try:
        result = verifier(sug)
    except Exception:
        result = None
    if result is not None:
        record["verified"] = True
        record["action_taken"] = sug
        consultations.append(record)
        _emit(Status.OK, "verified, applying", suggestion=sug)
        return result
    consultations.append(record)
    _emit(Status.FAIL, "suggestion didn't verify → marking UNSUPPORTED",
          suggestion=sug)
    return None


def onboard(
    paths,
    on_event: Callable[[PhaseEvent], None],
    ai=None,
    probes: Optional[Probes] = None,
) -> list:
    """Run the deterministic onboarding pipeline, emitting PhaseEvents.

    ``paths`` may be a single path (file OR folder - folders are walked) or an
    explicit LIST of paths (file-by-file multi-add: each entry is discovered -
    files used directly, folders walked - then the union is classified/paired
    exactly as one set). Archives among the entries are still extracted and
    documents are still kept as references.

    Returns a list of verified CaseManifest objects. ``ai`` is the optional
    grounded advisor; it is consulted ONLY at deterministic-exhaustion points
    and every suggestion is verified by a real probe before it is applied
    (see consult_and_verify). When ai is None/unavailable the pipeline is
    fully deterministic and ``ai_consultations`` stays empty.
    """
    probes = probes or RealProbes()
    consultations: list = []

    def emit(phase, status, detail="", **data):
        on_event(PhaseEvent(phase, status, detail, dict(data)))

    entries = list(paths) if isinstance(paths, (list, tuple)) else [paths]
    root = entries[0] if entries else "case"
    emit(Phase.DISCOVER, Status.START, "Looking at what you gave me…", path=root)
    items: list[str] = []
    seen_items: set = set()
    for entry in entries:                     # each entry: file -> [file], dir -> walk
        for it in probes.discover(entry):
            # Collapse symlinks/aliases to ONE real file. A folder full of
            # `ln -s` aliases (or the same image reachable by two paths) must
            # not become N duplicate listings / N spurious cases.
            try:
                key = os.path.realpath(it)
            except OSError:
                key = it
            if key not in seen_items:
                seen_items.add(key)
                items.append(it)
    if not items:
        emit(Phase.ERROR, Status.FAIL,
             "I could not find anything usable at that path.", path=root)
        return []
    emit(Phase.DISCOVER, Status.OK,
         f"found {len(items)} item(s)", count=len(items), items=list(items))

    # Disk-space preflight: extraction + ewf/dm mounts all use the temp filesystem.
    # If it's nearly full, abort CLEANLY with guidance rather than crashing mid-probe
    # with an OSError (Errno 28). A full /tmp is the #1 cause of an ugly traceback.
    _free = _tmp_free_bytes()
    _need = _min_free_bytes()
    if _free is not None and _free < _need:
        emit(Phase.ERROR, Status.FAIL,
             f"Low disk space - only {_free // (1 << 20)} MB free in "
             f"{tempfile.gettempdir()} (need >= {_need // (1 << 20)} MB). I won't "
             "start and risk a crash. Free up space (clear old /tmp/sift-* dirs), or "
             "point me at ONE case folder instead of a big shared one, then retry.",
             free_mb=(_free // (1 << 20)), need_mb=(_need // (1 << 20)))
        return []

    # -- extraction (RECURSIVE; only narrated when an archive is opened) -----
    # Work a queue so an archive extracted from another archive (zip-in-7z) is
    # itself re-extracted. `seen` + a hard cap guard against loops / zip bombs.
    working: list[str] = []
    queue: list[str] = list(items)
    seen: set = set()
    # De-dup: stems of loose (non-archive, non-document) images already on disk.
    # An archive whose stem matches one is just its compressed twin - skip it
    # (avoids a needless multi-GB re-extraction and a duplicate case).
    loose_stems = {
        _stem(os.path.basename(it)) for it in items
        if probes.archive_kind(it) is None and not archive.is_document(it)
    }
    qi = 0
    while qi < len(queue) and len(seen) < 4096:
        item = queue[qi]
        qi += 1
        if item in seen:
            continue
        seen.add(item)
        kind = probes.archive_kind(item)
        if kind:
            name = os.path.basename(item)
            if _stem(name) in loose_stems:
                emit(Phase.EXTRACT, Status.SUBSTEP,
                     f"{name}: already present uncompressed - skipping extraction",
                     name=name, skipped_duplicate=True)
                continue
            emit(Phase.EXTRACT, Status.SUBSTEP,
                 f"{name} - {kind} → extracting…", name=name, type=kind)
            try:
                children = probes.extract(item)
            except archive.ArchiveToolMissing as exc:
                emit(Phase.EXTRACT, Status.WARN,
                     f"{name}: {exc.kind} archive detected but `{exc.tool}` "
                     f"isn't installed - run: sudo apt install {exc.pkg}",
                     name=name, tool=exc.tool, pkg=exc.pkg)
                working.append(item)
                continue
            except OSError as exc:
                # Disk full / permission / I/O error mid-extraction must NEVER
                # crash onboarding -- skip this archive and keep going on the
                # files already on disk (the loose images still get classified).
                if getattr(exc, "errno", None) == errno.ENOSPC:
                    emit(Phase.EXTRACT, Status.WARN,
                         f"{name}: ran out of disk space while extracting - "
                         "skipped. Free up space, or point me straight at the "
                         "already-extracted memory/disk images instead.",
                         name=name, error="no_space")
                else:
                    emit(Phase.EXTRACT, Status.WARN,
                         f"{name}: could not extract "
                         f"({exc.strerror or exc}) - skipped.",
                         name=name, error="oserror")
                continue
            except Exception as exc:        # corrupt/locked archive -> skip, never crash
                emit(Phase.EXTRACT, Status.WARN,
                     f"{name}: could not extract ({exc}) - skipped.",
                     name=name, error="extract_failed")
                continue
            for child in children:         # already recursed to leaves
                queue.append(child)
            emit(Phase.EXTRACT, Status.OK,
                 f"extracted {len(children)} item(s) from {name}",
                 name=name, count=len(children))
            continue
        # Not a known archive - maybe an unrecognized container (point 1).
        mg = probes.magic(item)
        rescued = None
        if _looks_like_unknown_container(mg):
            rescued = consult_and_verify(
                ai, consultations, "EXTRACT",
                "Unrecognized container; how should I open it?",
                {"magic_hex": mg, "name": os.path.basename(item),
                 "size": _safe_size(item)},
                ["split_rar", "vhdx_is_disk", "join_001_segments",
                 "not_an_archive"],
                lambda m: (probes.extract_as(item, m) or None),
                on_event)
        if rescued:
            for child in rescued:
                queue.append(child)
        else:
            working.append(item)

    if not working:
        emit(Phase.ERROR, Status.FAIL, "Nothing to classify after extraction.")
        return []

    # -- classification (BUG2 pre-filter: never probe/advise obvious non-evidence)
    memories: list[tuple[str, dict]] = []
    disks: list[str] = []
    documents: list[str] = []
    skipped = 0
    other_artifacts = 0
    unknown_count = 0
    unreadable_count = 0
    for cand in working:
        name = os.path.basename(cand)
        if archive.is_document(cand):
            documents.append(cand)
            emit(Phase.CLASSIFY, Status.OK,
                 f"{name} - reference document (kept, not analyzed)",
                 name=name, role="DOC", probe="type")
            continue
        # Known non-image forensic artifacts (triage/.mans, plaso, bodyfile, db,
        # evtx, pcap): kept as a quiet note, never probed, never flagged UNKNOWN.
        if _is_non_image_artifact(cand):
            other_artifacts += 1
            continue
        if archive.is_junk(cand) or _too_small_to_probe(cand):
            skipped += 1                    # collapsed into one summary line
            continue
        # Unreadable evidence is NEVER classified: a BROKEN symlink (lexists but
        # not exists) or a zero-byte file has no bytes to probe -- every content
        # probe fails silently and the name-shape rescue would otherwise claim
        # it on the filename alone (live: a broken '<host>-memory.zip' link took
        # the host's disk while the real image was orphaned). Injected/virtual
        # test paths (which do not lexist at all) keep the probes-decide
        # contract. Filesystem primitives only -- no names.
        _broken_link = os.path.lexists(cand) and not os.path.exists(cand)
        if _broken_link or _safe_size(cand) == 0:
            unreadable_count += 1
            emit(Phase.CLASSIFY, Status.WARN,
                 f"{name} - unreadable ("
                 f"{'broken link' if _broken_link else 'empty file'}), set aside",
                 name=name, role="SETASIDE", reason="unreadable")
            continue
        # (a) large enough AND (b) not doc/junk -> the only files that may probe.
        if probes.has_filesystem(cand):
            disks.append(cand)
            emit(Phase.CLASSIFY, Status.OK, f"{name} → DISK",
                 name=name, role="DISK", probe="fsstat")
            continue
        # Content-signature memory probe BEFORE the slow vol3: a crash dump / LiME
        # capture is provable from offset-0 magic alone -- the spec's "probe them,
        # not by name", and it skips the 120s vol3 wait. Kill-switch
        # SIFT_MEMORY_SIGNATURE_PROBE=0.
        if os.environ.get("SIFT_MEMORY_SIGNATURE_PROBE", "1") != "0":
            sig = probes.memory_signature(cand)
            if sig:
                memories.append((cand, {}))
                emit(Phase.CLASSIFY, Status.OK,
                     f"{name} → MEMORY (content signature: {sig})",
                     name=name, role="MEMORY", probe=f"signature:{sig}")
                continue
        info = probes.memory_info(cand)
        if info:
            memories.append((cand, info))
            emit(Phase.CLASSIFY, Status.OK, f"{name} → MEMORY",
                 name=name, role="MEMORY", probe="vol3")
            continue
        # Deterministic memory rescue BEFORE any AI consult: not-a-filesystem +
        # memory role-shape in the filename => MEMORY (vol3 profile deferred to
        # the pipeline's own check, which runs with a longer budget).
        if _memory_role_name_shape(name):
            memories.append((cand, {}))
            emit(Phase.CLASSIFY, Status.OK,
                 f"{name} → MEMORY (filename role-shape; vol3 probe "
                 "unavailable, profile resolved in-pipeline)",
                 name=name, role="MEMORY", probe="name-shape")
            continue
        # Deterministic exhaustion (point 2): a genuine evidence-sized leaf that
        # is neither FS nor memory. ONLY here may the advisor be consulted.
        res = consult_and_verify(
            ai, consultations, "CLASSIFY",
            "File matches no filesystem and no memory profile; which role?",
            {"name": name, "size": _safe_size(cand),
             "has_fs": False, "vol3_profile": None},
            ["MEMORY", "DISK", "DOC", "UNKNOWN"],
            lambda role: probes.deep_classify(cand, role), on_event)
        if res is not None and res[0] == "MEMORY":
            memories.append((cand, res[1] or {}))
            emit(Phase.CLASSIFY, Status.OK,
                 f"{name} → MEMORY (AI-assisted, verified)",
                 name=name, role="MEMORY", probe="vol3+ai")
        elif res is not None and res[0] == "DISK":
            disks.append(cand)
            emit(Phase.CLASSIFY, Status.OK,
                 f"{name} → DISK (AI-assisted, verified)",
                 name=name, role="DISK", probe="mmls+ai")
        else:
            unknown_count += 1
            emit(Phase.CLASSIFY, Status.WARN,
                 f"{name} → could not classify (no FS, vol3 found no profile)",
                 name=name, role="UNKNOWN", probe="none")
    # ONE quiet summary for everything that is NOT a raw memory/disk image, so the
    # main view stays focused on the evidence. Per-file doc/artifact/unknown lines
    # are emitted above too, but the presenter hides them in the default view and
    # surfaces them only under --verbose.
    doc_count = len(documents)
    set_aside = (doc_count + other_artifacts + skipped + unknown_count
                 + unreadable_count)
    if set_aside:
        bits = []
        if doc_count:
            bits.append(f"{doc_count} reference doc(s)")
        if other_artifacts:
            bits.append(f"{other_artifacts} forensic artifact(s)")
        if skipped:
            bits.append(f"{skipped} small/fragment(s)")
        if unknown_count:
            bits.append(f"{unknown_count} unrecognized")
        if unreadable_count:
            bits.append(f"{unreadable_count} unreadable (broken link/empty)")
        emit(Phase.CLASSIFY, Status.OK,
             f"set aside {set_aside} non-image file(s) - not analyzed "
             f"({' · '.join(bits)})", role="SETASIDE", count=set_aside)

    # -- pair memory+disk into one or more cases (multi-case aware) ----------
    # Pairing is by SHARED HOST TOKEN, never by sorted index: a folder holding
    # many hosts pairs each memory image to ITS OWN disk (base-dc-memory.img ->
    # base-dc-cdrive.E01), not memory[i] to whatever disk happens to sort at [i].
    # Collapse duplicate COPIES (same filename, different folder) so one host is
    # never emitted as two identical cases.
    memories = _dedupe_by_basename(memories, key=lambda m: m[0])
    disks = _dedupe_by_basename(disks)
    if not memories and not disks:
        note = (f"{len(documents)} reference document(s) only"
                if documents else "nothing usable")
        emit(Phase.ERROR, Status.FAIL,
             f"No memory or disk images found ({note}).")
        return []
    multi = len(memories) > 1 or len(disks) > 1
    if multi:
        pairings = _pair_by_host(memories, disks)
        emit(Phase.DISCOVER, Status.WARN, "multiple cases detected",
             multi_case=True, memory=len(memories), disk=len(disks),
             cases=len(pairings))
    else:
        pairings = [(memories[0] if memories else None,
                     disks[0] if disks else None)]

    _REFS_BASE = ("OS from memory windows.info (vol3) and the disk SOFTWARE-hive "
                  "ProductName; fsstat 'Version' (NTFS format) is NOT used as the OS.")

    def assemble(idx: int, mem_tuple, disk_path: Optional[str]) -> CaseManifest:
        mem_path = mem_tuple[0] if mem_tuple else None
        mem_info = mem_tuple[1] if mem_tuple else None
        cid = f"{_case_id(root)}-{idx + 1}" if multi else _case_id(root)

        # mount ladder (+ advisor point 4) FIRST - so the disk OS can be read
        # from the mounted SOFTWARE hive.
        mount_method: Optional[str] = None
        mount_path: Optional[str] = None
        if disk_path:
            mountpoint = os.path.join(
                tempfile.gettempdir(), "sift-onboard-mnt", cid)
            emit(Phase.MOUNT, Status.START, "Mounting the disk read-only…",
                 disk=os.path.basename(disk_path))
            ladder = list(MOUNT_LADDER)
            for i, method in enumerate(ladder):
                ok, reason = probes.mount(disk_path, method, mountpoint)
                if ok:
                    mount_method, mount_path = method, mountpoint
                    emit(Phase.MOUNT, Status.OK, f"mounted via {method}",
                         method=method, mountpoint=mountpoint)
                    break
                nxt = ladder[i + 1] if i + 1 < len(ladder) else None
                if nxt:
                    emit(Phase.MOUNT, Status.WARN,
                         f"{method} didn't take ({reason}) → trying {nxt}…",
                         method_tried=method, reason=reason, next=nxt)
                else:
                    emit(Phase.MOUNT, Status.FAIL,
                         f"could not mount the disk ({reason})",
                         method_tried=method, reason=reason)
            if mount_method is None:
                mp = consult_and_verify(
                    ai, consultations, "MOUNT",
                    "Mount ladder exhausted; which method should I try?",
                    {"fstype": probes.fs_facts(disk_path).get("fstype", ""),
                     "disk": os.path.basename(disk_path)},
                    ["apfs-fuse", "refs", "try_offset:<n>", "vfat", "ext_auto"],
                    lambda m: (mountpoint
                               if probes.mount(disk_path, m, mountpoint)[0]
                               else None),
                    on_event)
                if mp is not None:
                    mount_method = consultations[-1]["action_taken"]
                    mount_path = mp
                    emit(Phase.MOUNT, Status.OK,
                         f"mounted via {mount_method} (AI-assisted, verified)",
                         method=mount_method, mountpoint=mountpoint)

        # OS detection: memory authoritative (vol3 windows.info); disk OS read
        # FRESH from THIS disk's mounted SOFTWARE hive - never carried, never
        # fsstat's NTFS-version label. Unreadable / unmounted -> None (shown
        # "undetermined"). agree=yes only when both resolve to the same family.
        memory_os = _os_from_memory(mem_info) if mem_info else None
        disk_os = probes.disk_os(mount_path) if (disk_path and mount_path) else None
        # SIFT_ONBOARD_OS_LABEL_SAFE_DEFAULTS_V1
        # detect_os() should return {"os": ..., "source": ...}, but onboarding
        # must not crash or leave os_label/os_source unbound if a future probe
        # returns a malformed value. Unknown is explicit and audit-visible.
        os_profile_raw = detect_os(memory_os, disk_os) or {}
        if not isinstance(os_profile_raw, dict):
            os_profile_raw = {
                "os": "unknown",
                "source": "none",
                "malformed_detect_os": repr(os_profile_raw),
            }
        os_label = str(os_profile_raw.get("os") or "unknown")
        os_source = str(os_profile_raw.get("source") or "none")
        os_profile = {**os_profile_raw, "os": os_label, "source": os_source}
        if not isinstance(os_profile, dict):
            os_profile = {}
        os_label = os_profile.get("os") or "undetermined"
        os_source = os_profile.get("source") or "none"
        os_profile.setdefault("os", os_label)
        os_profile.setdefault("source", os_source)
        if os_label not in ("unknown", "undetermined"):
            emit(Phase.OS_DETECT, Status.OK, os_label, **os_profile)
        else:
            emit(Phase.OS_DETECT, Status.WARN, "operating system undetermined",
                 **os_profile)
            _os_target = mount_path or mem_path or ""
            guess = consult_and_verify(
                ai, consultations, "OS_DETECT",
                "OS family undetermined after disk+memory probes; best guess?",
                {"disk_os": disk_os, "memory_os": memory_os,
                 "fstype": (probes.fs_facts(disk_path).get("fstype", "")
                            if disk_path else "")},
                None, lambda fam: probes.deep_os(_os_target, fam), on_event)
            if guess is not None:
                os_label, os_source = guess, "ai+probe"
                os_profile = {**os_profile, "os": guess, "source": os_source}
                emit(Phase.OS_DETECT, Status.OK,
                     f"{guess} (AI-assisted, verified)", **os_profile)

        # health
        mem_health: Optional[str] = None
        mem_facts: dict = {}
        if mem_path:
            healthy, reasons, facts = probes.health(mem_path)
            mem_facts = facts
            if "missing_or_empty" in reasons:
                mem_health = None
                emit(Phase.HEALTH, Status.FAIL,
                     "memory image is missing or empty", reasons=reasons)
            elif healthy:
                mem_health = "HEALTHY"
                emit(Phase.HEALTH, Status.OK, "memory image is HEALTHY",
                     healthy=True, facts=facts)
            else:
                mem_health = "DEGRADED"
                emit(Phase.HEALTH, Status.WARN, "memory image is DEGRADED",
                     healthy=False, reasons=reasons, facts=facts)

        refs = [_REFS_BASE]
        if mem_path:
            refs.append(f"memory: windows.info (vol3) - {mem_path}")
        if disk_path:
            src = "SOFTWARE hive" if disk_os else "fsstat (TSK)"
            refs.append(f"disk: {src}"
                        f"{' + ntfs-3g mount' if mount_method else ''} - {disk_path}")
        manifest = CaseManifest(
            case_id=cid, os=os_label, os_source=os_source,
            memory_path=mem_path, memory_health=mem_health,
            memory_health_facts=mem_facts, disk_path=disk_path,
            disk_mounted=mount_method is not None, mount_method=mount_method,
            mount_path=mount_path, reference_docs=refs, os_profile=os_profile,
            ai_consultations=consultations, documents=list(documents),
        )
        emit(Phase.MANIFEST, Status.OK, f"case '{cid}' assembled", case_id=cid)
        return manifest

    cases = [assemble(i, mem, disk) for i, (mem, disk) in enumerate(pairings)]
    emit(Phase.READY, Status.OK, "Everything is verified and ready.",
         cases=len(cases))
    return cases
