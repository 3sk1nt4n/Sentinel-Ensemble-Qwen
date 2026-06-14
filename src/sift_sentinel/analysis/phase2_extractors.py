"""Phase 2 additive typed-fact extractors (slot31AS).

Adds compilers for Volatility3 Windows plugins that ran in production but
had no _TOOL_COMPILERS entry, causing silent drop of records per run:

  - vol_userassist  -> userassist_fact      (Registry execution history)
  - vol_privileges  -> privilege_fact       (Token privileges per process)
  - vol_ssdt        -> ssdt_integrity_fact  (Kernel syscall table entries)
  - vol_getsids     -> sid_fact             (Per-process SIDs)
  - vol_sessions    -> session_fact         (Logon sessions)

Dataset-agnostic AND judgment-free:
  * Every emitted field is a structural pass-through from the Volatility3
    record. No derived classifications (is_sensitive, is_hooked, etc.).
  * No hardcoded vendor/module/privilege/SID lists. The extractor never
    decides what is malicious, sensitive, or clean. That judgment lives
    downstream (Inv2 / ReAct / candidate_observations / severity layer)
    where it can be audited and questioned by the AI.
  * Random-token input -> correctly shaped facts with tokens passed
    through verbatim. Empty input -> empty output. Generator pattern
    matches phase1_extractors._c_*.
"""
import re
from typing import Iterator, Tuple

from .evidence_db import (
    normalize_path, normalize_timestamp, _int_or_none, _pid_eid,
)

# NTFS user-hive path structure - parses ANY user name; structural only.
_USER_FROM_HIVE_RE = re.compile(
    r"\\Users\\([^\\]+)\\ntuser\.dat", re.IGNORECASE)

# Windows SID structural format: S-<revision>-<authority>-<subauthority...>
_SID_FORMAT_RE = re.compile(r"^S-\d+-\d+(-\d+)*$")


def _c_userassist(records):
    """vol_userassist records -> userassist_fact. Structural pass-through."""
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        hive = (rec.get("Hive Name") or "").strip()
        path = (rec.get("Path") or "").strip()
        if not hive and not path:
            yield idx, None, "no_hive_or_path"
            continue
        # Structural: extract user from NTFS user-hive path pattern.
        # The regex matches the path STRUCTURE, captures whatever name
        # appears there (no hardcoded user names).
        user = ""
        if hive:
            m = _USER_FROM_HIVE_RE.search(hive)
            if m:
                user = m.group(1).lower()
        rec_type = (rec.get("Type") or "").strip()
        name = (rec.get("Name") or "").strip()
        ceid = f"userassist:{user or 'unknown'}:{normalize_path(path)[:80]}"
        yield idx, {
            "fact_type": "userassist_fact",
            "entity_id": ceid,
            "artifact": [user[:32], rec_type[:8], name[:60]],
            "user": user,
            "hive_path": hive,
            "registry_path": path,
            "last_write_time": normalize_timestamp(rec.get("Last Write Time")),
            "last_updated_time": normalize_timestamp(rec.get("Last Updated")),
            "run_count": _int_or_none(rec.get("Count")),
            "focus_count": _int_or_none(rec.get("Focus Count")),
            "focus_time_seconds": _int_or_none(rec.get("Time Focused")),
            "entry_type": rec_type,
            "entry_name": name,
        }, None


def _c_privileges(records):
    """vol_privileges records -> privilege_fact. Structural pass-through.

    No is_sensitive / is_enabled / is_present flags. Downstream layers
    apply judgment by checking attribute strings or whitelists.
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        pid = _int_or_none(rec.get("PID"))
        priv = (rec.get("Privilege") or "").strip()
        if pid is None or not priv:
            yield idx, None, "no_pid_or_privilege"
            continue
        proc = (rec.get("Process") or "").lower().strip()
        attrs_raw = (rec.get("Attributes") or "").strip()
        attrs = [a.strip() for a in attrs_raw.split(",") if a.strip()]
        ceid = f"privilege:{_pid_eid(pid)}:{priv}"
        yield idx, {
            "fact_type": "privilege_fact",
            "entity_id": ceid,
            "artifact": [proc[:32], priv[:40], attrs_raw[:30]],
            "pid": pid,
            "process_name": proc,
            "privilege": priv,
            "description": (rec.get("Description") or "").strip(),
            "attributes": attrs,
            "attributes_raw": attrs_raw,
            "value": _int_or_none(rec.get("Value")),
        }, None


def _c_ssdt(records):
    """vol_ssdt records -> ssdt_integrity_fact. Structural pass-through.

    No is_hooked classification. Downstream judgment compares module
    name to a kernel-module whitelist that can be audited separately.
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        module = (rec.get("Module") or "").strip().lower()
        symbol = (rec.get("Symbol") or "").strip()
        index_val = _int_or_none(rec.get("Index"))
        if index_val is None or not module:
            yield idx, None, "no_index_or_module"
            continue
        yield idx, {
            "fact_type": "ssdt_integrity_fact",
            "entity_id": f"ssdt:{index_val}:{symbol}",
            "artifact": [str(index_val), module[:40], symbol[:40]],
            "syscall_index": index_val,
            "module": module,
            "symbol": symbol,
            "address": _int_or_none(rec.get("Address")),
        }, None


def _c_getsids(records):
    """vol_getsids records -> sid_fact. Structural pass-through.

    Filters records by SID FORMAT (S-revision-authority-subauthority),
    not by literal value. No is_system / is_local_admin / is_user_sid
    derived flags - those are downstream judgments.
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        pid = _int_or_none(rec.get("PID"))
        sid = (rec.get("SID") or "").strip()
        if pid is None or not sid:
            yield idx, None, "no_pid_or_sid"
            continue
        # Structural format check; rejects ANY non-SID-shaped string
        # (including Volatility3 status messages like "Token unreadable").
        if not _SID_FORMAT_RE.match(sid):
            yield idx, None, "invalid_sid_format"
            continue
        proc = (rec.get("Process") or "").lower().strip()
        name = (rec.get("Name") or "").strip()
        yield idx, {
            "fact_type": "sid_fact",
            "index": {"by_pid": [str(pid)]},  # SID_FACT_INDEX_DIRECTIVE_V1
            "entity_id": f"sid:{_pid_eid(pid)}:{sid}",
            "artifact": [proc[:32], name[:32], sid[:50]],
            "pid": pid,
            "process_name": proc,
            "sid": sid,
            "resolved_name": name,
        }, None


def _c_sessions(records):
    """vol_sessions records -> session_fact. Structural pass-through.

    Note: Volatility3 uses space-containing keys here (Process ID,
    Session ID, Create Time, Session Type, User Name).
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        pid = _int_or_none(rec.get("Process ID"))
        if pid is None:
            yield idx, None, "no_pid"
            continue
        session_id = _int_or_none(rec.get("Session ID"))
        proc = (rec.get("Process") or "").lower().strip()
        user = (rec.get("User Name") or "").strip()
        sess_type = (rec.get("Session Type") or "").strip()
        sid_key = session_id if session_id is not None else "none"
        yield idx, {
            "fact_type": "session_fact",
            # Index by PID (and process name) so a logon-session fact JOINS to a
            # process finding -- the session/user/logon-type context enriches the
            # finding (WHO + session anomaly) and counts as a corroborating
            # source tool. Without this the fact was collected but unjoinable.
            "index": {"by_pid": [str(pid)],
                      "by_process_name": [proc] if proc else []},
            "entity_id": f"session:{sid_key}:{_pid_eid(pid)}",
            "artifact": [proc[:32], user[:32], sess_type[:20]],
            "pid": pid,
            "process_name": proc,
            "session_id": session_id,
            "session_type": sess_type,
            "user_name": user,
            "create_time": normalize_timestamp(rec.get("Create Time")),
        }, None


def _c_callbacks(records):
    """vol_callbacks records -> kernel_callback_fact. Structural pass-through.

    Vol3 windows.callbacks.Callbacks record schema (verified on live output):
      Type    (callback registration kind, e.g. PspLoadImageNotifyRoutine)
      Callback (routine address)
      Module  (kernel module name owning the routine)
      Symbol  (resolved symbol or None)
      Detail  (or None) / TreeDepth (Vol3 nesting, ignored)

    Kernel callbacks are the classic rootkit hook surface; this compiler makes
    no is_suspicious judgment and carries no module name lists -- downstream
    layers decide. Without it, every live run dropped these records (31X WARN).
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        cb_type = (rec.get("Type") or "").strip()
        module = (rec.get("Module") or "").strip().lower()
        if not cb_type and not module:
            yield idx, None, "no_type_or_module"
            continue
        symbol = (rec.get("Symbol") or "").strip()
        detail = (rec.get("Detail") or "").strip()
        addr = _int_or_none(rec.get("Callback"))
        ceid = "kcallback:%s:%s:%s" % (
            cb_type[:40], module[:40], addr if addr is not None else idx)
        yield idx, {
            "fact_type": "kernel_callback_fact",
            "entity_id": ceid,
            "artifact": [cb_type[:40], module[:40], symbol[:40]],
            "callback_type": cb_type,
            "module": module,
            "symbol": symbol,
            "detail": detail,
            "address": addr,
        }, None


def _c_modscan(records):
    """vol_modscan / vol_modules records -> kernel_module_fact. Structural.

    Vol3 windows.modscan.ModScan schema (verified against the installed plugin):
      Offset / Base / Size / Name (BaseDllName) / Path (FullDllName) / File output.

    modscan scans pool memory for module objects, so it sees UNLINKED / hidden
    kernel modules a clean module-list walk misses. A kernel-mode driver (.sys)
    loaded from OUTSIDE System32\\drivers is the kernel-rootkit loading primitive
    (T1014). This compiler makes NO malice judgment -- it copies Name/Path through
    and surfaces Path as ``image_path`` so the existing conclusive
    match_kernel_driver_nonstandard_path detector can fire from MEMORY evidence.
    Indexed by_path so the driver joins to registry/event corroborators (XCORR).
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        name = (rec.get("Name") or "").strip()
        path = (rec.get("Path") or rec.get("FullDllName")
                or rec.get("File output") or "").strip()
        if not name and not path:
            yield idx, None, "no_name_or_path"
            continue
        ceid = "kmodule:%s" % (name.lower() or normalize_path(path)[:80])
        yield idx, {
            "fact_type": "kernel_module_fact",
            "index": {"by_path": [normalize_path(path)] if path else []},
            "entity_id": ceid,
            "artifact": [name[:48], path[:90]],
            "module_name": name,
            "module_path": path,
            "image_path": path,  # field match_kernel_driver_nonstandard_path reads
            "base_address": rec.get("Base"),
            "size": rec.get("Size"),
        }, None


def _c_reg_hivelist(records):
    """vol_reg_hivelist records -> registry_hive_fact (structural).

    Vol3 reg.hivelist record schema (verified on rd-01):
      FileFullPath  (NT-style path, may be empty for unmapped hives)
      Offset        (hive offset in memory)
      File output   (Vol3 flag, ignored)
      TreeDepth     (Vol3 nesting, ignored)

    Pure structural: one fact per non-empty hive path. No judgment
    about which hives are anomalous - downstream layers handle that.
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        path = (rec.get("FileFullPath") or "").strip()
        if not path:
            yield idx, None, "empty_hive_path"
            continue
        offset = _int_or_none(rec.get("Offset"))
        norm = path.lower().replace("\\", "/")
        ceid = f"hive:{norm[:120]}"
        yield idx, {
            "fact_type": "registry_hive_fact",
            "entity_id": ceid,
            "artifact": [path[:80]],
            "hive_path": path,
            "hive_offset": offset,
        }, None


PHASE2_COMPILERS = {
    "vol_userassist":   _c_userassist,
    "parse_userassist": _c_userassist,  # USERASSIST-DISK: same compiler, disk NTUSER source
    "vol_privileges":   _c_privileges,
    "vol_ssdt":         _c_ssdt,
    "vol_getsids":      _c_getsids,
    "vol_sessions":     _c_sessions,
    "vol_reg_hivelist": _c_reg_hivelist,
    "vol_callbacks":    _c_callbacks,   # kernel callback hooks (rootkit surface)
    "vol_modscan":      _c_modscan,     # kernel modules incl. hidden (rootkit driver)
    "vol_modules":      _c_modscan,     # same schema, linked-list view
}

PHASE2_FACT_TYPES = (
    "userassist_fact",
    "privilege_fact",
    "ssdt_integrity_fact",
    "sid_fact",
    "session_fact",
    "registry_hive_fact",
    "kernel_callback_fact",
    "kernel_module_fact",
)


# ── Import-order-safe registration ───────────────────────────────────────────
# This module imports evidence_db's normalizers (line ~26), so when THIS module
# is imported FIRST, evidence_db's bottom-of-module merge sees a partially
# initialized phase2_extractors (PHASE2_COMPILERS not yet defined), hits
# ImportError, and SILENTLY skips registration -- every phase2 fact family
# vanishes from the DB for that process, depending purely on import order.
# Registering from this side too (idempotent: setdefault / append-if-missing,
# matching evidence_db's own guards) makes the merge hold in BOTH orders.
# evidence_db._TOOL_COMPILERS and FACT_TYPES are defined near its top, so they
# exist even when evidence_db is itself mid-import here.
from . import evidence_db as _edb_reg

for _p2_tool, _p2_compiler in PHASE2_COMPILERS.items():
    _edb_reg._TOOL_COMPILERS.setdefault(_p2_tool, _p2_compiler)
_edb_reg.FACT_TYPES = tuple(_edb_reg.FACT_TYPES) + tuple(
    _t for _t in PHASE2_FACT_TYPES if _t not in _edb_reg.FACT_TYPES)
