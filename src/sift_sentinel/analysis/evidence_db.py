"""SIFT Sentinel - Typed EvidenceDB compiler layer (Slot 31E-DB.1).

Converts rich tool_outputs into first-class, typed forensic facts.

This module is *sidecar only*. It does NOT change validator behavior,
report behavior, Inv2 prompts, ReAct, model routing, or live execution.
Step 7 still writes reference_set.json exactly as before; this layer adds
evidence_db.json + evidencedb_coverage.json alongside it.

Design contract:
  - Every fact carries: fact_id, fact_type, fact_signature, source_tool,
    source_record_index (when available), confidence_hint, raw_excerpt.
  - fact_signature = sha1(fact_type + "::" + canonical_entity_id
                          + "::" + canonical_artifact_tuple)
  - Coverage reconciliation per tool:
        record_count == compiled_record_count + dropped_record_count
    (record_count is intentionally NOT compared to emitted_fact_count,
     because one raw record may legitimately emit multiple facts.)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from typing import Any

VERSION = "31E-DB.1"

FACT_TYPES = (
    "process_fact",
    "process_relationship_fact",
    "memory_injection_fact",
    "network_connection_fact",
    "file_execution_fact",
    "registry_persistence_fact",
    "scheduled_task_fact",
    "event_log_fact",
    "powershell_command_fact",
    "service_fact",
    "rdp_artifact_fact",
    "network_ioc_fact",
    "string_artifact_fact",
    "environment_variable_fact",
    "decoded_string_fact",
    "wmi_subscription_fact",
    "yara_match_fact",
    "filesystem_listing_fact",
    "filesystem_timeline_fact",
    "ioc_carve_summary_fact",
    "srum_usage_fact",  # 31K-SRUM-TYPED-VALIDATOR
    "appcompatcache_execution_fact",  # 31K-APPCOMPAT-TYPED-CANDIDATE
    "lnk_execution_fact",  # 31K-LNK-WIRE
    "jumplist_fact",  # 31K-LNK-WIRE
    "usb_device_fact",  # USB-WIRE: removable-media device identity (USBSTOR/MountedDevices/MountPoints2)
)

INDEX_NAMES = (
    'by_pid',
    'by_path',
    'by_hash',
    'by_ip',
    'by_port',
    'by_registry_path',
    'by_task_name',
    'by_service_name',
    'by_event_id',
    'by_fact_signature',
    'by_ttp_tag',
    'by_user',
    'by_timestamp_minute',
    'by_source_file_basename',
    'by_url_host',
)

_WS_RE = re.compile(r"\s+")
_SLASH_RE = re.compile(r"/{2,}")
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[ ]\d{2}:\d{2})")
_RAW_EXCERPT_CAP = 600


# ── Normalization ────────────────────────────────────────────────────────

def normalize_path(value: Any) -> str:
    """Lowercase; backslash -> slash; collapse duplicate slashes; strip
    trailing slash and surrounding quotes/whitespace."""
    if value is None:
        return ""
    s = str(value).strip().strip('"').strip("'").strip()
    if not s:
        return ""
    s = s.replace("\\", "/")
    s = _SLASH_RE.sub("/", s)
    s = s.rstrip("/")
    return s.lower()


def normalize_ip(value: Any) -> str | None:
    """Canonical IP string via ipaddress, or None if not an IP."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return None


def normalize_registry(*parts: Any) -> str:
    """Normalize a registry hive/path/value tuple into one canonical key."""
    joined = "/".join(str(p) for p in parts if p not in (None, ""))
    return normalize_path(joined)


def normalize_cmdline(value: Any) -> str:
    """Lowercase, whitespace-collapsed command-line form."""
    if value is None:
        return ""
    return _WS_RE.sub(" ", str(value).strip()).lower()


def normalize_timestamp(value: Any) -> str:
    """Whitespace-trimmed timestamp with 'T' -> ' '. No fabrication;
    returns '' when absent. Not minute-truncated (see timestamp_minute)."""
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    return s.replace("T", " ")


def _pid_eid(pid: Any) -> str:
    """Canonical process entity id: 'pid:<N>'."""
    return f"pid:{pid}"


def _int_or_none(value: Any):
    """Best-effort int coercion; None when not an integer."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def timestamp_minute(value: Any) -> str:
    """Minute-granularity prefix of a timestamp for coarse correlation.
    Best-effort, no fabrication; returns '' when absent."""
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    s = s.replace("T", " ")
    m = _TS_RE.match(s)
    return m.group(1) if m else s[:16]


def _canon(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def fact_signature(fact_type: str, entity_id: str,
                    artifact_tuple) -> str:
    canon_artifact = "|".join(_canon(a) for a in artifact_tuple)
    payload = f"{fact_type}::{entity_id}::{canon_artifact}"
    return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()


def _excerpt(record: Any) -> str:
    try:
        s = json.dumps(record, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        s = str(record)
    return s[:_RAW_EXCERPT_CAP]


# ── Record extraction from heterogeneous envelopes ───────────────────────

def _records(envelope: Any) -> list:
    """Return the record list regardless of envelope shape.

    Handles three observed shapes:
      - {"records": [...]}                          (parse_* / net_iocs)
      - {"output": [...]}                            (vol_* / event_logs)
      - {"output": {"entries"|"events"|...: [...]}}  (amcache / mft)
    """
    if not isinstance(envelope, dict):
        return []
    recs = envelope.get("records")
    if isinstance(recs, list):
        return recs
    out = envelope.get("output")
    if isinstance(out, list):
        return out
    if isinstance(out, dict):
        for key in ("entries", "events", "records", "output"):
            if isinstance(out.get(key), list):
                return out[key]
    return []


def _declared_record_count(envelope: Any, fallback: int) -> int:
    if isinstance(envelope, dict):
        rc = envelope.get("record_count")
        if isinstance(rc, int):
            return rc
        out = envelope.get("output")
        if isinstance(out, dict) and isinstance(out.get("record_count"), int):
            return out["record_count"]
    return fallback


def _is_error_envelope(envelope: Any) -> bool:
    return (
        isinstance(envelope, dict)
        and "error" in envelope
        and not _records(envelope)
    )


# ── Compilers ────────────────────────────────────────────────────────────
# Each compiler is a generator over enumerate(records). For each record it
# yields one or more tuples:  (record_index, fact_spec | None, reason)
# where fact_spec is:
#   {"fact_type", "entity_id", "artifact": (...),
#    "confidence_hint", "index": {index_name: [keys]}}
# Yielding (idx, None, reason) for a record marks it dropped.

def _c_process(records):
    for i, rec in enumerate(records):
        pid = rec.get("PID")
        name = rec.get("ImageFileName") or rec.get("Process") or ""
        if pid is None or not name:
            yield i, None, "missing_pid_or_name"
            continue
        path = rec.get("Path") or ""
        np = normalize_path(path)
        pid_i = _int_or_none(pid)
        ppid = rec.get("PPID")
        ppid_i = _int_or_none(ppid)
        cmdline = normalize_cmdline(rec.get("Cmd") or rec.get("Args"))
        idx = {"by_pid": [str(pid)]}
        if np:
            idx["by_path"] = [np]
        ceid = _pid_eid(pid)
        yield i, {
            "fact_type": "process_fact",
            "entity_id": ceid,
            "canonical_entity_id": ceid,
            "artifact": (name.lower(), np,
                         timestamp_minute(rec.get("CreateTime"))),
            "confidence_hint": "observed",
            "index": idx,
            "fields": {
                "canonical_entity_id": ceid,
                "pid": pid_i,
                "process_name": name.lower(),
                "image_name": name,
                "parent_pid": ppid_i,
                "path": np,
                "cmdline": cmdline,
                "create_time": normalize_timestamp(rec.get("CreateTime")),
                "exit_time": normalize_timestamp(rec.get("ExitTime")),
            },
        }, None
        if ppid is not None:
            child_eid = _pid_eid(pid)
            parent_eid = _pid_eid(ppid)
            rel_ceid = f"{child_eid}->{parent_eid}"
            yield i, {
                "fact_type": "process_relationship_fact",
                "entity_id": rel_ceid,
                "canonical_entity_id": rel_ceid,
                "artifact": (name.lower(), str(ppid)),
                "confidence_hint": "observed",
                "index": {"by_pid": [str(pid), str(ppid)]},
                "fields": {
                    "canonical_entity_id": rel_ceid,
                    "pid": pid_i,
                    "parent_pid": ppid_i,
                    "child_entity_id": child_eid,
                    "parent_entity_id": parent_eid,
                    "process_name": name.lower(),
                    "parent_process_name": "",
                },
            }, None



# SIFT_NETCONN_DIRECTION_V1 -- deterministic, dataset-agnostic network direction enrichment.
def _net_is_external_ip(ip):
    s=str(ip or "")
    if s in ("","*","::","0.0.0.0"): return False
    if s.startswith(("10.","127.","169.254.","192.168.","::1","fe80","fc","fd")): return False
    if s.startswith("172."):
        try:
            if 16<=int(s.split(".")[1])<=31: return False
        except Exception: pass
    if s.startswith(("224.","239.","255.")): return False
    return True

def _net_direction(lport, fport, state):
    st=str(state or "").upper()
    if "LISTEN" in st: return "listening"
    def _i(x):
        try: return int(x)
        except Exception: return None
    lp,fp=_i(lport),_i(fport)
    if not fp: return "listening" if lp else "indeterminate"
    if lp is None: return "indeterminate"
    if lp<fp: return "inbound"
    if fp<lp: return "outbound"
    return "indeterminate"


def _c_netconn(records):
    for i, rec in enumerate(records):
        pid = rec.get("PID")
        laddr = normalize_ip(rec.get("LocalAddr"))
        faddr = normalize_ip(rec.get("ForeignAddr"))
        lport = rec.get("LocalPort")
        fport = rec.get("ForeignPort")
        if pid is None and laddr is None and faddr is None:
            yield i, None, "no_pid_or_endpoint"
            continue
        idx: dict[str, list] = {}
        if pid is not None:
            idx["by_pid"] = [str(pid)]
        ips = [a for a in (laddr, faddr) if a]
        if ips:
            idx["by_ip"] = ips
        ports = [str(p) for p in (lport, fport)
                 if p not in (None, 0, "0")]
        if ports:
            idx["by_port"] = ports
        eid = (str(pid) if pid is not None else (laddr or faddr))
        _ndir = _net_direction(lport, fport, rec.get("State"))
        yield i, {
            "fact_type": "network_connection_fact",
            "entity_id": eid,
            "canonical_entity_id": (
                _pid_eid(pid) if pid is not None
                else f"net:{laddr}:{lport}-{faddr}:{fport}"),
            "artifact": (rec.get("Proto", ""), f"{laddr}:{lport}",
                         f"{faddr}:{fport}", rec.get("State", ""),
                         rec.get("Owner", "")),
            "confidence_hint": "observed",
            "index": idx,
            "fields": {
                "pid": _int_or_none(pid),
                "src_ip": laddr or "",
                "src_port": _int_or_none(lport),
                "dst_ip": faddr or "",
                "dst_port": _int_or_none(fport),
                "protocol": rec.get("Proto", ""),
                "state": rec.get("State", ""),
                "owner": rec.get("Owner", ""),
                "direction": _ndir,
                "is_listener": _ndir == "listening",
                "remote_is_external": _net_is_external_ip(faddr),
            },
        }, None



# SIFT_MALFIND_CHARACTERIZE_V1 -- byte-level, dataset-agnostic malfind characterization.
def _malfind_characterize(rec):
    import re
    toks=re.findall(r'[0-9a-fA-F]{2}', str(rec.get("Disasm") or ""))
    b=[int(t,16) for t in toks[:64]]
    priv=1 if str(rec.get("PrivateMemory")) in ("1","True","true") else 0
    if not b: return {"characterization":"unknown","private":priv,"injection_corroborated":False}
    n=len(b); cc=sum(1 for x in b if x==0xcc); zero=sum(1 for x in b if x==0x00)
    hexs=" ".join(f"{x:02x}" for x in b); char="code"
    if b[0]==0x4d and len(b)>1 and b[1]==0x5a: char="mz_pe"
    elif zero>=n*0.8: char="zero_fill"
    elif cc>=n*0.8: char="int3_pad"
    elif ("e8 00 00 00 00" in hexs) or hexs.startswith(("64 a1","65 48 8b","fc 48 83 e4")): char="shellcode"
    return {"characterization":char,"private":priv,
            "injection_corroborated": bool(priv==1 and char in ("mz_pe","shellcode"))}


def _c_malfind(records):
    for i, rec in enumerate(records):
        pid = rec.get("PID")
        if pid is None:
            yield i, None, "missing_pid"
            continue
        prot = str(rec.get("Protection") or "")
        hint = ("high" if "EXECUTE" in prot and "WRITE" in prot
                else "medium")
        _mchar = _malfind_characterize(rec)
        yield i, {
            "fact_type": "memory_injection_fact",
            "entity_id": str(pid),
            "canonical_entity_id": _pid_eid(pid),
            "artifact": ((rec.get("Process") or "").lower(), prot,
                         str(rec.get("Start VPN")), rec.get("Tag", "")),
            "confidence_hint": hint,
            "index": {"by_pid": [str(pid)]},
            "fields": {
                "pid": _int_or_none(pid),
                "process_name": (rec.get("Process") or "").lower(),
                "protection": prot,
                "vad_start": rec.get("Start VPN"),
                "vad_end": rec.get("End VPN"),
                "tag": rec.get("Tag", ""),
                "characterization": _mchar["characterization"],
                "private_rwx": bool(_mchar["private"]),
                "injection_corroborated": _mchar["injection_corroborated"],
            },
        }, None


def _ldr_bool(value):
    if value is None or isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def _c_ldrmodules(records):
    """vol_ldrmodules -> memory_injection_fact for UNBACKED in-memory modules (T1055).

    A module present in the loader/memory view (InLoad/InMem) with NO backing file on
    disk (empty MappedPath) is a reflectively-loaded / injected region. Legit unlinked
    entries (System/smss/csrss meta-processes, and every process's main image showing
    InInit=False) ALL carry a valid System32 MappedPath, so requiring an EMPTY MappedPath
    is the low-FP discriminator -- on a clean image it fires zero times. Backed or
    not-loaded modules are skipped; the judgment is the empty-path structural rule,
    mirroring vol_malfind which emits only injection-like regions. Reuses the
    memory_injection_fact family (validated by_pid) so no new validation wiring is needed."""
    for i, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield i, None, "non_dict_record"
            continue
        pid = rec.get("Pid")
        if pid is None:
            pid = rec.get("PID")
        if pid is None:
            yield i, None, "missing_pid"
            continue
        mapped = str(rec.get("MappedPath") or "").strip()
        in_load = _ldr_bool(rec.get("InLoad"))
        in_mem = _ldr_bool(rec.get("InMem"))
        if not (mapped == "" and (in_load is True or in_mem is True)):
            yield i, None, "ldrmodules_backed_or_not_loaded"
            continue
        proc = (rec.get("Process") or "").lower()
        yield i, {
            "fact_type": "memory_injection_fact",
            "entity_id": str(pid),
            "canonical_entity_id": _pid_eid(pid),
            "artifact": (proc, "unbacked_module", str(rec.get("Base") or ""), ""),
            "confidence_hint": "high",
            "index": {"by_pid": [str(pid)]},
            "fields": {
                "pid": _int_or_none(pid),
                "process_name": proc,
                "protection": "UNBACKED_IMAGE",
                "vad_start": rec.get("Base"),
                "tag": "ldrmodules_unbacked",
                "characterization": "unbacked_executable_module",
                "private_rwx": False,
                "injection_corroborated": True,
                "source_detector": "vol_ldrmodules",
            },
        }, None


def _c_amcache(records):
    for i, rec in enumerate(records):
        path = rec.get("path") or ""
        sha1 = (rec.get("sha1") or "").lower()
        if not path and not sha1:
            yield i, None, "missing_path_and_hash"
            continue
        np = normalize_path(path)
        idx: dict[str, list] = {}
        if np:
            idx["by_path"] = [np]
        if sha1:
            idx["by_hash"] = [sha1]
        yield i, {
            "fact_type": "file_execution_fact",
            "entity_id": sha1 or np,
            "canonical_entity_id": (
                f"sha1:{sha1}" if sha1 else f"path:{np}"),
            "artifact": (np, sha1,
                         timestamp_minute(rec.get("first_run")),
                         "amcache"),
            "confidence_hint": "execution_evidence",
            "index": idx,
            "fields": {
                "path": path,
                "normalized_path": np,
                "sha1": sha1,
                "first_run": normalize_timestamp(rec.get("first_run")),
                "source": "amcache",
            },
        }, None


def _c_mft(records):
    for i, rec in enumerate(records):
        path = rec.get("path") or ""
        fname = rec.get("filename") or ""
        if not path and not fname:
            yield i, None, "missing_path"
            continue
        np = normalize_path(path or fname)
        yield i, {
            "fact_type": "filesystem_timeline_fact",
            "entity_id": np,
            "canonical_entity_id": f"path:{np}",
            "artifact": (
                np, rec.get("si_created", ""), rec.get("fn_created", ""),
                rec.get("si_modified", ""), rec.get("fn_modified", ""),
                rec.get("real_created", ""), rec.get("action", ""),
                "timestomped" if rec.get("timestomped") else "",
            ),
            "confidence_hint": "filesystem_timeline",
            "index": {"by_path": [np]} if np else {},
            "fields": {
                "path": path or fname,
                "normalized_path": np,
                "sha1": "",
                "si_created": normalize_timestamp(rec.get("si_created")),
                "fn_created": normalize_timestamp(rec.get("fn_created")),
                "si_modified": normalize_timestamp(
                    rec.get("si_modified")),
                "fn_modified": normalize_timestamp(
                    rec.get("fn_modified")),
                "real_created": normalize_timestamp(
                    rec.get("real_created")),
                "action": rec.get("action", ""),
                "timestomped": bool(rec.get("timestomped")),
                "source": "mft",
            },
        }, None


def _c_registry(records):
    """Compile registry persistence rows.

    31G-REG-TASK-RDP-FIELDS: preserve structured values exactly enough for
    later validation. In particular, numeric DWORD 0 must remain 0 rather
    than being collapsed to an empty string by ``or ""``.
    """
    for i, rec in enumerate(records):
        regpath = rec.get("registry_path") or ""
        if not regpath:
            yield i, None, "missing_registry_path"
            continue
        nreg = normalize_registry(regpath, rec.get("value_name"))
        idx: dict[str, list] = {"by_registry_path": [nreg]}
        svc = rec.get("service_name")
        if svc:
            idx["by_service_name"] = [str(svc).lower()]

        raw_value_data = rec.get("value_data")
        if raw_value_data is None:
            raw_value_data = ""
        vd = normalize_path(raw_value_data)
        if vd:
            idx["by_path"] = [vd]

        yield i, {
            "fact_type": "registry_persistence_fact",
            "entity_id": normalize_registry(regpath),
            "canonical_entity_id": f"reg:{normalize_registry(regpath)}",
            "artifact": (
                nreg, (rec.get("value_name") or "").lower(), vd,
                rec.get("persistence_type", ""),
                rec.get("hive_type", ""),
            ),
            "confidence_hint": "persistence_candidate",
            "index": idx,
            "fields": {
                "hive": rec.get("hive_type", ""),
                "registry_path": regpath,
                "normalized_registry_path": nreg,
                "value_name": rec.get("value_name", "") or "",
                "value_data": raw_value_data,
                "value_type": rec.get("value_type", "") or "",
                "persistence_type": rec.get("persistence_type", ""),
                "service_name": rec.get("service_name") or "",
                "control_set": rec.get("control_set") or "",
                "is_active_controlset": rec.get("is_active_controlset"),
                "last_write_time": rec.get("last_write_time") or "",
                "source_hive": rec.get("source_hive") or "",
            },
        }, None


def _c_usb(records):
    """Compile USB / removable-media device records into typed facts.

    Three removable-media artifact shapes share one fact_type:
      * usb_device     -- USBSTOR: device serial + vendor/product + FriendlyName
                          (the unique physical-device identity).
      * mounted_device -- MountedDevices: a drive letter the device was mounted as.
      * mount_point    -- MountPoints2: a volume mounted under a specific USER.

    Universal: keyed on the registry structure of removable media, no name list,
    no case data. Every fact binds via the universal by_fact_signature anchor;
    the USBSTOR/MountedDevices registry path and the per-user attribution
    additionally populate by_registry_path / by_path / by_user so a claim citing
    a device path or user resolves without any per-tool validator.
    """
    for i, rec in enumerate(records):
        kind = rec.get("type") or ""
        regpath = rec.get("registry_path") or ""
        serial = (rec.get("serial") or "").strip()
        drive = (rec.get("drive_letter") or "").strip()
        volume = (rec.get("volume") or "").strip()
        nreg = normalize_registry(regpath) if regpath else ""
        # Identity precedence: device serial > drive letter > volume GUID >
        # normalized registry path. A record with no identity at all is dropped.
        entity = serial or drive or volume or nreg
        if not entity:
            yield i, None, "missing_usb_entity"
            continue

        idx: dict[str, list] = {}
        if nreg:
            idx["by_registry_path"] = [nreg]
            idx["by_path"] = [nreg]
        user = (rec.get("user") or "").strip()
        if user:
            idx["by_user"] = [user.lower()]

        yield i, {
            "fact_type": "usb_device_fact",
            "entity_id": entity,
            "canonical_entity_id": f"usb:{entity.lower()}",
            "artifact": (
                kind, serial, rec.get("vendor", "") or "",
                rec.get("product", "") or "", drive, volume,
            ),
            "confidence_hint": "removable_media",
            "index": idx,
            "fields": {
                "device_kind": kind,
                "serial": serial,
                "vendor": rec.get("vendor", "") or "",
                "product": rec.get("product", "") or "",
                "friendly_name": rec.get("friendly_name", "") or "",
                "drive_letter": drive,
                "volume": volume,
                "user": user,
                "registry_path": regpath,
            },
        }, None


def _c_sched(records):
    """Compile scheduled-task XML artifacts.

    31G-REG-TASK-RDP-FIELDS: keep executable paths for indexing but also
    preserve action arguments, COM handler details, source path, user/run
    metadata, and timestamps so validation can distinguish benign hidden
    baseline tasks from suspicious task persistence.
    """
    for i, rec in enumerate(records):
        tname = rec.get("task_name") or rec.get("task_path") or ""
        if not tname:
            yield i, None, "missing_task_name"
            continue

        actions_raw = [
            a for a in (rec.get("actions") or [])
            if isinstance(a, dict)
        ]
        execs = [
            normalize_path(a.get("execute"))
            for a in actions_raw
            if a.get("execute")
        ]
        action_details = []
        class_ids = []
        for a in actions_raw:
            norm_execute = normalize_path(a.get("execute"))
            class_id = str(a.get("class_id") or "")
            if class_id:
                class_ids.append(class_id.lower())
            action_details.append({
                "type": a.get("type") or "",
                "execute": a.get("execute") or "",
                "normalized_execute": norm_execute,
                "arguments": a.get("arguments") or "",
                "working_directory": a.get("working_directory") or "",
                "class_id": class_id,
                "data": a.get("data") or "",
            })

        idx: dict[str, list] = {"by_task_name": [tname.lower()]}
        if execs:
            idx["by_path"] = execs
        # 31G-REG-TASK-RDP-FIELDS-INDEX-GUARD:
        # only emit index buckets known to EvidenceDB.INDEX_NAMES.
        if class_ids and "by_class_id" in INDEX_NAMES:
            idx["by_class_id"] = class_ids
        user_id = rec.get("user_id") or ""
        if user_id and "by_user" in INDEX_NAMES:
            idx["by_user"] = [str(user_id).lower()]

        task_path = rec.get("task_path") or tname
        yield i, {
            "fact_type": "scheduled_task_fact",
            "entity_id": task_path.lower(),
            "canonical_entity_id": f"task:{task_path.lower()}",
            "artifact": (
                tname.lower(), "|".join(execs),
                str(rec.get("enabled")), str(rec.get("hidden")),
                (rec.get("author") or "").lower(),
            ),
            "confidence_hint": "persistence_candidate",
            "index": idx,
            "fields": {
                "task_name": tname,
                "task_path": task_path,
                "source_path": rec.get("source_path") or "",
                "actions": execs,
                "action_details": action_details,
                "triggers": rec.get("triggers") or [],
                "enabled": rec.get("enabled"),
                "hidden": rec.get("hidden"),
                "author": rec.get("author") or "",
                "user_id": user_id,
                "run_level": rec.get("run_level") or "",
                "logon_type": rec.get("logon_type") or "",
                "created": rec.get("created") or "",
                "modified": rec.get("modified") or "",
                "description": rec.get("description") or "",
            },
        }, None


def _c_eventlog(records):
    for i, rec in enumerate(records):
        eid = rec.get("EventID")
        if eid is None:
            yield i, None, "missing_event_id"
            continue
        yield i, {
            "fact_type": "event_log_fact",
            "entity_id": str(eid),
            "artifact": (
                str(eid), rec.get("Provider", ""),
                rec.get("Channel", ""), _canon(rec.get("TimeCreated")),
                str(rec.get("Message", ""))[:160],
            ),
            "confidence_hint": "log_record",
            "index": {"by_event_id": [str(eid)]},
        }, None


def _c_svc(records):
    for i, rec in enumerate(records):
        name = rec.get("Name") or ""
        if not name:
            yield i, None, "missing_service_name"
            continue
        binary = normalize_path(rec.get("Binary"))
        pid = rec.get("PID")
        idx: dict[str, list] = {"by_service_name": [name.lower()]}
        if binary:
            idx["by_path"] = [binary]
        if pid not in (None, 0):
            idx["by_pid"] = [str(pid)]
        yield i, {
            "fact_type": "service_fact",
            "entity_id": name.lower(),
            "artifact": (
                name.lower(), binary, normalize_path(rec.get("Dll")),
                rec.get("State", ""), rec.get("Start", ""),
            ),
            "confidence_hint": "observed",
            "index": idx,
        }, None


def _c_netioc(records):
    for i, rec in enumerate(records):
        val = rec.get("value")
        if val in (None, ""):
            yield i, None, "missing_value"
            continue
        port = rec.get("port")
        idx: dict[str, list] = {}
        cip = normalize_ip(val)
        if cip:
            idx["by_ip"] = [cip]
        else:
            # A domain IOC (not an IP) must be host-queryable: index it
            # by_url_host so domain-keyed lookups + the DGA/staging matchers can
            # reach it. Strip any scheme/path/userinfo/port; require a
            # registrable domain shape (alphabetic TLD). Universal: host SHAPE.
            _host = str(val).strip().lower().split("://", 1)[-1]
            _host = _host.split("/", 1)[0].split("?", 1)[0]
            _host = _host.rsplit("@", 1)[-1].split(":", 1)[0].strip(".")
            if "." in _host and not _host.replace(".", "").isdigit():
                _tld = _host.rsplit(".", 1)[-1]
                if _tld.isalpha() and len(_tld) >= 2:
                    idx["by_url_host"] = [_host]
        if port not in (None, 0, "0"):
            idx["by_port"] = [str(port)]
        yield i, {
            "fact_type": "network_ioc_fact",
            "entity_id": str(val).lower(),
            "artifact": (
                rec.get("type", ""), str(val).lower(), str(port),
                rec.get("classification", ""),
            ),
            "confidence_hint": "ioc_candidate",
            "index": idx,
        }, None


def _c_rdp(records):
    """Compile RDP artifacts with structured fields.

    31G-REG-TASK-RDP-FIELDS: previous compiler stored most useful RDP
    content only in artifact/raw_excerpt and used weak entity IDs such as
    event number 21. Keep typed host/user/event/profile fields and indexes
    so candidate validation/report routing can reason over RDP evidence.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or not rec:
            yield i, None, "empty_record"
            continue

        record_type = str(rec.get("type") or rec.get("artifact_type") or "").strip()
        source_kind = str(rec.get("source_kind") or "").strip()
        extraction_method = str(rec.get("extraction_method") or "").strip()
        source_file = str(rec.get("source_file") or "").strip()
        record_id = str(rec.get("record_id") or "").strip()
        timestamp = str(rec.get("timestamp") or "").strip()
        event_id = rec.get("event_id")
        channel = str(rec.get("channel") or "").strip()
        provider = str(rec.get("provider") or "").strip()
        computer = str(rec.get("computer") or "").strip()
        user = str(rec.get("username") or rec.get("user") or "").strip()
        host_or_target = str(
            rec.get("host_or_target")
            or rec.get("remote_host")
            or rec.get("target")
            or rec.get("server")
            or rec.get("hostname")
            or ""
        ).strip()
        src_ip = str(rec.get("source_ip") or rec.get("client_ip") or "").strip()
        client = str(rec.get("client") or rec.get("client_name") or "").strip()

        idx: dict[str, list] = {}
        indexed_ips = []
        for ipish in (src_ip, host_or_target):
            nip = normalize_ip(ipish)
            if nip and nip not in indexed_ips:
                indexed_ips.append(nip)
        if indexed_ips:
            idx["by_ip"] = indexed_ips
        # 31G-REG-TASK-RDP-FIELDS-INDEX-GUARD:
        # host/user/event remain in fields even when no dedicated index exists.
        if host_or_target and "by_host" in INDEX_NAMES:
            idx["by_host"] = [host_or_target.lower()]
        if user and "by_user" in INDEX_NAMES:
            idx["by_user"] = [user.lower()]
        if event_id not in (None, "") and "by_event_id" in INDEX_NAMES:
            idx["by_event_id"] = [str(event_id)]
        source_path = normalize_path(source_file)
        if source_path:
            idx["by_path"] = [source_path]

        entity = (
            (indexed_ips[0] if indexed_ips else "")
            or host_or_target.lower()
            or user.lower()
            or record_id.lower()
            or (f"event:{event_id}" if event_id not in (None, "") else "")
            or "rdp"
        )

        scalars = tuple(
            f"{k}={v}" for k, v in sorted(rec.items())
            if isinstance(v, (str, int, float, bool))
        )
        yield i, {
            "fact_type": "rdp_artifact_fact",
            "entity_id": entity,
            "canonical_entity_id": f"rdp:{entity}",
            "artifact": scalars,
            "confidence_hint": "observed",
            "index": idx,
            "fields": {
                "record_type": record_type,
                "source_kind": source_kind,
                "extraction_method": extraction_method,
                "source_file": source_file,
                "record_id": record_id,
                "timestamp": timestamp,
                "event_id": event_id,
                "channel": channel,
                "provider": provider,
                "computer": computer,
                "user": user,
                "host_or_target": host_or_target,
                "source_ip": src_ip,
                "client": client,
                "raw_excerpt": rec.get("raw_excerpt") or "",
            },
        }, None


_PS_TTP_PATTERNS = [
    ("encoded_command",
     re.compile(r"-[Ee]nc(?:odedCommand)?\b[^\n]{0,40}\s+[A-Za-z0-9+/]{20,}={0,3}")),
    ("bypass_execution_policy",
     re.compile(r"-ExecutionPolicy\s+[Bb]ypass|-[Ee][Pp]\s+[Bb]ypass")),
    ("no_profile_hidden",
     re.compile(r"(?=.*-NoP(?:rofile)?\b)(?=.*-W(?:indowStyle)?\s+[Hh]idden)", re.IGNORECASE)),
    ("download_cradle",
     re.compile(r"(?:IEX|Invoke-Expression)[^\n]{0,80}(?:WebClient|Invoke-WebRequest|DownloadString|DownloadFile|Net\.WebClient)", re.IGNORECASE)),
    ("invoke_mimikatz",
     re.compile(r"[Ii]nvoke-?[Mm]imikatz|[Mm]imikatz\.ps1|sekurlsa::")),
    ("wmi_execution",
     re.compile(r"Invoke-WmiMethod|Get-WmiObject[^\n]{0,80}Win32_Process|Win32_Process[^\n]{0,40}Create", re.IGNORECASE)),
    ("ps_remoting_lateral",
     re.compile(r"Invoke-Command\s+-ComputerName\b|Enter-PSSession\b", re.IGNORECASE)),
    ("lsass_access",
     re.compile(r"lsass\.exe|MiniDump|procdump\b|sekurlsa", re.IGNORECASE)),
    ("reflection_load",
     re.compile(r"\[Reflection\.Assembly\]::Load|\[System\.Reflection\.Assembly\]::Load", re.IGNORECASE)),
    ("amsi_bypass",
     re.compile(r"AmsiUtils|amsiInitFailed|AmsiContext", re.IGNORECASE)),
    ("credential_harvest",
     re.compile(r"\bGet-Credential\b|ConvertTo-SecureString[^\n]{0,40}-AsPlainText", re.IGNORECASE)),
    ("long_base64_blob",
     re.compile(r"[A-Za-z0-9+/]{200,}={0,3}")),
]



_PS_CONTEXT_RE = re.compile(
    r"\bpowershell(?:\.exe)?\b|\bpwsh(?:\.exe)?\b|\.ps1\b|"
    r"\bIEX\b|Invoke-|EncodedCommand|FromBase64String|"
    r"New-Object\s+Net\.WebClient|Get-Credential|Enter-PSSession|"
    r"Invoke-Command|PSReadLine|ScriptBlock|ConsoleHost|Transcript|"
    r"Microsoft-Windows-PowerShell",
    re.IGNORECASE,
)

_PS_CONTEXT_REQUIRED_TTP_TAGS = {"long_base64_blob"}


def _ps_ttp_tags(haystack: str) -> list:
    """Match generic well-known PowerShell attacker TTPs against a text blob.

    Dataset-agnostic: patterns describe attacker techniques, not any specific
    dataset's IOCs, hashes, PIDs, paths, or domains.
    """
    if not haystack:
        return []
    hits = []
    for name, pat in _PS_TTP_PATTERNS:
        if pat.search(haystack):
            hits.append(name)
    return hits


def _c_powershell(records):
    """Generator: powershell_command_fact extractor.

    Source: parse_powershell_transcripts. Emits one fact per record only when
    the record has a strong PowerShell TTP tag, decoded command content, or
    PowerShell context plus a behavioral signal (TTP tag, marker, URL, domain,
    IP, or path). Generic application log field-only noise is dropped.
    Schema and entity_id are dataset-agnostic.
    """
    import os as _os
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield i, None, "not_a_dict"
            continue
        command = str(rec.get("command") or "")
        decoded = str(rec.get("decoded_command") or "")
        host_app = str(rec.get("host_application") or "")
        urls = list(rec.get("urls") or [])
        domains = list(rec.get("domains") or [])
        ips = list(rec.get("ips") or [])
        paths = list(rec.get("paths") or [])
        markers = list(rec.get("suspicious_markers") or [])
        haystack = " ".join([command, decoded, host_app, str(rec.get("raw_excerpt") or "")])
        ttp_tags = _ps_ttp_tags(haystack)
        src_file = str(rec.get("source_file") or "")
        ps_context = bool(_PS_CONTEXT_RE.search(haystack) or _PS_CONTEXT_RE.search(src_file))
        strong_ttp_tags = [tag for tag in ttp_tags if tag not in _PS_CONTEXT_REQUIRED_TTP_TAGS]
        field_signal = bool(urls or domains or ips or paths)
        # Noise filter: require actual PowerShell context or strong PowerShell TTP.
        has_signal = bool(strong_ttp_tags) or bool(decoded.strip()) or (
            ps_context and bool(ttp_tags or markers or field_signal)
        )
        if not has_signal:
            yield i, None, "no_powershell_signal_noise"
            continue
        src_file = str(rec.get("source_file") or "")
        line_no = rec.get("line_number")
        line_no_s = str(line_no) if line_no is not None else "?"
        entity_id = line_no_s + "::" + _os.path.basename(src_file)
        ts = _canon(rec.get("timestamp"))
        user = rec.get("user")
        user_s = str(user) if user else None
        raw = str(rec.get("raw_excerpt") or "")[:500]
        if len(ttp_tags) >= 2:
            conf_hint = "high"
        elif ttp_tags:
            conf_hint = "medium"
        else:
            conf_hint = "low"
        url_hosts = []
        for u in urls:
            try:
                u_s = str(u)
                if "://" in u_s:
                    host = u_s.split("://", 1)[1].split("/", 1)[0]
                    host = host.split(":", 1)[0]
                    if host:
                        url_hosts.append(host)
            except Exception:
                pass
        fact = {
            "fact_type": "powershell_command_fact",
            "entity_id": entity_id,
            "command": command[:500],
            "decoded_command": (decoded[:500] if decoded else None),
            "host_application": (host_app[:500] if host_app else None),
            "user": user_s,
            "timestamp": ts,
            "ttp_tags": ttp_tags,
            "urls": urls[:20],
            "domains": domains[:20],
            "ips": ips[:20],
            "paths": paths[:20],
            "suspicious_markers": markers[:20],
            "source_file": src_file,
            "raw_excerpt": raw,
            "artifact": (
                command[:160],
                decoded[:160] if decoded else "",
                host_app[:160] if host_app else "",
                user_s or "",
                ts or "",
                "|".join(ttp_tags),
                "|".join(url_hosts[:10]),
                "|".join(str(x) for x in ips[:10]),
                _os.path.basename(src_file),
            ),
            "fields": {
                "command": command[:500],
                "decoded_command": decoded[:500] if decoded else None,
                "host_application": host_app[:500] if host_app else None,
                "user": user_s,
                "timestamp": ts,
                "ttp_tags": list(ttp_tags),
                "urls": urls[:20],
                "domains": domains[:20],
                "ips": ips[:20],
                "paths": paths[:20],
                "suspicious_markers": markers[:20],
                "source_file": src_file,
                "confidence_hint": conf_hint,
            },
            "confidence_hint": conf_hint,
            "index": {
                "by_ttp_tag": list(ttp_tags),
                "by_user": ([user_s] if user_s else []),
                "by_timestamp_minute": ([timestamp_minute(ts)] if ts else []),
                "by_source_file_basename": ([_os.path.basename(src_file)] if src_file else []),
                "by_ip": list(ips)[:20],
                "by_url_host": list(set(url_hosts))[:20],
            },
        }
        yield i, fact, None



def _zero_contrib_signal_tags(value: str) -> list[str]:
    """Dataset-agnostic string signal tags for generic string sources."""
    import re as _re
    s = str(value or "")
    low = s.lower()
    tags: list[str] = []
    checks = [
        ("url", r"https?://"),
        ("loopback_or_internal_endpoint", r"\b127\.0\.0\.1\b|\blocalhost\b|\b10\.\d+\.\d+\.\d+\b|\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b|\b192\.168\.\d+\.\d+\b"),
        ("powershell", r"powershell|encodedcommand|\s-enc\b|frombase64string|downloadstring|\biex\b|invoke-webrequest|invoke-expression"),
        ("credential_access", r"lsass|pwdump|mimikatz|sekurlsa|procdump|comsvcs\.dll"),
        ("remote_admin_or_lateral", r"psexec|psexesvc|wmic|wsmprovhost|winrm|evil-winrm|remoting"),
        ("suspicious_windows_path", r"c:\\\\windows\\\\temp|c:/windows/temp|\\\\temp\\\\|/temp/|appdata\\\\roaming|users\\\\public"),
        ("script_or_executable", r"\.(exe|dll|ps1|bat|cmd|vbs|js|jse|scr|sys)\b"),
        ("encoded_or_b64_marker", r"[a-z0-9+/]{80,}={0,2}"),
    ]
    for tag, pat in checks:
        if _re.search(pat, low):
            tags.append(tag)
    return sorted(set(tags))


def _zero_contrib_hash_id(prefix: str, value: str) -> str:
    import hashlib as _hashlib
    return f"{prefix}:{_hashlib.sha1(str(value).encode('utf-8', errors='replace')).hexdigest()[:16]}"


def _c_strings(records):
    """Compile high-signal generic strings into string_artifact_fact.

    We intentionally do not ingest all strings output. Only strings with
    dataset-agnostic forensic signals are registered, preventing 5000 rows of
    low-value device IDs/noise from drowning EvidenceDB.
    """
    emitted = 0
    cap = 1000
    for i, rec in enumerate(records):
        if isinstance(rec, dict):
            value = rec.get("string") or rec.get("value") or rec.get("text") or rec.get("raw") or ""
        else:
            value = rec
        s = str(value or "").strip()
        if len(s) < 4:
            yield i, None, "string_too_short"
            continue
        tags = _zero_contrib_signal_tags(s)
        if not tags:
            yield i, None, "low_signal_string"
            continue
        if emitted >= cap:
            yield i, None, "string_fact_cap"
            continue
        emitted += 1
        entity = _zero_contrib_hash_id("string", s)
        fact = {
            "fact_type": "string_artifact_fact",
            "entity_id": entity,
            "string_value": s[:1000],
            "signal_tags": tags,
            "source": "run_strings",
            "raw_excerpt": s[:500],
            "artifact": (s[:240], "|".join(tags)),
            "fields": {
                "string_value": s[:1000],
                "signal_tags": tags,
                "confidence_hint": "medium" if len(tags) >= 2 else "low",
            },
            "confidence_hint": "medium" if len(tags) >= 2 else "low",
            "index": {
                "by_ttp_tag": tags,
            },
        }
        yield i, fact, None


def _c_decoded_strings(records):
    """Compile decoded base64/string observations into decoded_string_fact."""
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield i, None, "decoded_record_not_dict"
            continue
        decoded = str(
            rec.get("decoded")
            or rec.get("decoded_text")
            or rec.get("decoded_preview")
            or ""
        )
        original = str(rec.get("original") or rec.get("original_preview") or "")
        if not decoded.strip():
            yield i, None, "decoded_empty"
            continue
        keywords = [str(x).lower() for x in (rec.get("suspicious_keywords") or [])]
        tags = sorted(set(_zero_contrib_signal_tags(decoded) + keywords + ["decoded_string"]))
        conf = str(rec.get("confidence") or "").lower()
        if keywords or any(t for t in tags if t != "decoded_string"):
            hint = "high" if conf == "high" or len(tags) >= 3 else "medium"
        else:
            hint = "low"
        entity = _zero_contrib_hash_id("decoded", original + "::" + decoded)
        fact = {
            "fact_type": "decoded_string_fact",
            "entity_id": entity,
            "original_preview": original[:300],
            "decoded_preview": decoded[:1000],
            "encoding": rec.get("encoding"),
            "source_tool_ref": rec.get("source_tool"),
            "source_record": rec.get("source_record"),
            "signal_tags": tags,
            "suspicious_keywords": keywords,
            "raw_excerpt": str(rec)[:500],
            "artifact": (original[:160], decoded[:240], "|".join(tags)),
            "fields": {
                "original_preview": original[:300],
                "decoded_preview": decoded[:1000],
                "encoding": rec.get("encoding"),
                "signal_tags": tags,
                "suspicious_keywords": keywords,
                "confidence_hint": hint,
            },
            "confidence_hint": hint,
            "index": {
                "by_ttp_tag": tags,
            },
        }
        yield i, fact, None


def _c_yara(records):
    """Compile real YARA matches only. No rules/no matches emits no facts."""
    for i, rec in enumerate(records):
        if isinstance(rec, dict):
            rule = str(rec.get("rule") or rec.get("rule_name") or rec.get("match") or "")
            target = str(rec.get("target") or rec.get("path") or rec.get("file") or "")
            namespace = str(rec.get("namespace") or "")
            raw = str(rec)
        else:
            raw = str(rec)
            parts = raw.split()
            rule = parts[0] if parts else ""
            target = parts[-1] if len(parts) > 1 else ""
            namespace = ""
        if not rule.strip() and not raw.strip():
            yield i, None, "empty_yara_record"
            continue
        entity = _zero_contrib_hash_id("yara", rule + "::" + target + "::" + raw[:200])
        fact = {
            "fact_type": "yara_match_fact",
            "entity_id": entity,
            "rule": rule[:200],
            "target": target[:500],
            "namespace": namespace[:100],
            "raw_excerpt": raw[:500],
            "artifact": (rule[:200], target[:500], raw[:240]),
            "fields": {
                "rule": rule[:200],
                "target": target[:500],
                "namespace": namespace[:100],
                "confidence_hint": "low",
            },
            "confidence_hint": "low",  # 31K-REWEIGHT: yara value lowered (0 confirmed, FP-only)
            "index": {
                "by_path": ([target] if target else []),
            },
        }
        yield i, fact, None


def _c_sleuthkit_fls(records):
    """Compile SleuthKit fls rows when a real disk image is available."""
    for i, rec in enumerate(records):
        raw = rec if isinstance(rec, str) else str(rec)
        if isinstance(rec, dict):
            path = str(rec.get("path") or rec.get("name") or rec.get("file") or rec.get("filename") or "")
            inode = str(rec.get("inode") or rec.get("meta") or "")
            flags = str(rec.get("flags") or rec.get("type") or "")
        else:
            line = raw.strip()
            path = line.split("\t")[-1] if "\t" in line else line.split(":", 1)[-1].strip()
            inode = ""
            flags = line.split()[0] if line.split() else ""
        if not path:
            yield i, None, "fls_path_empty"
            continue
        entity = _zero_contrib_hash_id("fls", path)
        fact = {
            "fact_type": "filesystem_listing_fact",
            "entity_id": entity,
            "path": path[:500],
            "inode": inode[:80],
            "flags": flags[:80],
            "raw_excerpt": raw[:500],
            "artifact": (path[:500], inode[:80], flags[:80]),
            "fields": {
                "path": path[:500],
                "inode": inode[:80],
                "flags": flags[:80],
                "confidence_hint": "low",
            },
            "confidence_hint": "low",
            "index": {
                "by_path": [path[:500]],
            },
        }
        yield i, fact, None


def _c_sleuthkit_mactime(records):
    """Compile SleuthKit mactime rows when a body_file is available."""
    for i, rec in enumerate(records):
        raw = rec if isinstance(rec, str) else str(rec)
        if isinstance(rec, dict):
            path = str(rec.get("path") or rec.get("file") or rec.get("filename") or "")
            ts = _canon(rec.get("timestamp") or rec.get("time") or rec.get("date"))
            activity = str(rec.get("activity") or rec.get("event") or "")
        else:
            parts = raw.split("|")
            ts = parts[0].strip() if parts else ""
            path = parts[1].strip() if len(parts) > 1 else raw.strip()
            activity = parts[2].strip() if len(parts) > 2 else ""
        if not path:
            yield i, None, "mactime_path_empty"
            continue
        entity = _zero_contrib_hash_id("mactime", path + "::" + str(ts))
        fact = {
            "fact_type": "filesystem_timeline_fact",
            "entity_id": entity,
            "path": path[:500],
            "timestamp": ts,
            "activity": activity[:200],
            "raw_excerpt": raw[:500],
            "artifact": (path[:500], str(ts)[:80], activity[:200]),
            "fields": {
                "path": path[:500],
                "timestamp": ts,
                "activity": activity[:200],
                "confidence_hint": "medium" if ts else "low",
            },
            "confidence_hint": "medium" if ts else "low",
            "index": {
                "by_path": [path[:500]],
                "by_timestamp_minute": ([timestamp_minute(ts)] if ts else []),
            },
        }
        yield i, fact, None



def _c_vol_filescan(records):
    """Compile vol_filescan memory-resident file objects to filesystem_listing_fact.

    vol_filescan output records have shape:
        {"Name": "\\path", "Offset": int, "TreeDepth": int}
    These are file objects discovered in memory, which may be stale or already
    freed. Confidence is intentionally "low" to reflect this. Inode is encoded
    as the hex memory offset, flags is "memory_resident" to distinguish from
    on-disk SleuthKit fls entries.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield i, None, "vol_filescan_record_not_dict"
            continue
        path = str(rec.get("Name") or rec.get("name") or "")
        if not path:
            yield i, None, "vol_filescan_path_empty"
            continue
        offset = rec.get("Offset")
        try:
            inode = f"0x{int(offset):x}" if offset is not None else ""
        except (TypeError, ValueError):
            inode = str(offset) if offset is not None else ""
        flags = "memory_resident"
        try:
            raw = json.dumps(rec, default=str)
        except Exception:
            raw = str(rec)
        entity = _zero_contrib_hash_id("vol_filescan", path)
        fact = {
            "fact_type": "filesystem_listing_fact",
            "entity_id": entity,
            "path": path[:500],
            "inode": inode[:80],
            "flags": flags[:80],
            "raw_excerpt": raw[:500],
            "artifact": (path[:500], inode[:80], flags[:80]),
            "fields": {
                "path": path[:500],
                "inode": inode[:80],
                "flags": flags[:80],
                "source": "vol_filescan_memory",
                "confidence_hint": "low",
            },
            "confidence_hint": "low",
            "index": {
                "by_path": [path[:500]],
            },
        }
        yield i, fact, None


def _c_wmi_subscription(records):
    """Compile WMI subscription artifacts (filters, consumers, bindings).

    Per-instance identity: distinct subscriptions must not collapse into
    a single type-bucket. entity_key is derived from the REAL extractor
    fields emitted by parse_wmi_subscription (extracted_name, type,
    extracted_consumer_ref, plus a short hash of the payload), so two
    different ActiveScript consumers with different script bodies stay
    separate facts. raw_excerpt holds the verbatim parser record as JSON
    so downstream scorers (_parse_raw_excerpt) can read the typed
    extractor fields, which the storage layer strips from typed_facts.

    Dataset-agnostic: keys on generic WMI structural fields only. Never
    references specific consumer or filter names from any dataset.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        wmi_type = str(
            rec.get("type") or rec.get("record_type")
            or rec.get("wmi_type") or ""
        ).strip()
        # Prefer the real extractor field, then fall back to legacy keys.
        name = str(
            rec.get("extracted_name") or rec.get("name")
            or rec.get("consumer_name") or rec.get("filter_name")
            or rec.get("binding_name") or ""
        ).strip()
        consumer_ref = str(
            rec.get("extracted_consumer_ref") or rec.get("consumer_ref") or ""
        ).strip()
        filter_ref = str(
            rec.get("extracted_filter_ref") or rec.get("filter_ref") or ""
        ).strip()
        script_text = str(
            rec.get("extracted_script_text") or rec.get("script_text") or ""
        )
        script_filename = str(
            rec.get("extracted_script_filename") or rec.get("script_filename") or ""
        )
        command_template = str(
            rec.get("extracted_command_template")
            or rec.get("command_line_template")
            or rec.get("command_template") or ""
        )
        executable_path = str(
            rec.get("extracted_executable_path") or rec.get("executable_path") or ""
        )
        query = str(
            rec.get("extracted_query") or rec.get("query")
            or rec.get("query_language") or rec.get("event_query") or ""
        ).strip()
        namespace = str(
            rec.get("extracted_event_namespace") or rec.get("namespace")
            or rec.get("scope") or ""
        ).strip()
        source_file = str(
            rec.get("source_file") or rec.get("source") or ""
        ).strip()
        # Legacy aggregate "target" for the storage-stripped typed field.
        target_legacy = (
            command_template or script_text or executable_path
            or str(rec.get("target") or rec.get("template") or "")
        ).strip()
        # Payload hash discriminates two subscriptions that share name/type
        # but carry different bodies. Empty payload -> empty hash slot.
        payload_basis = "|".join((script_text, script_filename, command_template))
        payload_hash = (
            hashlib.sha1(payload_basis.encode("utf-8", "replace")).hexdigest()[:12]
            if payload_basis.strip() else ""
        )
        if not (wmi_type or name or query or target_legacy or consumer_ref or filter_ref):
            yield i, None, "empty_wmi_record"
            continue
        entity_key = "::".join((
            wmi_type, name, consumer_ref, filter_ref, payload_hash,
        ))
        entity = _zero_contrib_hash_id("wmi", entity_key)
        canonical = (
            f"wmi:{wmi_type}:{name}:{payload_hash}" if name and payload_hash else
            f"wmi:{wmi_type}:{name}" if name else
            f"wmi:{wmi_type}:{consumer_ref}" if consumer_ref else
            f"wmi:{wmi_type}" if wmi_type else
            f"wmi:{entity[:16]}"
        )
        # Preserve the verbatim parser record as JSON so scorers can read
        # extracted_* fields via _parse_raw_excerpt. Storage strips typed
        # fields from facts; raw_excerpt is the structural source-of-truth.
        try:
            raw_json = json.dumps(rec, ensure_ascii=False, default=str)[:4000]
        except (TypeError, ValueError):
            raw_json = str(rec)[:4000]
        fact = {
            "fact_type": "wmi_subscription_fact",
            "entity_id": entity,
            "canonical_entity_id": canonical,
            "wmi_type": wmi_type[:100],
            "name": name[:200],
            "query": query[:500],
            "target": target_legacy[:500],
            "namespace": namespace[:100],
            "source_file": source_file[:500],
            "raw_excerpt": raw_json,
            "artifact": (wmi_type[:100], name[:200], (payload_hash or consumer_ref or target_legacy[:200])),
        }
        yield i, fact, None



def _c_bulk_extractor(records):
    # 31G-BULK-SAMPLES
    """Compile bulk_extractor's single summary record to ONE
    ioc_carve_summary_fact.

    bulk_extractor is a summary-only tool: it emits exactly one record
    per run carrying feature counts (emails / urls / domains /
    carved_feature_total). The emitted fact stores those counts as
    metadata only - no entity key, no PID, IP, path, hash, registry,
    or URL fields. _entity_keys falls back to the artifact tag and
    _score_fact has no branch for this fact_type, so the fact never
    contributes to candidate generation (supporting list stays empty
    and the candidate is dropped by the empty-supporting guard).

    Reconciles by construction: record_count(1) == compiled(1) +
    dropped(0). Registering this compiler removes the silent-drop
    coverage-gate violation for run_bulk_extractor without weakening
    the gate for any other tool.

    Dataset-agnostic: keys on the summary record's count fields only;
    never references specific carved values or evidence paths.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield i, None, "non_dict_record"
            continue
        try:
            emails = int(rec.get("emails") or 0)
        except (TypeError, ValueError):
            emails = 0
        try:
            urls = int(rec.get("urls") or 0)
        except (TypeError, ValueError):
            urls = 0
        try:
            domains = int(rec.get("domains") or 0)
        except (TypeError, ValueError):
            domains = 0
        try:
            total = int(rec.get("carved_feature_total")
                        if rec.get("carved_feature_total") is not None
                        else (emails + urls + domains))
        except (TypeError, ValueError):
            total = emails + urls + domains
        # 31G-BULK-SAMPLES: preserve bounded samples as summary metadata.
        # This remains one ioc_carve_summary_fact; samples are not expanded
        # into per-feature facts here.
        def _bounded_sample_list(name: str, limit: int) -> list[str]:
            raw = rec.get(name) or []
            if not isinstance(raw, list):
                return []
            out: list[str] = []
            seen: set[str] = set()
            for item in raw:
                value = str(item or "").replace("\x00", "")
                value = "".join(ch for ch in value if ch.isprintable()).strip()
                if not value:
                    continue
                value = value[:500]
                if value in seen:
                    continue
                seen.add(value)
                out.append(value)
                if len(out) >= limit:
                    break
            return out

        emails_sample = _bounded_sample_list("emails_sample", 10)
        urls_sample = _bounded_sample_list("urls_sample", 25)
        domains_sample = _bounded_sample_list("domains_sample", 25)

        # raw_excerpt holds the structural counts only - NOT the carved
        # text - so no URL/IP literals leak into _entity_keys.
        raw_json = json.dumps({
            "emails": emails, "urls": urls,
            "domains": domains, "carved_feature_total": total,
        })
        fact = {
            "fact_type": "ioc_carve_summary_fact",
            # No entity_id: the fact is a tool-level summary, not an
            # observable artifact. canonical_entity_id is constant so
            # re-runs merge to one signature.
            "entity_id": "",
            "canonical_entity_id": "bulk_extractor:summary",
            "raw_excerpt": raw_json,
            "artifact": ("bulk_extractor_summary",),
            "confidence_hint": "summary",
            # build_typed_evidence_db copies entries from `fields` onto
            # the stored fact_obj; top-level keys are dropped.
            "fields": {
                "emails": emails,
                "urls": urls,
                "domains": domains,
                "carved_feature_total": total,
                "emails_sample": emails_sample,
                "urls_sample": urls_sample,
                "domains_sample": domains_sample,
            },
        }
        yield i, fact, None


def _c_sleuthkit_tsk_recover(records):
    """Compile tsk_recover recovered-file inventory.

    The SleuthKit tool writes files into an output directory. The runtime
    wrapper converts those files into inventory records. Reuse the existing
    filesystem_listing_fact family so recovered artifacts become typed,
    searchable, and validator-visible without adding a new claim type.
    """
    for i, rec in enumerate(records):
        if isinstance(rec, dict):
            path = str(
                rec.get("path")
                or rec.get("relative_path")
                or rec.get("name")
                or rec.get("recovered_path")
                or ""
            ).strip()
            recovered_path = str(rec.get("recovered_path") or "").strip()
            name = str(rec.get("name") or path.rsplit("/", 1)[-1]).strip()
            sha256 = str(rec.get("sha256") or "").strip().lower()
            size = rec.get("size")
            raw = json.dumps(rec, sort_keys=True, default=str)
        else:
            raw = str(rec)
            path = raw.strip()
            recovered_path = ""
            name = path.rsplit("/", 1)[-1]
            sha256 = ""
            size = None

        if not path:
            yield i, None, "tsk_recover_path_empty"
            continue

        entity_key = "::".join([
            path.lower(),
            sha256 if sha256 else "",
            str(size) if size is not None else "",
        ])
        entity = _zero_contrib_hash_id("tsk_recover", entity_key)
        by_hash = [sha256] if sha256 else []
        by_path = [path]
        if recovered_path:
            by_path.append(recovered_path)

        fact = {
            "fact_type": "filesystem_listing_fact",
            "entity_id": entity,
            "path": path[:500],
            "recovered_path": recovered_path[:500],
            "name": name[:240],
            "size": size,
            "sha256": sha256[:64],
            "flags": "recovered",
            "raw_excerpt": raw[:500],
            "artifact": (path[:500], sha256[:64], "recovered"),
            "fields": {
                "path": path[:500],
                "recovered_path": recovered_path[:500],
                "name": name[:240],
                "size": size,
                "sha256": sha256[:64],
                "flags": "recovered",
                "confidence_hint": "low",
            },
            "confidence_hint": "low",
            "index": {
                "by_path": by_path,
                "by_hash": by_hash,
            },
        }
        yield i, fact, None




def _c_srumecmd(records):
    """31K-SRUM-TYPED-VALIDATOR: SrumECmd CSV rows -> srum_usage_fact.

    SRUM is aggregate application/user/resource/network usage telemetry from
    SRUDB.dat. It is NOT process-creation proof, NOT command-line proof, and
    NOT destination-IP proof unless the row itself carries that field and a
    later claim specifically validates SRUM usage. Deliberately does not
    register by_path so generic path claims cannot be upgraded to execution
    evidence through SRUM alone.
    """
    import re as _re

    def _pick(rec, *keys):
        low = {str(k).strip().lower(): v for k, v in rec.items()}
        for key in keys:
            if key in rec and rec.get(key) not in (None, ""):
                return rec.get(key)
            lk = str(key).strip().lower()
            if lk in low and low[lk] not in (None, ""):
                return low[lk]
        return ""

    def _int0(value):
        try:
            s = str(value if value is not None else "").replace(",", "").strip()
            if not s:
                return 0
            return int(float(s))
        except Exception:
            return 0

    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or not rec:
            yield i, None, "empty_record"
            continue
        if str(rec.get("status") or "").startswith("complete"):
            yield i, None, "status_stub_no_srum_row"
            continue
        if rec.get("_csv_read_error"):
            yield i, None, "csv_read_error"
            continue

        table = str(
            _pick(rec, "_srum_table", "Table", "table", "TableName", "Name")
            or ""
        ).strip()

        app_raw = str(_pick(
            rec,
            "Application", "ApplicationName", "App", "AppName", "AppId",
            "ImageName", "Path", "FileName", "Executable", "Exe",
            "Application Path", "ApplicationPath", "FullPath",
        ) or "").strip()

        # Normalize only path-like application values. Some SRUM rows carry
        # package/app IDs rather than paths; keep those as application labels.
        path_like = bool(
            _re.search(r"[\\/]", app_raw)
            or _re.search(r"\.[A-Za-z0-9]{2,5}($|\\s)", app_raw)
        )
        normalized_path = normalize_path(app_raw) if path_like else ""

        user = str(_pick(
            rec, "UserName", "Username", "User", "UserId", "User ID"
        ) or "").strip()
        sid = str(_pick(
            rec, "UserSid", "UserSID", "SID", "Sid"
        ) or "").strip()

        timestamp = normalize_timestamp(_pick(
            rec,
            "Timestamp", "TimeStamp", "StartTime", "EndTime",
            "Time", "EventTime", "LastModified", "LastModifiedTimeUTC",
        ) or "")
        ts_min = timestamp_minute(timestamp) if timestamp else ""

        bytes_sent = _int0(_pick(
            rec, "BytesSent", "Bytes Sent", "SentBytes", "SendBytes",
            "BytesOut", "Bytes Out", "TxBytes", "BytesTransmitted",
        ))
        bytes_received = _int0(_pick(
            rec, "BytesReceived", "Bytes Received", "ReceivedBytes",
            "RecvBytes", "BytesIn", "Bytes In", "RxBytes",
        ))
        bytes_total = _int0(_pick(
            rec, "BytesTotal", "Bytes Total", "TotalBytes", "Total Bytes",
            "Bytes", "Total",
        ))
        if bytes_total <= 0:
            bytes_total = bytes_sent + bytes_received

        remote_raw = str(_pick(
            rec,
            "RemoteIP", "RemoteIp", "DestinationIP", "DestinationIp",
            "IPAddress", "IpAddress", "Address", "RemoteAddress",
            "DestinationAddress",
        ) or "").strip()
        remote_ip = normalize_ip(remote_raw) or ""

        source_file = str(_pick(
            rec, "SourceFile", "source_file", "_srum_csv"
        ) or "").strip()

        if not (table or app_raw or user or sid or timestamp or bytes_total):
            yield i, None, "missing_srum_identity"
            continue

        entity = (
            normalized_path
            or app_raw.lower()
            or sid.lower()
            or user.lower()
            or table.lower()
            or f"srum_row_{i}"
        )

        idx: dict[str, list] = {}
        # Intentional: no by_path. SRUM path-like values are validated only
        # through claim type srum_usage, not generic path passthrough.
        user_keys = []
        if user:
            user_keys.append(user.lower())
        if sid:
            user_keys.append(sid.lower())
        if user_keys:
            idx["by_user"] = sorted(set(user_keys))
        if remote_ip:
            idx["by_ip"] = [remote_ip]
        if ts_min:
            idx["by_timestamp_minute"] = [ts_min]

        base = source_file.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] if source_file else ""
        if base:
            idx["by_source_file_basename"] = [base.lower()]

        scalars = tuple(
            f"{k}={v}" for k, v in sorted(rec.items())
            if isinstance(v, (str, int, float, bool)) and str(v).strip()
        )

        yield i, {
            "fact_type": "srum_usage_fact",
            "entity_id": entity,
            "canonical_entity_id": f"srum:{entity}",
            "artifact": (
                table[:120],
                (normalized_path or app_raw)[:240],
                (user or sid)[:120],
                ts_min,
                str(bytes_total),
                base,
            ),
            "confidence_hint": "srum_usage_telemetry",
            "index": idx,
            "fields": {
                "table": table,
                "application": app_raw,
                "application_path": app_raw,
                "normalized_path": normalized_path,
                "user": user,
                "sid": sid,
                "timestamp": timestamp,
                "timestamp_minute": ts_min,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "bytes_total": bytes_total,
                "remote_ip": remote_ip,
                "remote_ip_raw": remote_raw,
                "source_file": source_file,
            },
        }, None


def _c_appcompatcacheparser(records):
    """31K-APPCOMPAT-TYPED-CANDIDATE: AppCompatCache/ShimCache CSV -> typed facts.

    AppCompatCache is execution-compatibility evidence, not a precise process
    creation log. Preserve the real parser fields and index paths so validator
    path/artifact claims can ground to the SYSTEM hive output.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or not rec:
            yield i, None, "empty_record"
            continue
        if rec.get("status", "").startswith("complete"):
            yield i, None, "status_stub_no_appcompat_row"
            continue

        raw_path = str(rec.get("Path") or rec.get("path") or "").strip()
        if not raw_path:
            yield i, None, "missing_path"
            continue

        normalized_path = normalize_path(raw_path)
        path_variants = []
        if normalized_path:
            path_variants.append(normalized_path)

        # Zimmerman AppCompatCache output often uses SYSVOL\... rather than
        # C:\...; index both forms so validator path claims can match either.
        sysvol_prefix = "sysvol/"
        if normalized_path.lower().startswith(sysvol_prefix):
            expanded = normalize_path("C:/" + normalized_path[len(sysvol_prefix):])
            if expanded and expanded not in path_variants:
                path_variants.append(expanded)
        else:
            expanded = ""

        control_set = str(rec.get("ControlSet") or rec.get("control_set") or "").strip()
        entry_pos = str(
            rec.get("CacheEntryPosition")
            or rec.get("EntryPosition")
            or rec.get("cache_entry_position")
            or ""
        ).strip()
        last_modified = normalize_timestamp(
            rec.get("LastModifiedTimeUTC")
            or rec.get("LastModified")
            or rec.get("LastModifiedUTC")
            or ""
        )
        executed_raw = str(rec.get("Executed") or rec.get("executed") or "").strip()
        executed_bool = executed_raw.lower() in {"yes", "true", "1"}
        duplicate_raw = str(rec.get("Duplicate") or rec.get("duplicate") or "").strip()
        duplicate_bool = duplicate_raw.lower() in {"yes", "true", "1"}
        source_file = str(rec.get("SourceFile") or rec.get("source_file") or "").strip()

        entity = path_variants[0] if path_variants else raw_path.lower()
        idx: dict[str, list] = {}
        if path_variants:
            idx["by_path"] = path_variants

        scalars = tuple(
            f"{k}={v}" for k, v in sorted(rec.items())
            if isinstance(v, (str, int, float, bool)) and str(v).strip()
        )

        yield i, {
            "fact_type": "appcompatcache_execution_fact",
            "entity_id": entity,
            "canonical_entity_id": f"appcompatcache:{entity}",
            "artifact": scalars,
            "confidence_hint": "execution_compatibility_artifact",
            "index": idx,
            "fields": {
                "path": raw_path,
                "normalized_path": normalized_path,
                "expanded_path": expanded,
                "path_variants": path_variants,
                "control_set": control_set,
                "cache_entry_position": entry_pos,
                "last_modified_utc": last_modified,
                "executed": executed_bool,
                "executed_raw": executed_raw,
                "duplicate": duplicate_bool,
                "source_file": source_file,
            },
        }, None


def _c_lnk(records):
    """31K-LNK-WIRE: LECmd LNK shortcut -> typed lnk_execution_fact.

    Per-user/per-target execution provenance. Reads REAL captured columns
    (LocalPath/TargetIDAbsolutePath/Arguments/WorkingDirectory/
    VolumeSerialNumber/MachineID + Source/Target MAC times). Literal-free:
    only the run's own values appear. Scoring/suppression land in a later slot.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or not rec:
            yield i, None, "empty_record"
            continue
        if rec.get("status", "").startswith("complete"):
            yield i, None, "status_stub_no_lnk_row"
            continue
        local_path = normalize_path(rec.get("LocalPath") or rec.get("TargetIDAbsolutePath") or "")
        target_abs = normalize_path(rec.get("TargetIDAbsolutePath") or "")
        arguments = str(rec.get("Arguments") or "").strip()
        working_dir = normalize_path(rec.get("WorkingDirectory") or "")
        source_file = str(rec.get("SourceFile") or "").strip()
        machine_id = str(rec.get("MachineID") or "").strip()
        volume_serial = str(rec.get("VolumeSerialNumber") or "").strip()
        target_modified = str(rec.get("TargetModified") or "").strip()
        source_modified = str(rec.get("SourceModified") or "").strip()
        entity = (local_path or target_abs or source_file or "lnk").lower()
        idx: dict[str, list] = {}
        for p in (local_path, target_abs):
            if p:
                idx.setdefault("by_path", [])
                if p not in idx["by_path"]:
                    idx["by_path"].append(p)
        base = source_file.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] if source_file else ""  # 31K-LNK-WIRE: module-scope safe (no os; matches rsplit idiom at 1437/1445)
        if base:
            idx["by_source_file_basename"] = [base.lower()]
        scalars = tuple(
            f"{k}={v}" for k, v in sorted(rec.items())
            if isinstance(v, (str, int, float, bool)) and str(v).strip()
        )
        yield i, {
            "fact_type": "lnk_execution_fact",
            "entity_id": entity,
            "canonical_entity_id": f"lnk:{entity}",
            "artifact": scalars,
            "confidence_hint": "observed",
            "index": idx,
            "fields": {
                "local_path": local_path,
                "target_abs_path": target_abs,
                "arguments": arguments,
                "working_directory": working_dir,
                "source_file": source_file,
                "machine_id": machine_id,
                "volume_serial": volume_serial,
                "target_modified": target_modified,
                "source_modified": source_modified,
            },
        }, None


def _c_jumplist(records):
    """31K-LNK-WIRE: JLECmd Jump List -> typed jumplist_fact.

    Per-application access history. Columns are JLECmd's DOCUMENTED schema
    (AppId/AppIdDescription/Path/Arguments/EntryNumber + MAC times); flagged
    pending-real-data until a live run writes jumplists.csv. Literal-free.
    """
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or not rec:
            yield i, None, "empty_record"
            continue
        if rec.get("status", "").startswith("complete"):
            yield i, None, "status_stub_no_jumplist_row"
            continue
        path = normalize_path(rec.get("Path") or rec.get("LocalPath") or "")
        arguments = str(rec.get("Arguments") or "").strip()
        app_id = str(rec.get("AppId") or rec.get("AppID") or "").strip()
        app_desc = str(rec.get("AppIdDescription") or rec.get("MacRobertsExpanded") or "").strip()
        source_file = str(rec.get("SourceFile") or "").strip()
        entry_no = str(rec.get("EntryNumber") or "").strip()
        last_modified = str(rec.get("LastModified") or rec.get("TargetModified") or "").strip()
        entity = (path or f"{app_id}:{entry_no}" or source_file or "jumplist").lower()
        idx: dict[str, list] = {}
        if path:
            idx["by_path"] = [path]
        base = source_file.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] if source_file else ""  # 31K-LNK-WIRE: module-scope safe (no os; matches rsplit idiom at 1437/1445)
        if base:
            idx["by_source_file_basename"] = [base.lower()]
        scalars = tuple(
            f"{k}={v}" for k, v in sorted(rec.items())
            if isinstance(v, (str, int, float, bool)) and str(v).strip()
        )
        yield i, {
            "fact_type": "jumplist_fact",
            "entity_id": entity,
            "canonical_entity_id": f"jumplist:{entity}",
            "artifact": scalars,
            "confidence_hint": "observed",
            "index": idx,
            "fields": {
                "path": path,
                "arguments": arguments,
                "app_id": app_id,
                "app_description": app_desc,
                "source_file": source_file,
                "entry_number": entry_no,
                "last_modified": last_modified,
            },
        }, None




def _mftecmd_records(obj):
    """Normalize MFTECmd/EZTools output shapes into row dicts.

    Dataset-agnostic: accepts list rows, wrapped records/entries/events/rows,
    or a single row dict. Does not depend on case-specific paths or values.
    """
    if obj is None:
        return []

    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        mft_markers = {
            "EntryNumber", "Entry Number", "MFTEntry", "RecordNumber",
            "Record Number", "FileName", "Filename", "ParentPath",
            "Parent Path", "Created0x10", "LastModified0x10",
            "LastAccess0x10", "SequenceNumber", "Sequence Number",
        }
        if any(k in obj for k in mft_markers):
            return [obj]

        for key in ("records", "entries", "events", "rows", "data", "results", "output"):
            val = obj.get(key)
            if isinstance(val, list):
                return val
            if isinstance(val, dict):
                got = _mftecmd_records(val)
                if got:
                    return got

        for val in obj.values():
            if isinstance(val, (dict, list)):
                got = _mftecmd_records(val)
                if got:
                    return got

    return []

def _mftecmd_first(rec, *names):
    """Case-insensitive field lookup for MFTECmd/EZTools CSV-style rows."""
    if not isinstance(rec, dict):
        return ""
    norm = {}
    for key, value in rec.items():
        nk = "".join(ch for ch in str(key).lower() if ch.isalnum())
        norm[nk] = value
    for name in names:
        nk = "".join(ch for ch in str(name).lower() if ch.isalnum())
        value = norm.get(nk)
        if value is not None and str(value).strip():
            return value
    return ""


def _mftecmd_row_locator(rec):
    """Stable artifact locator for rows that do not expose a full path."""
    import hashlib
    import json

    entry = _mftecmd_first(
        rec,
        "EntryNumber", "Entry Number", "MFTEntry", "RecordNumber",
        "Record Number", "Entry", "Inode",
    )
    seq = _mftecmd_first(
        rec,
        "SequenceNumber", "Sequence Number", "Seq", "Sequence",
    )
    name = _mftecmd_first(
        rec,
        "FileName", "Filename", "Name", "File Name", "File", "BaseName",
    )

    pieces = [str(x).strip() for x in (entry, seq, name) if str(x).strip()]
    if pieces:
        return "mftecmd:" + ":".join(pieces)

    raw = json.dumps(rec, sort_keys=True, default=str)
    digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
    return "mftecmd:row:" + digest


def _mftecmd_pathish(rec):
    """Return a traceable path/name/locator without inventing case content."""
    path = _mftecmd_first(
        rec,
        "Path", "FullPath", "Full Path", "FilePath", "File Path",
        "SourceFile", "Source File", "TargetFilename", "Target Filename",
        "LongName", "Long Name",
    )
    if path:
        return str(path), "path"

    parent = _mftecmd_first(
        rec,
        "ParentPath", "Parent Path", "Directory", "Folder", "FolderPath",
        "VolumePath", "Volume Path",
    )
    name = _mftecmd_first(
        rec,
        "FileName", "Filename", "Name", "File Name", "File", "BaseName",
    )
    if parent and name:
        return str(parent).rstrip("\\/") + "/" + str(name).lstrip("\\/"), "derived_path"
    if name:
        return str(name), "name_only"

    return _mftecmd_row_locator(rec), "row_locator"


def _mftecmd_first_timestamp(rec):
    return _mftecmd_first(
        rec,
        "LastModified0x10", "Last Modified 0x10", "Modified0x10",
        "Created0x10", "Created 0x10",
        "LastRecordChange0x10", "Last Record Change 0x10",
        "LastAccess0x10", "Last Access 0x10",
        "LastModified0x30", "Created0x30",
        "Modified", "Created", "LastModified", "LastAccess",
        "Timestamp", "Time", "Date",
    )


def _c_mftecmd(records):
    """Compile MFTECmd output into traceable filesystem timeline facts.

    EvidenceDB compiler protocol:
        yield (record_index, fact_spec_or_none, drop_reason_or_none)

    Dataset-agnostic behavior:
    - full paths are used when present;
    - otherwise filenames or stable MFT row locators are used;
    - no case-specific paths, hosts, IPs, users, or expected findings.
    """
    for rec_i, rec in enumerate(_mftecmd_records(records)):
        if not isinstance(rec, dict):
            yield rec_i, None, "non_dict_record"
            continue

        pathish, path_kind = _mftecmd_pathish(rec)
        if not pathish:
            yield rec_i, None, "missing_locator"
            continue

        entry = _mftecmd_first(
            rec,
            "EntryNumber", "Entry Number", "MFTEntry", "RecordNumber",
            "Record Number", "Entry", "Inode",
        )
        seq = _mftecmd_first(rec, "SequenceNumber", "Sequence Number", "Seq")
        filename = _mftecmd_first(
            rec,
            "FileName", "Filename", "Name", "File Name", "File", "BaseName",
        )
        ts = _mftecmd_first_timestamp(rec)
        action = _mftecmd_first(
            rec,
            "Action", "Event", "Type", "UpdateType", "Reason",
        ) or "mft_record"

        fact = {
            "fact_type": "filesystem_timeline_fact",
            "source": "mftecmd",
            "source_tool": "run_mftecmd",
            "source_tools": ["run_mftecmd"],
            "entity_id": str(pathish),
            "artifact": str(pathish),
            "canonical_entity_id": str(pathish).lower(),
            "path": str(pathish),
            "path_kind": path_kind,
            "filename": str(filename or ""),
            "timestamp": str(ts or ""),
            "ts": str(ts or ""),
            "action": str(action),
            "mft_entry_number": str(entry or ""),
            "sequence_number": str(seq or ""),
            "artifact_locator": _mftecmd_row_locator(rec),
            "confidence_hint": (
                "filesystem_timeline_mftecmd"
                if path_kind in {"path", "derived_path"}
                else "filesystem_timeline_mftecmd_locator"
            ),
        }
        yield rec_i, fact, None



def _c_prefetch(records):
    """Compile Prefetch records into file execution facts.

    Dataset-agnostic: uses only fields emitted by the parser.
    """
    for i, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield i, None, "not_a_dict"
            continue

        exe = (
            rec.get("ExecutableName")
            or rec.get("executable")
            or rec.get("filename")
            or rec.get("FileName")
            or rec.get("name")
            or ""
        )
        path = rec.get("Path") or rec.get("path") or exe
        if not path and not exe:
            yield i, None, "missing_prefetch_executable"
            continue

        np = normalize_path(path or exe)
        run_count = rec.get("RunCount") or rec.get("run_count") or ""
        last_run = (
            rec.get("LastRun")
            or rec.get("last_run")
            or rec.get("LastRunTime")
            or rec.get("last_run_time")
            or ""
        )

        yield i, {
            "fact_type": "file_execution_fact",
            "entity_id": np or str(exe),
            "canonical_entity_id": f"path:{np}" if np else f"file:{exe}",
            "artifact": (np or str(exe), "prefetch", str(last_run), str(run_count)),
            "confidence_hint": "prefetch_execution",
            "index": {"by_path": [np]} if np else {},
            "fields": {
                "path": path,
                "normalized_path": np,
                "filename": str(exe),
                "execution_source": "prefetch",
                "run_count": run_count,
                "last_run_time": normalize_timestamp(last_run),
                "source": "prefetch",
            },
        }, None


_TOOL_COMPILERS = {
    "vol_pstree": _c_process,
    "vol_psscan": _c_process,
    "vol_netscan": _c_netconn,
    "vol_malfind": _c_malfind,
    "vol_ldrmodules": _c_ldrmodules,  # unbacked module -> memory_injection_fact (T1055)
    "get_amcache": _c_amcache,
    "parse_prefetch": _c_prefetch,
    "extract_mft_timeline": _c_mft,
    "run_mftecmd": _c_mftecmd,  # dataset-agnostic MFTECmd/MFT timeline compiler coverage
    "parse_registry_persistence": _c_registry,
    "parse_usb_devices": _c_usb,  # USB-WIRE: removable-media device facts
    "parse_scheduled_tasks_disk": _c_sched,
    "parse_event_logs": _c_eventlog,
    "parse_powershell_transcripts": _c_powershell,
    "vol_svcscan": _c_svc,
    "extract_network_iocs": _c_netioc,
    "decode_base64_strings": _c_decoded_strings,
    "run_strings": _c_strings,
    "run_yara": _c_yara,
    "sleuthkit_fls": _c_sleuthkit_fls,
    "sleuthkit_tsk_recover": _c_sleuthkit_tsk_recover,
    "sleuthkit_mactime": _c_sleuthkit_mactime,

    "vol_filescan": _c_vol_filescan,
    "parse_rdp_artifacts": _c_rdp,
    "parse_wmi_subscription": _c_wmi_subscription,
    "run_bulk_extractor": _c_bulk_extractor,
    "run_srumecmd": _c_srumecmd,  # 31K-SRUM-TYPED-VALIDATOR
    "run_appcompatcacheparser": _c_appcompatcacheparser,  # 31K-APPCOMPAT-TYPED-CANDIDATE
    "run_lecmd": _c_lnk,  # 31K-LNK-WIRE
    "run_jlecmd": _c_jumplist,  # 31K-LNK-WIRE
}




def _legacy_passthrough(reference_set: dict | None) -> dict:
    """JSON-safe copy of the legacy reference set (sets -> sorted lists)."""
    if not isinstance(reference_set, dict):
        return {}
    safe: dict = {}
    for k, v in reference_set.items():
        if isinstance(v, set):
            safe[k] = sorted(str(x) for x in v)
        else:
            safe[k] = v
    return safe


_CEID_PID_RE = re.compile(r"(?:^|[:|])pid:(\d+)(?=[:|]|$)")
_CEID_IP_RE = re.compile(
    r"(?:^|[:|])(?:ip|peer|addr|remote|foreign):((?:\d{1,3}\.){3}\d{1,3})(?=[:|]|$)")


def _ceid_entity_indexes(ceid: str) -> dict:
    """Universal entity-index backfill: extract the OS-primitive entities a
    canonical_entity_id ALREADY encodes (pid:N, ip:X) so EVERY family becomes
    queryable by_pid / by_ip even when its compiler declared no entity index
    (privilege/handle/session/sid). Keys only on the system's own canonical
    encoding -- no per-family code, no case/tool/IP literals baked in. Returns
    {index_name: [keys]}; empty when the id encodes no such entity."""
    s = str(ceid or "").lower()
    out: dict[str, list] = {}
    pids = _CEID_PID_RE.findall(s)
    if pids:
        out["by_pid"] = sorted(set(pids))
    ips = _CEID_IP_RE.findall(s)
    if ips:
        out["by_ip"] = sorted(set(ips))
    return out


def _redundant_mft_to_skip(tool_outputs: dict) -> set:
    """Step-7 speed: extract_mft_timeline (Vol3 memory MFT) and run_mftecmd
    (MFTECmd disk $MFT) parse the SAME $MFT. Compiling BOTH doubles MFT path
    facts to ~100K and drives the by_path index inserts O(n^2) (a 225s vs 9s
    build). When run_mftecmd is present and healthy, skip the redundant
    extract_mft_timeline COMPILE (its raw output still feeds the timeline /
    candidates). Memory-only runs (no run_mftecmd) keep extract_mft_timeline.
    Universal: redundant-artifact dedup by tool identity. Kill-switch
    SIFT_DEDUP_MFT_COMPILE=0."""
    if os.environ.get("SIFT_DEDUP_MFT_COMPILE", "1") == "0":
        return set()
    em = tool_outputs.get("run_mftecmd")
    if em is not None and not _is_error_envelope(em) and "extract_mft_timeline" in tool_outputs:
        return {"extract_mft_timeline"}
    return set()


def build_typed_evidence_db(tool_outputs: dict,
                            reference_set: dict | None = None) -> dict:
    """Compile typed forensic facts from rich tool_outputs.

    Pure function: deterministic, no I/O, no network, no fabrication.
    """
    _skip_mft = _redundant_mft_to_skip(tool_outputs or {})
    typed_facts: dict[str, list] = {ft: [] for ft in FACT_TYPES}
    indexes: dict[str, dict] = {name: {} for name in INDEX_NAMES}
    coverage: dict[str, dict] = {}

    # signature -> the canonical fact object (merge target, not discard)
    sig_to_fact: dict[str, dict] = {}
    fact_counter: dict[str, int] = {ft: 0 for ft in FACT_TYPES}
    _RAW_EXCERPT_LIST_CAP = 3
    # Provenance refs per fact are CAPPED (default 64; 0 = uncapped). A fact
    # merged thousands of times (common handles/events) otherwise accumulates
    # tens of KB of record_refs -- bloating the sidecar to 100s of MB.
    # merge_count always carries the TRUE count; provenance_truncated makes the
    # cap honest (same pattern as the raw_excerpts cap above).
    try:
        _PROV_REF_CAP = int(os.environ.get("SIFT_PROVENANCE_REF_CAP", "64"))
    except ValueError:
        _PROV_REF_CAP = 64
    # Sidecar membership sets keyed by fact_id: O(1) merge dedup instead of
    # rebuilding sorted(set(list)) on EVERY merge (O(k^2 log k) per hot fact --
    # the measured Step-7 quadratic hotspot). Lists are sorted ONCE at the end,
    # so under the cap the output is byte-identical to the legacy path.
    _ref_seen: dict[str, set] = {}
    _idx_seen: dict[str, set] = {}

    for tool_name, envelope in (tool_outputs or {}).items():
        compiler = _TOOL_COMPILERS.get(tool_name)
        if compiler is None:
            continue
        if tool_name in _skip_mft:
            # Redundant MFT source (same $MFT as run_mftecmd) -- skip the
            # duplicate compile that drives by_path O(n^2). Visible in coverage.
            _dr = _declared_record_count(envelope, len(_records(envelope)))
            coverage[tool_name] = {
                "record_count": _dr, "compiled_record_count": 0,
                "emitted_fact_count": 0, "dropped_record_count": _dr,
                "dropped_reasons": {"redundant_mft_source": _dr},
                "fact_types": [], "skipped": True, "reconciliation_ok": True,
            }
            continue

        records = _records(envelope)
        declared = _declared_record_count(envelope, len(records))
        cov: dict[str, Any] = {
            "record_count": declared,
            "compiled_record_count": 0,
            "emitted_fact_count": 0,
            "dropped_record_count": 0,
            "dropped_reasons": {},
            "fact_types": set(),
            "dedup_merged_count": 0,
            "attributed_fact_count": 0,
        }
        coverage[tool_name] = cov

        if _is_error_envelope(envelope):
            cov["dropped_record_count"] = declared
            if declared:
                cov["dropped_reasons"]["error_envelope"] = declared
            cov["fact_types"] = []
            cov["reconciliation_ok"] = (
                cov["record_count"] == cov["dropped_record_count"]
            )
            continue

        # SIFT_PSSCAN_ALIAS_PROVENANCE_V1: if this envelope is a fallback clone
        # of another tool that is ALSO present (vol_pstree <- vol_psscan when the
        # tree plugin returned 0 records), skip a duplicate fact set. The origin
        # compiles these records under its own source_tool; re-emitting here would
        # attribute the same records to a second tool and fabricate a corroborating
        # source. Coverage is recorded above; records are accounted as alias-dropped.
        _alias_src = envelope.get("fallback_alias_of")
        if _alias_src and _alias_src in (tool_outputs or {}):
            cov["dropped_record_count"] = declared
            if declared:
                cov["dropped_reasons"]["fallback_alias_of_%s" % _alias_src] = declared
            cov["fact_types"] = []
            cov["reconciliation_ok"] = (
                cov["record_count"] == cov["dropped_record_count"]
            )
            continue

        # Aggregate per record index so a multi-fact record counts once.
        produced_idx: set[int] = set()
        drop_reason_idx: dict[int, str] = {}

        for rec_i, fact_spec, reason in compiler(records):
            if fact_spec is None:
                drop_reason_idx.setdefault(rec_i, reason or "dropped")
                continue
            produced_idx.add(rec_i)
            ft = fact_spec["fact_type"]
            sig = fact_signature(
                ft, fact_spec["entity_id"], fact_spec["artifact"])
            cov["fact_types"].add(ft)
            rref = f"{tool_name}#{rec_i}"
            excerpt = _excerpt(
                records[rec_i] if rec_i < len(records) else None)

            existing = sig_to_fact.get(sig)
            if existing is not None:
                # Same signature -> MERGE source attribution. Never
                # discard a corroborating source. Membership via sidecar
                # sets (O(1)); lists append-only, sorted once at the end.
                if tool_name not in existing["source_tools"]:
                    existing["source_tools"] = sorted(
                        set(existing["source_tools"]) | {tool_name})
                _efid = existing["fact_id"]
                _ers = _ref_seen.setdefault(
                    _efid, set(existing["record_refs"]))
                if rref not in _ers:
                    _ers.add(rref)
                    if _PROV_REF_CAP <= 0 or (
                            len(existing["record_refs"]) < _PROV_REF_CAP):
                        existing["record_refs"].append(rref)
                    else:
                        existing["provenance_truncated"] = True
                _eis = _idx_seen.setdefault(
                    _efid, set(existing["source_record_indices"]))
                if rec_i not in _eis:
                    _eis.add(rec_i)
                    if _PROV_REF_CAP <= 0 or (
                            len(existing["source_record_indices"])
                            < _PROV_REF_CAP):
                        existing["source_record_indices"].append(rec_i)
                    else:
                        existing["provenance_truncated"] = True
                if (excerpt not in existing["raw_excerpts"]
                        and len(existing["raw_excerpts"])
                        < _RAW_EXCERPT_LIST_CAP):
                    existing["raw_excerpts"].append(excerpt)
                existing["merge_count"] = existing.get("merge_count", 1) + 1
                cov["dedup_merged_count"] += 1
                # Re-register index keys against the existing fid so a
                # merged record's lookups still resolve.
                fid = existing["fact_id"]
                for idx_name, keys in fact_spec.get("index", {}).items():
                    bucket = indexes[idx_name]
                    for key in keys:
                        lst = bucket.setdefault(str(key), [])
                        if fid not in lst:
                            lst.append(fid)
                continue

            fid = f"{ft}-{fact_counter[ft]:07d}"
            fact_counter[ft] += 1
            ceid = fact_spec.get(
                "canonical_entity_id", fact_spec["entity_id"])
            fact_obj = {
                "fact_id": fid,
                "fact_type": ft,
                "fact_signature": sig,
                "canonical_entity_id": ceid,
                # backward-compatible single-source fields (31E-DB.1)
                "source_tool": tool_name,
                "source_record_index": rec_i,
                "record_ref": rref,
                "raw_excerpt": excerpt,
                # canonical merged-source attribution (31E-DB.1a)
                "source_tools": [tool_name],
                "source_record_indices": [rec_i],
                "record_refs": [rref],
                "raw_excerpts": [excerpt],
                "merge_count": 1,
                "confidence_hint": fact_spec.get(
                    "confidence_hint", "observed"),
                "entity_id": fact_spec["entity_id"],
                "artifact": list(fact_spec["artifact"]),
            }
            for fk, fv in fact_spec.get("fields", {}).items():
                fact_obj.setdefault(fk, fv)
            typed_facts[ft].append(fact_obj)
            sig_to_fact[sig] = fact_obj
            cov["emitted_fact_count"] += 1
            for idx_name, keys in fact_spec.get("index", {}).items():
                bucket = indexes[idx_name]
                for key in keys:
                    bucket.setdefault(str(key), []).append(fid)
            # Universal entity backfill: index every fact by the OS-primitive
            # entities embedded in its canonical id (pid:N / ip:X), so families
            # whose compiler declared no entity index still become queryable via
            # the EXISTING by_pid / by_ip (fact_type-filtered -> invisible to
            # process queries). No per-family code, no case data.
            for idx_name, keys in _ceid_entity_indexes(ceid).items():
                bucket = indexes.get(idx_name)
                if bucket is None:
                    continue
                for key in keys:
                    _lst = bucket.setdefault(str(key), [])
                    if fid not in _lst:
                        _lst.append(fid)
            indexes["by_fact_signature"].setdefault(sig, []).append(fid)

        n = len(records)
        compiled = len(produced_idx)
        cov["compiled_record_count"] = compiled
        # A record with declared count but no list entries, or a record
        # that produced no fact, is dropped with a reason.
        dropped = declared - compiled
        cov["dropped_record_count"] = dropped if dropped > 0 else 0
        for ri in range(n):
            if ri not in produced_idx:
                reason = drop_reason_idx.get(ri, "no_fact")
                cov["dropped_reasons"][reason] = (
                    cov["dropped_reasons"].get(reason, 0) + 1
                )
        # Reconcile any declared/list-length mismatch explicitly.
        accounted = compiled + sum(cov["dropped_reasons"].values())
        if accounted < declared:
            gap = declared - accounted
            cov["dropped_reasons"]["unlisted_record"] = (
                cov["dropped_reasons"].get("unlisted_record", 0) + gap
            )
        cov["dropped_record_count"] = sum(cov["dropped_reasons"].values())
        cov["fact_types"] = sorted(cov["fact_types"])
        cov["reconciliation_ok"] = (
            cov["record_count"]
            == cov["compiled_record_count"] + cov["dropped_record_count"]
        )

    # Attribution telemetry: a fact is attributed to every tool listed
    # in its merged source_tools, not just its creating tool.
    for facts in typed_facts.values():
        for f in facts:
            for st in f.get("source_tools", []):
                if st in coverage:
                    coverage[st]["attributed_fact_count"] += 1

    coverage_totals = {
        "tools_compiled": len(coverage),
        "total_emitted_facts": sum(len(v) for v in typed_facts.values()),
        "all_reconciled": all(
            c.get("reconciliation_ok", True) for c in coverage.values()
        ),
        "fact_type_counts": {
            ft: len(typed_facts[ft]) for ft in FACT_TYPES
        },
    }

    # 31X: wire cross-tool user_account_fact extractor into the rebuild path.
    # Before 31X, extract_user_account_facts ran only inside the pipeline runtime,
    # so live runs produced user_account_fact but rebuild/audit paths did not.
    # Wiring it here makes typed_facts identical across live and rebuild,
    # closing the P0 preflight gates. Synthesizer is dataset-agnostic and
    # reads only from tool_outputs already in scope.
    try:
        from sift_sentinel.analysis.user_account_synthesizer import (
            extract_user_account_facts as _extract_uaf_31x,
        )
        _uaf_31x = _extract_uaf_31x(tool_outputs)
        if isinstance(_uaf_31x, list) and _uaf_31x:
            _existing_uaf = typed_facts.get("user_account_fact")
            if not (isinstance(_existing_uaf, list) and _existing_uaf):
                typed_facts["user_account_fact"] = _uaf_31x
    except Exception:
        # Graceful: rebuild path must not fail if synthesizer errors.
        pass

    # Finalize provenance ordering ONCE (the merge path appends without
    # re-sorting -- see the sidecar-set merge above). Under the cap this
    # reproduces the legacy always-sorted contract byte-for-byte.
    for _ft_facts in typed_facts.values():
        for _fobj in _ft_facts:
            _rr = _fobj.get("record_refs")
            if isinstance(_rr, list) and len(_rr) > 1:
                _rr.sort()
            _si = _fobj.get("source_record_indices")
            if isinstance(_si, list) and len(_si) > 1:
                _si.sort()

    return {
        "version": VERSION,
        "legacy_reference_set_passthrough": _legacy_passthrough(
            reference_set),
        "typed_facts": typed_facts,
        "indexes": indexes,
        "coverage": {"per_tool": coverage, "totals": coverage_totals},
    }


# --- Phase 1 additive registration (auto-inserted, removable) ---
from .phase1_extractors import PHASE1_COMPILERS, PHASE1_FACT_TYPES

# Register new fact types so typed_facts dict has slots for them
try:
    if isinstance(FACT_TYPES, tuple):
        FACT_TYPES = FACT_TYPES + tuple(
            ft for ft in PHASE1_FACT_TYPES if ft not in FACT_TYPES
        )
    elif isinstance(FACT_TYPES, list):
        for ft in PHASE1_FACT_TYPES:
            if ft not in FACT_TYPES:
                FACT_TYPES.append(ft)
except NameError:
    pass  # FACT_TYPES not defined at module load; phase1 will not register

# Register new tool -> compiler mappings
try:
    for _tool, _compiler in PHASE1_COMPILERS.items():
        if _tool not in _TOOL_COMPILERS:
            _TOOL_COMPILERS[_tool] = _compiler

    # slot31AS phase2 (zero-hit-tool extractors)
    try:
        from sift_sentinel.analysis.phase2_extractors import (
            PHASE2_COMPILERS, PHASE2_FACT_TYPES,
        )
        for _tool, _compiler in PHASE2_COMPILERS.items():
            if _tool not in _TOOL_COMPILERS:
                _TOOL_COMPILERS[_tool] = _compiler
        # dedup-guard: phase2_extractors also self-registers at its bottom
        # (import-order-safe path); don't double-append its fact types.
        FACT_TYPES = FACT_TYPES + tuple(
            _ft for _ft in PHASE2_FACT_TYPES if _ft not in FACT_TYPES)
    except ImportError:
        pass
except NameError:
    pass
# --- end Phase 1 registration ---


# slot31AT-beta: phase3 typed-fact extractor for vol_psxview
try:
    from sift_sentinel.analysis.phase3_extractors import (
        PHASE3_COMPILERS, PHASE3_FACT_TYPES,
    )
    for _tool, _compiler in PHASE3_COMPILERS.items():
        if _tool not in _TOOL_COMPILERS:
            _TOOL_COMPILERS[_tool] = _compiler
    FACT_TYPES = FACT_TYPES + PHASE3_FACT_TYPES
except (ImportError, NameError):
    pass
# --- end Phase 3 registration ---

# 31K-PS-DECODED-COMMAND-WIRE:
# Precision hardening for PowerShell TTP tags. Do not treat helper source code
# or "msiexec" substrings as IEX/encoded execution. Add decoded_string_fact
# tags so decoded base64 payloads can become typed, validator-checkable facts.
import re as _31k_ps_re

_31K_BASE_PS_TTP_TAGS = _ps_ttp_tags
_31K_BASE_C_POWERSHELL = _c_powershell
_31K_BASE_C_DECODED_STRINGS = _c_decoded_strings

_31K_ENCODED_WITH_REAL_B64_RE = _31k_ps_re.compile(
    r"(?i)(?:^|[\s'\"`])-(?:e|en|enc|encodedcommand)\s+['\"]?([A-Za-z0-9+/=]{20,})"
)
_31K_STANDALONE_IEX_RE = _31k_ps_re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:iex|invoke-expression)(?![A-Za-z0-9_])"
)
_31K_DOWNLOAD_CRADLE_RE = _31k_ps_re.compile(
    r"(?i)(downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient|new-object\s+system\.net\.webclient)"
)
_31K_URL_OR_IP_RE = _31k_ps_re.compile(
    r"(?i)(https?://|ftp://|\\\\[A-Za-z0-9_.-]+\\|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d))"
)
_31K_FROM_B64_RE = _31k_ps_re.compile(r"(?i)frombase64string")
_31K_LONG_B64_RE = _31k_ps_re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/=]{80,})(?![A-Za-z0-9+/=])")


_31K_REFLECTION_HELPER_RE = re.compile(r"func_get_proc_address|func_get_delegate_type|invoke-shellcode|invoke-reflectivepeinjection", re.I)
_31K_REFLECTION_API_RE = re.compile(r"getprocaddress|getdelegateforfunctionpointer", re.I)
_31K_REFLECTION_PRIM_RE = re.compile(r"virtualalloc|createthread|writeprocessmemory|ntmapviewofsection|copymemory|marshal::copy", re.I)


def _ps_ttp_tags(text: str) -> list[str]:
    """Precision wrapper around the base PowerShell tagger.

    Adds encoded_command only for a real base64-looking payload, not for
    helper code like '-EncodedCommand $encoded'. Adds download_cradle only
    when download/WebClient behavior has a concrete URL/IP/UNC context.
    """
    text = str(text or "")
    tags = set(_31K_BASE_PS_TTP_TAGS(text) or [])

    m = _31K_ENCODED_WITH_REAL_B64_RE.search(text)
    if m and "$" not in m.group(1):
        tags.add("encoded_command")

    if _31K_FROM_B64_RE.search(text) and _31K_LONG_B64_RE.search(text):
        tags.add("long_base64_blob")

    if _31K_DOWNLOAD_CRADLE_RE.search(text) and _31K_URL_OR_IP_RE.search(text):
        tags.add("download_cradle")

    if _31K_REFLECTION_HELPER_RE.search(text) or (
            _31K_REFLECTION_API_RE.search(text) and _31K_REFLECTION_PRIM_RE.search(text)):
        tags.add("reflection_load")

    return sorted(tags)


def _31k_sanitize_powershell_record(rec):
    if not isinstance(rec, dict):
        return rec
    out = dict(rec)
    markers = list(out.get("suspicious_markers") or [])
    if markers:
        hay = " ".join(str(out.get(k) or "") for k in (
            "command", "decoded_command", "host_application", "raw_excerpt"
        ))
        clean = []
        for marker in markers:
            marker_s = str(marker or "")
            # parse_powershell_transcripts previously marked "IEX" inside
            # "msiexec". Keep only true standalone iex / Invoke-Expression.
            if marker_s.lower() == "iex" and not _31K_STANDALONE_IEX_RE.search(hay):
                continue
            clean.append(marker)
        out["suspicious_markers"] = clean
    return out


def _c_powershell(records):
    sanitized = [
        _31k_sanitize_powershell_record(r)
        for r in (records or [])
    ]
    yield from _31K_BASE_C_POWERSHELL(sanitized)


def _c_decoded_strings(records):
    for rec_i, fact_spec, reason in _31K_BASE_C_DECODED_STRINGS(records):
        if fact_spec is None:
            yield rec_i, fact_spec, reason
            continue

        rec = records[rec_i] if isinstance(records, list) and rec_i < len(records) else {}
        decoded = " ".join(str(x or "") for x in (
            rec.get("decoded"),
            rec.get("decoded_text"),
            rec.get("decoded_preview"),
            fact_spec.get("decoded_preview"),
            (fact_spec.get("fields") or {}).get("decoded_preview"),
        ))
        original = " ".join(str(x or "") for x in (
            rec.get("original"),
            rec.get("original_text"),
            rec.get("encoded"),
            rec.get("candidate"),
            rec.get("raw_excerpt"),
            (fact_spec.get("fields") or {}).get("original_preview"),
        ))
        combo = (decoded + " " + original).strip()

        tags = set()
        for container in (fact_spec, fact_spec.get("fields") or {}, rec):
            for key in ("tags", "keywords", "ttp_tags"):
                val = container.get(key) if isinstance(container, dict) else None
                if isinstance(val, list):
                    tags.update(str(x) for x in val if x)
                elif val:
                    tags.add(str(val))

        if _31K_DOWNLOAD_CRADLE_RE.search(decoded) and _31K_URL_OR_IP_RE.search(decoded):
            tags.add("download_cradle")
        if _31K_ENCODED_WITH_REAL_B64_RE.search(original) or "encodedcommand" in original.lower():
            tags.add("encoded_command")
        if _31K_FROM_B64_RE.search(combo) or _31K_LONG_B64_RE.search(original):
            tags.add("long_base64_blob")
        if decoded.strip():
            tags.add("decoded_string")

        if tags:
            tag_list = sorted(tags)
            fields = dict(fact_spec.get("fields") or {})
            fields["tags"] = tag_list
            fact_spec["fields"] = fields
            idx = dict(fact_spec.get("index") or {})
            idx["by_ttp_tag"] = sorted(set((idx.get("by_ttp_tag") or []) + tag_list))
            fact_spec["index"] = idx
            art = list(fact_spec.get("artifact") or [])
            if art:
                art[-1] = "|".join(tag_list)
            else:
                art = (decoded[:240], "|".join(tag_list))
            fact_spec["artifact"] = tuple(art)

        yield rec_i, fact_spec, reason


_TOOL_COMPILERS["parse_powershell_transcripts"] = _c_powershell
_TOOL_COMPILERS["decode_base64_strings"] = _c_decoded_strings


def _c_eventlog_with_ps(records):
    yield from _c_eventlog(records)
    for i, rec in enumerate(records or []):
        eid = rec.get("EventID")
        if eid is None:
            continue
        prov = str(rec.get("Provider", "")); ch = str(rec.get("Channel", ""))
        if str(eid) in ("4104", "4103", "4100") and "powershell" in (prov + ch).lower():
            msg = str(rec.get("Message", ""))
            if not msg.strip():
                continue
            ps_rec = {"type": "command", "command": msg, "decoded_command": msg,
                      "timestamp": rec.get("TimeCreated"), "host_application": rec.get("Computer", "")}
            for _j, fspec, _r in _c_powershell([ps_rec]):
                if fspec is not None:
                    yield i, fspec, None


_TOOL_COMPILERS["parse_event_logs"] = _c_eventlog_with_ps

# SIFT_VOL_AMCACHE_COMPILER_V1: Volatility windows.amcache -> execution facts.
# Remaps Capitalized vol keys to the get_amcache lowercase schema, then
# delegates to _c_amcache (facts identical to disk amcache). Dataset-agnostic:
# pure field-name remap, no hardcoded values, no fabricated timestamps.
def _c_vol_amcache(records):
    adapted = []
    for rec in (records or []):
        if not isinstance(rec, dict):
            continue
        adapted.append({
            "path": rec.get("Path") or rec.get("path") or "",
            "sha1": rec.get("SHA1") or rec.get("sha1") or "",
            "first_run": rec.get("InstallTime") or "",
        })
    yield from _c_amcache(adapted)


_TOOL_COMPILERS["vol_amcache"] = _c_vol_amcache




# RUN17_VOL_ENVARS_COMPILER_V1
#
# Dataset-agnostic compiler for Volatility envars output.
# Volatility commonly emits PID, Process, Block, Variable, and Value fields.
# The compiler accepts only structural field names and preserves observed values;
# it does not classify, score, or hardcode any dataset-specific variable.
def _c_vol_envars(records):
    """vol_envars records -> environment_variable_fact."""
    for i, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield i, None, "non_dict_record"
            continue

        pid = _int_or_none(
            rec.get("PID")
            if "PID" in rec else rec.get("pid")
        )

        proc = str(
            rec.get("Process")
            or rec.get("process")
            or rec.get("ImageFileName")
            or rec.get("process_name")
            or ""
        ).strip().lower()

        variable = str(
            rec.get("Variable")
            or rec.get("variable")
            or rec.get("Name")
            or rec.get("name")
            or rec.get("EnvVar")
            or rec.get("envvar")
            or ""
        ).strip()

        value_raw = (
            rec.get("Value")
            if "Value" in rec else
            rec.get("value")
            if "value" in rec else
            rec.get("Data")
            if "Data" in rec else
            rec.get("data")
            if "data" in rec else
            ""
        )
        value = "" if value_raw is None else str(value_raw).strip()

        block = str(
            rec.get("Block")
            or rec.get("block")
            or rec.get("Address")
            or rec.get("address")
            or ""
        ).strip()

        if not variable:
            yield i, None, "no_variable"
            continue

        var_lc = variable.lower()
        pid_key = _pid_eid(pid) if pid is not None else "global"
        value_key = value.lower()[:80]
        ceid = f"envvar:{pid_key}:{var_lc}:{value_key}"

        idx = {
            "by_envvar_name": [var_lc],
        }
        if pid is not None:
            idx["by_pid"] = [str(pid)]
        if proc:
            idx["by_process_name"] = [proc]

        yield i, {
            "fact_type": "environment_variable_fact",
            "canonical_entity_id": ceid,
            "fields": {
                "pid": pid,
                "process_name": proc,
                "variable": variable,
                "variable_name": var_lc,
                "value": value,
                "block": block,
            },
            "index": idx,
        }, None


_TOOL_COMPILERS["vol_envars"] = _c_vol_envars

try:
    TYPED_FACT_TYPES = tuple(
        dict.fromkeys(tuple(TYPED_FACT_TYPES) + ("environment_variable_fact",))
    )
except Exception:
    pass


# RUN17_VOL_ENVARS_COMPILER_FACT_SHAPE_V2
#
# Repair for older EvidenceDB compiler contract:
# build_typed_evidence_db requires fact_spec["entity_id"] and
# fact_spec["artifact"]. The v1 compiler emitted only canonical_entity_id.
#
# Dataset-agnostic:
# - Uses structural Volatility envars fields only.
# - Emits observed PID/process/variable/value fields.
# - No dataset names, fixed PIDs, hashes, paths, IPs, or case-key values.
def _c_vol_envars(records):
    """vol_envars records -> environment_variable_fact."""
    for i, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield i, None, "non_dict_record"
            continue

        pid = _int_or_none(
            rec.get("PID")
            if "PID" in rec else rec.get("pid")
        )

        proc = str(
            rec.get("Process")
            or rec.get("process")
            or rec.get("ImageFileName")
            or rec.get("image_file_name")
            or rec.get("process_name")
            or ""
        ).strip().lower()

        variable = str(
            rec.get("Variable")
            or rec.get("variable")
            or rec.get("Name")
            or rec.get("name")
            or rec.get("EnvVar")
            or rec.get("envvar")
            or ""
        ).strip()

        value_raw = (
            rec.get("Value")
            if "Value" in rec else
            rec.get("value")
            if "value" in rec else
            rec.get("Data")
            if "Data" in rec else
            rec.get("data")
            if "data" in rec else
            ""
        )
        value = "" if value_raw is None else str(value_raw).strip()

        block = str(
            rec.get("Block")
            or rec.get("block")
            or rec.get("Address")
            or rec.get("address")
            or ""
        ).strip()

        if not variable:
            yield i, None, "no_variable"
            continue

        var_lc = variable.lower()
        pid_key = _pid_eid(pid) if pid is not None else "global"
        value_key = value.lower()[:80]
        entity_id = f"envvar:{pid_key}:{var_lc}:{value_key}"
        artifact = f"{variable}={value}" if value else variable
        artifact = artifact[:500]

        idx = {}
        if pid is not None:
            idx["by_pid"] = [str(pid)]
        if var_lc:
            idx["by_envvar_name"] = [var_lc]
        if proc:
            idx["by_process_name"] = [proc]

        yield i, {
            "fact_type": "environment_variable_fact",
            "entity_id": entity_id,
            "canonical_entity_id": entity_id,
            "artifact": [artifact],
            "fields": {
                "pid": pid,
                "process_name": proc,
                "variable": variable,
                "variable_name": var_lc,
                "value": value,
                "block": block,
            },
            "index": idx,
        }, None


# Register/override the v1 compiler with the fact-spec-compatible v2.
_TOOL_COMPILERS["vol_envars"] = _c_vol_envars

# Extend family/index declarations at import time. build_typed_evidence_db reads
# these globals dynamically when constructing typed_facts and indexes.
try:
    FACT_TYPES = tuple(
        dict.fromkeys(tuple(FACT_TYPES) + ("environment_variable_fact",))
    )
except Exception:
    pass

try:
    INDEX_NAMES = tuple(
        dict.fromkeys(tuple(INDEX_NAMES) + ("by_envvar_name", "by_process_name"))
    )
except Exception:
    pass
