"""Phase 1 additive typed-fact extractors.

Adds compilers for previously-unextracted tools:
  - run_memprocfs    -> memprocfs_indicator_fact
  - vol_handles      -> handle_fact
  - vol_dlllist      -> dll_load_fact
  - vol_cmdline      -> process_cmdline_fact

Dataset-agnostic: every emitted fact reads only structural fields from the
source tool's records. No hardcoded names, IOCs, paths, PIDs, hashes, or
usernames. Empty input -> empty output. Random-token input -> correctly
shaped facts with the random tokens passed through verbatim.

Follows the same generator pattern as existing _c_* compilers in
evidence_db.py: yields (record_index, fact_spec | None, drop_reason) tuples.
"""
from typing import Iterator, Tuple

# Lazy evidence_db helper accessors.
#
# phase1_extractors is imported by evidence_db during fact-factory
# registration. An eager import from evidence_db here creates a circular
# import when phase1_extractors is imported first. These wrappers keep
# the shared normalization semantics while making import order safe.
def _edb_helper(name):
    from . import evidence_db as _edb
    return getattr(_edb, name)

def normalize_path(*args, **kwargs):
    return _edb_helper('normalize_path')(*args, **kwargs)

def normalize_cmdline(*args, **kwargs):
    return _edb_helper('normalize_cmdline')(*args, **kwargs)

def normalize_timestamp(*args, **kwargs):
    return _edb_helper('normalize_timestamp')(*args, **kwargs)

def _int_or_none(*args, **kwargs):
    return _edb_helper('_int_or_none')(*args, **kwargs)

def _pid_eid(*args, **kwargs):
    return _edb_helper('_pid_eid')(*args, **kwargs)

def _c_memprocfs(records: list) -> Iterator[Tuple[int, "dict | None", "str | None"]]:
    """run_memprocfs records -> memprocfs_indicator_fact."""
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue

        pid = _int_or_none(rec.get("pid"))
        proc = (rec.get("process") or "").lower().strip()
        subsystem = (rec.get("memprocfs_subsystem") or "").lower().strip()
        sem_family = (rec.get("semantic_family") or "").lower().strip()
        sem_role = (rec.get("semantic_role") or "").lower().strip()
        ind_type = (rec.get("indicator_type") or "").lower().strip()
        priority = (rec.get("priority_tier") or "").lower().strip()
        path = normalize_path(rec.get("path") or "")
        evidence_id = str(rec.get("evidence_id") or "").strip()

        families_raw = rec.get("families") or []
        families = (
            [str(x).lower().strip() for x in families_raw if x]
            if isinstance(families_raw, list)
            else []
        )
        anchors_raw = rec.get("anchors") or {}
        anchors = anchors_raw if isinstance(anchors_raw, dict) else {}

        if evidence_id:
            ceid = f"memprocfs:evid:{evidence_id}"
        elif pid is not None and subsystem:
            ceid = f"memprocfs:{subsystem}:{_pid_eid(pid)}"
        elif subsystem and sem_role:
            ceid = f"memprocfs:{subsystem}:{sem_role}"
        else:
            yield idx, None, "no_canonical_key"
            continue

        source_csv = str(rec.get("source_csv") or "").strip()
        source_file = str(
            rec.get("source_file")
            or rec.get("source_txt")
            or rec.get("source_csv")
            or ""
        ).strip()
        description = str(rec.get("description") or "").strip()

        yield idx, {
            "fact_type": "memprocfs_indicator_fact",
            "entity_id": ceid,
            "artifact": [proc[:40], subsystem[:30], sem_role[:30]],
            "pid": pid,
            "process_name": proc,
            "subsystem": subsystem,
            "semantic_family": sem_family,
            "semantic_role": sem_role,
            "indicator_type": ind_type,
            "priority_tier": priority,
            "path": path,
            "evidence_id": evidence_id,
            "families": families,
            "anchors": anchors,
            # 31G-MEMPROCFS-FIELDS-PERSISTENCE:
            # EvidenceDB preserves compiler extension data via fields/index.
            # Keep MemProcFS / FindEvil normalized values queryable without
            # forcing validators/themes/report truth to parse raw_excerpt JSON.
            "fields": {
                "pid": pid,
                "process_name": proc,
                "subsystem": subsystem,
                "semantic_family": sem_family,
                "semantic_role": sem_role,
                "indicator_type": ind_type,
                "priority_tier": priority,
                "path": path,
                "evidence_id": evidence_id,
                "families": families,
                "anchors": anchors,
                "source_csv": source_csv,
                "source_file": source_file,
                "description": description,
            },
            "index": {
                "by_pid": ([str(pid)] if pid is not None else []),
                "by_path": ([path] if path else []),
            },
        }, None


def _c_handles(records: list) -> Iterator[Tuple[int, "dict | None", "str | None"]]:
    """vol_handles records -> handle_fact.

    Handle types and access masks are Windows ABI constants, not dataset
    values. The detection of "LSASS opens" and similar happens in
    downstream scoring; this extractor stays structural.
    """
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue

        pid = _int_or_none(rec.get("PID"))
        if pid is None:
            yield idx, None, "no_pid"
            continue

        proc = (rec.get("Process") or "").lower().strip()
        htype = (rec.get("Type") or "").strip()
        if not htype:
            yield idx, None, "no_handle_type"
            continue

        hname = (rec.get("Name") or "").strip()
        granted = _int_or_none(rec.get("GrantedAccess"))
        hval = _int_or_none(rec.get("HandleValue"))

        htype_lc = htype.lower()
        if hname:
            short = hname.lower()[:120]
            ceid = f"handle:{_pid_eid(pid)}:{htype_lc}:{short}"
        else:
            ceid = f"handle:{_pid_eid(pid)}:{htype_lc}:{hval or 0}"

        yield idx, {
            "fact_type": "handle_fact",
            "entity_id": ceid,
            "artifact": [proc[:32], htype_lc, hname[:60]],
            "pid": pid,
            "process_name": proc,
            "handle_type": htype_lc,
            "handle_name": hname,
            "granted_access": granted,
            "handle_value": hval,
        }, None


def _c_dlllist(records: list) -> Iterator[Tuple[int, "dict | None", "str | None"]]:
    """vol_dlllist records -> dll_load_fact."""
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue

        pid = _int_or_none(rec.get("PID"))
        if pid is None:
            yield idx, None, "no_pid"
            continue

        proc = (rec.get("Process") or "").lower().strip()
        dll_name = (rec.get("Name") or "").lower().strip()
        dll_path = normalize_path(rec.get("Path") or "")
        base = _int_or_none(rec.get("Base"))
        size = _int_or_none(rec.get("Size"))
        load_time = normalize_timestamp(rec.get("LoadTime"))
        load_count = _int_or_none(rec.get("LoadCount"))

        if not dll_name and not dll_path:
            yield idx, None, "no_dll_identifier"
            continue

        if dll_path:
            ceid = f"dll:{_pid_eid(pid)}:path:{dll_path}"
        else:
            ceid = f"dll:{_pid_eid(pid)}:name:{dll_name}"

        yield idx, {
            "fact_type": "dll_load_fact",
            "index": {  # DLL_LOAD_INDEX_DIRECTIVE_V1
                "by_pid": [str(pid)],
                "by_path": [dll_path] if dll_path else [],
            },
            "entity_id": ceid,
            "artifact": [proc[:32], dll_name[:40], dll_path[:80]],
            "pid": pid,
            "process_name": proc,
            "dll_name": dll_name,
            "dll_path": dll_path,
            "image_base": base,
            "image_size": size,
            "load_time": load_time,
            "load_count": load_count,
        }, None


def _c_cmdline(records: list) -> Iterator[Tuple[int, "dict | None", "str | None"]]:
    """vol_cmdline records -> process_cmdline_fact.

    Empty command lines are evidence, not missing data.

    Dataset-agnostic rule:
    - If the volatility record contains an Args field, preserve it even when
      Args normalizes to an empty string.
    - If the Args field is absent entirely, skip it as unobserved.
    - This compiler does not decide whether an empty command line is malicious;
      it only preserves the current-run fact for typed validation.
    """
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue

        pid = _int_or_none(rec.get("PID"))
        if pid is None:
            yield idx, None, "no_pid"
            continue

        if "Args" not in rec:
            yield idx, None, "no_args_field"
            continue

        proc = (rec.get("Process") or "").lower().strip()
        args = normalize_cmdline(rec.get("Args"))
        args_empty = (args == "")

        ceid = f"cmdline:{_pid_eid(pid)}"

        yield idx, {
            "fact_type": "process_cmdline_fact",
            "entity_id": ceid,
            "artifact": [proc[:32], args[:120]],
            "pid": pid,
            "process_name": proc,
            "cmdline": args,
            "cmdline_is_empty": args_empty,
        }, None


# Mapping from tool_name -> compiler, registered by evidence_db.py at import
PHASE1_COMPILERS = {
    "run_memprocfs": _c_memprocfs,
    "vol_handles":   _c_handles,
    "vol_dlllist":   _c_dlllist,
    "vol_cmdline":   _c_cmdline,
}

# Fact types this module emits (registered into FACT_TYPES at import)
PHASE1_FACT_TYPES = (
    "memprocfs_indicator_fact",
    "handle_fact",
    "dll_load_fact",
    "process_cmdline_fact",
)
