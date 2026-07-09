"""Phase 3 additive typed-fact extractor (slot31AT-beta).

Compiles vol_psxview records into typed psxview_fact for downstream
cross-view-anomaly detection.

  - vol_psxview -> psxview_fact (per-process view membership flags)

Dataset-agnostic AND judgment-free, matching phase1/phase2 discipline:
  * Every emitted field is a structural pass-through from Volatility3.
  * NO is_hidden / is_rootkit / is_anomalous derived flags. The
    cross-view inconsistency judgment ("present in psscan but missing
    from pslist => DKOM hiding") lives in candidate_observations
    (slot31AT-gamma), NOT in the extractor.
  * View booleans normalized from mixed Vol3 output types (True/False/
    'True'/'False'/None) to Python bool|None. None means "field absent
    from this record" - downstream can distinguish absent from False.
"""
from typing import Iterator, Tuple

from .evidence_db import (
    normalize_timestamp, _int_or_none, _pid_eid,
)


def _to_bool(value):
    """Normalize Vol3 mixed-type booleans. None if field absent.

    Vol3 outputs view-membership as Python bool, string 'True'/'False',
    or None depending on plugin version. Returns Python bool|None.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "yes", "1"):
            return True
        if s in ("false", "no", "0", "okay"):
            return False
        return None
    try:
        return bool(value)
    except Exception:
        return None


def _c_psxview(records):
    """vol_psxview records -> psxview_fact (structural).

    Volatility3 PsXView schema:
      Name, PID, pslist, psscan, thrdproc, csrss, session, deskthrd,
      ExitTime, TreeDepth

    All view fields emitted verbatim. Downstream detects anomalies by
    checking if any view source disagrees with the others.
    """
    for idx, rec in enumerate(records or []):
        if not isinstance(rec, dict):
            yield idx, None, "non_dict_record"
            continue
        pid = _int_or_none(rec.get("PID"))
        if pid is None:
            yield idx, None, "no_pid"
            continue
        name = (rec.get("Name") or rec.get("Process") or "").strip()
        yield idx, {
            "fact_type": "psxview_fact",
            "entity_id": f"psxview:{_pid_eid(pid)}",
            "artifact": [name[:32]],
            "pid": pid,
            "process_name": name.lower(),
            "view_pslist":    _to_bool(rec.get("pslist")),
            "view_psscan":    _to_bool(rec.get("psscan")),
            "view_thrdproc":  _to_bool(rec.get("thrdproc")),
            "view_csrss":     _to_bool(rec.get("csrss")),
            "view_session":   _to_bool(rec.get("session")),
            "view_deskthrd":  _to_bool(rec.get("deskthrd")),
            "exit_time":      normalize_timestamp(rec.get("ExitTime")),
        }, None


PHASE3_COMPILERS = {
    "vol_psxview": _c_psxview,
}

PHASE3_FACT_TYPES = (
    "psxview_fact",
)
