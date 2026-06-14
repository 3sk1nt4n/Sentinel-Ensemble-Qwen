"""Two light, high-value memory enrichers selected by default: vol_sessions
(logon session -> process) and vol_envars (process environment). Both must
reach the DB indexed by PID and VALIDATE, so they join to process findings as
corroborating evidence (WHO / session-anomaly / execution-context) rather than
just being collected. Synthetic only; keyed on structure, no case data.
"""
from __future__ import annotations

from pathlib import Path

from sift_sentinel.analysis.evidence_db import _TOOL_COMPILERS
from sift_sentinel.analysis.confidence import TOOL_TO_ARTIFACT_TYPE
from sift_sentinel.validation.typed_validator import (
    TypedEvidenceDB,
    TYPED_SUPPORTED_CLAIM_TYPES,
    typed_check_claim,
)

_SRC = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()
_PRIORITY = _SRC.split("_slot31k_priority_add")[1].split("_slot31k_drop_if_needed")[0]
_DROP = _SRC.split("_slot31k_drop_if_needed = [")[1].split("]")[0]


def _session_fact(pid=4242, proc="explorer.exe", sess="RemoteInteractive", user="dom\\u"):
    rec = {"Process ID": pid, "Session ID": 2, "Process": proc,
           "User Name": user, "Session Type": sess, "Create Time": "2021-01-01 00:00:00"}
    for _i, f, _e in _TOOL_COMPILERS["vol_sessions"]([rec]):
        return f
    return None


# ── session_fact is now PID-joinable + validates ────────────────────────

def test_session_fact_indexed_by_pid():
    f = _session_fact()
    assert f["index"]["by_pid"] == ["4242"]
    assert f["index"]["by_process_name"] == ["explorer.exe"]


def test_session_fact_validates_via_typed_fact():
    f = dict(_session_fact(), fact_id="session_fact-0")
    # the real EvidenceDB build hoists each fact's index into a top-level
    # `indexes` dict; TypedEvidenceDB reads that, so mirror it here.
    evdb = {"typed_facts": {"session_fact": [f]},
            "indexes": {"by_pid": {"4242": ["session_fact-0"]}}}
    tdb = TypedEvidenceDB(evdb)
    r = typed_check_claim({"type": "typed_fact", "fact_type": "session_fact", "pid": 4242}, tdb)
    assert r and r[0] == "MATCH", r


def test_session_fact_no_pid_yields_error():
    out = list(_TOOL_COMPILERS["vol_sessions"]([{"Process": "x"}]))
    assert out and out[0][1] is None     # no Process ID -> dropped, not crash


# ── environment_variable_fact validates via the envvar checker ──────────

def test_envvar_fact_validates_via_process_envvar():
    evdb = {"typed_facts": {"environment_variable_fact": [{
        "fact_id": "environment_variable_fact-0",
        "fact_type": "environment_variable_fact", "pid": 4242,
        "variable": "TEMP", "value": "C:/staging",
        "index": {"by_pid": ["4242"]}}]}}
    tdb = TypedEvidenceDB(evdb)
    r = typed_check_claim({"type": "process_envvar", "pid": 4242, "variable": "TEMP"}, tdb)
    assert r and r[0] == "MATCH", r
    assert "process_envvar" in TYPED_SUPPORTED_CLAIM_TYPES


# ── both are selected by default + correctly typed ──────────────────────

def test_both_tools_in_priority_selection():
    assert '"vol_sessions",' in _PRIORITY
    assert '"vol_envars",' in _PRIORITY


def test_vol_sessions_no_longer_in_drop_list():
    assert "vol_sessions" not in _DROP


def test_both_tools_are_memory_artifact_type():
    assert TOOL_TO_ARTIFACT_TYPE.get("vol_sessions") == "M"
    assert TOOL_TO_ARTIFACT_TYPE.get("vol_envars") == "M"


def test_metamorphic_session_relabel():
    a = _session_fact(pid=1, proc="a.exe", user="dom\\alpha")
    b = _session_fact(pid=2, proc="b.exe", user="dom\\beta")
    assert set(a["index"]) == set(b["index"])
    assert a["index"]["by_pid"] == ["1"] and b["index"]["by_pid"] == ["2"]
