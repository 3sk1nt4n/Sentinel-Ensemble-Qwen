"""slot31AT-beta regression - phase3 psxview extractor.

Random-token property-based tests; matches phase2 pattern.
"""
import secrets
import pytest
from sift_sentinel.analysis.evidence_db import _TOOL_COMPILERS, FACT_TYPES
from sift_sentinel.analysis.phase3_extractors import (
    PHASE3_COMPILERS, PHASE3_FACT_TYPES, _c_psxview, _to_bool,
)


def test_phase3_compiler_registered():
    assert "vol_psxview" in _TOOL_COMPILERS


def test_phase3_fact_type_registered():
    assert "psxview_fact" in FACT_TYPES


def test_psxview_all_views_true():
    """Process visible in all views = no anomaly (downstream judgment)."""
    name_tok = "p" + secrets.token_hex(4)
    pid_tok = 1000 + secrets.randbelow(50000)
    rec = {
        "Name": name_tok, "PID": pid_tok,
        "pslist": True, "psscan": True, "thrdproc": True,
        "csrss": True, "session": True, "deskthrd": True,
        "ExitTime": None,
    }
    facts = [s for _, s, _ in _c_psxview([rec]) if s]
    assert len(facts) == 1
    f = facts[0]
    assert f["fact_type"] == "psxview_fact"
    assert f["pid"] == pid_tok
    assert f["process_name"] == name_tok.lower()
    for k in ("view_pslist","view_psscan","view_thrdproc",
             "view_csrss","view_session","view_deskthrd"):
        assert f[k] is True, f"{k} not normalized to True"


def test_psxview_view_disagreement_passes_through():
    """Cross-view disagreement passed through verbatim, no is_hidden flag."""
    rec = {
        "Name": "x", "PID": 999,
        "pslist": False, "psscan": True,  # hidden from pslist
        "thrdproc": True, "csrss": True,
        "session": True, "deskthrd": True,
    }
    facts = [s for _, s, _ in _c_psxview([rec]) if s]
    f = facts[0]
    # Structural: booleans passed through
    assert f["view_pslist"] is False
    assert f["view_psscan"] is True
    # NO derived judgment field
    assert "is_hidden" not in f
    assert "is_rootkit" not in f
    assert "is_anomalous" not in f


def test_psxview_string_booleans_normalized():
    """Vol3 may emit 'True'/'False' strings; _to_bool normalizes."""
    rec = {
        "Name": "x", "PID": 42,
        "pslist": "True", "psscan": "False",
        "thrdproc": "true", "csrss": "false",
        "session": "yes", "deskthrd": "no",
    }
    facts = [s for _, s, _ in _c_psxview([rec]) if s]
    f = facts[0]
    assert f["view_pslist"] is True
    assert f["view_psscan"] is False
    assert f["view_thrdproc"] is True
    assert f["view_csrss"] is False
    assert f["view_session"] is True
    assert f["view_deskthrd"] is False


def test_psxview_none_preserved():
    """None field stays None (distinct from False)."""
    rec = {
        "Name": "x", "PID": 1,
        "pslist": True, "psscan": None,
    }
    f = [s for _, s, _ in _c_psxview([rec]) if s][0]
    assert f["view_pslist"] is True
    assert f["view_psscan"] is None  # field absent, NOT False


def test_psxview_handles_empty():
    assert list(_c_psxview([])) == []


def test_psxview_handles_non_dict():
    result = list(_c_psxview([None, "string", 42]))
    for idx, spec, reason in result:
        assert spec is None
        assert reason is not None


def test_psxview_requires_pid():
    rec = {"Name": "x"}
    result = list(_c_psxview([rec]))
    assert result[0][1] is None
    assert result[0][2] == "no_pid"


def test_to_bool_helper():
    assert _to_bool(True) is True
    assert _to_bool(False) is False
    assert _to_bool(None) is None
    assert _to_bool("True") is True
    assert _to_bool("false") is False
    assert _to_bool("yes") is True
    assert _to_bool("garbage") is None
    assert _to_bool(1) is True
    assert _to_bool(0) is False
