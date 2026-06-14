"""Slot 31E-DB.5a-alpha TASK 3 -- NO_PID_ONLY_CONFIRMED_GATE.

A PID / process-existence claim identifies an entity; it does not prove
maliciousness. confirmed_malicious_atomic needs at least one behavioural
malicious claim beyond PID/process existence. Dataset-agnostic.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_CONFIRMED,
    GATE_NO_PID_ONLY_CONFIRMED,
    derive_final_disposition,
    evaluate_confirmed_bucket_eligibility,
    has_behavioral_malicious_claim,
)


def _clearing(**kw):
    base = {
        "finding_id": "SYNPID1",
        "title": "synthetic finding",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "validation_status": "MATCH",
        "deterministic_check": "passed",
        "self_verification_passed": True,
        "source_tools": ["vol_pstree"],
        "tool_call_ids": ["tc-pid-1"],
        "raw_excerpt": "synthetic excerpt",
        "validator_fact_refs": [{"fact_type": "process_fact"}],
        "malicious_semantic_signals": ["executes_from_temp_path"],
        "semantic_signal_support": [{
            "signal": "executes_from_temp_path",
            "supporting_fact_type": "file_execution_fact",
            "supporting_tool": "parse_mft",
            "supporting_fact_refs": ["file_execution_fact:synthetic"],
            "supporting_raw_excerpt": "executable under a staging path",
        }],
        "claims": [{"type": "pid", "pid": 7, "process": "svc.exe"}],
    }
    base.update(kw)
    return base


def test_pid_only_candidate_not_confirmed():
    f = _clearing()  # only a pid claim
    assert has_behavioral_malicious_claim(f, []) is False
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_NO_PID_ONLY_CONFIRMED] == "FAIL"
    assert derive_final_disposition(f)[0] != BUCKET_CONFIRMED


def test_process_exists_only_not_confirmed():
    f = _clearing(claims=[{"type": "process_exists", "pid": 9}])
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_NO_PID_ONLY_CONFIRMED] == "FAIL"
    assert derive_final_disposition(f)[0] != BUCKET_CONFIRMED


def test_pid_plus_behavioural_path_can_pass():
    f = _clearing(claims=[
        {"type": "pid", "pid": 7, "process": "svc.exe"},
        {"type": "path", "path": "\\temp\\stager.exe"},
    ])
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_NO_PID_ONLY_CONFIRMED] == "PASS"
    assert elig["eligible"] is True
    assert derive_final_disposition(f)[0] == BUCKET_CONFIRMED


def test_marker():
    print("NO_PID_ONLY_CONFIRMED_GATE=PASS")
    assert True
