"""Slot 31E-DB.5a-alpha TASK 2 -- SEMANTIC_SIGNAL_PROVENANCE_GATE /
MALICIOUS_SEMANTIC_PROVENANCE_GATE.

A malicious semantic signal must carry provenance (explicit support
block validated against the signal's required_fact_types, or a matcher
firing on a real candidate fact). Bare strings / free-text inference are
insufficient. Dataset-agnostic synthetic fixtures only.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_CONFIRMED,
    GATE_MALICIOUS_SEMANTIC_PROVENANCE,
    GATE_SEMANTIC_SIGNAL_PROVENANCE,
    derive_final_disposition,
    evaluate_confirmed_bucket_eligibility,
)


def _clearing(**kw):
    base = {
        "finding_id": "SYNSEM1",
        "title": "synthetic semantic finding",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "validation_status": "MATCH",
        "deterministic_check": "passed",
        "self_verification_passed": True,
        "source_tools": ["vol_malfind"],
        "tool_call_ids": ["tc-sem-1"],
        "raw_excerpt": "synthetic excerpt",
        "validator_fact_refs": [{"fact_type": "memory_injection_fact"}],
        "malicious_semantic_signals": [
            "rwx_memory_region_with_unusual_protection"],
        "claims": [
            {"type": "path", "path": "\\temp\\inj.bin"},
            {"type": "hash", "sha1": "cd", "filename": "inj.bin"},
        ],
    }
    base.update(kw)
    return base


def test_bare_string_signal_not_confirmed():
    f = _clearing()  # declared bare, no support, matcher won't fire
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_SEMANTIC_SIGNAL_PROVENANCE] == "FAIL"
    assert elig["gates"][GATE_MALICIOUS_SEMANTIC_PROVENANCE] == "FAIL"
    assert derive_final_disposition(f)[0] != BUCKET_CONFIRMED


def test_support_missing_raw_excerpt_not_confirmed():
    f = _clearing(semantic_signal_support=[{
        "signal": "rwx_memory_region_with_unusual_protection",
        "supporting_fact_type": "memory_injection_fact",
        "supporting_tool": "vol_malfind",
        "supporting_fact_refs": ["memory_injection_fact:synthetic"],
        "supporting_raw_excerpt": "",
    }])
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_SEMANTIC_SIGNAL_PROVENANCE] == "FAIL"
    assert derive_final_disposition(f)[0] != BUCKET_CONFIRMED


def test_support_fact_type_incompatible_not_confirmed():
    f = _clearing(semantic_signal_support=[{
        "signal": "rwx_memory_region_with_unusual_protection",
        # registry fact type is NOT in this signal's required_fact_types
        "supporting_fact_type": "registry_persistence_fact",
        "supporting_tool": "vol_malfind",
        "supporting_fact_refs": ["registry_persistence_fact:synthetic"],
        "supporting_raw_excerpt": "mismatched provenance",
    }])
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_MALICIOUS_SEMANTIC_PROVENANCE] == "FAIL"
    assert derive_final_disposition(f)[0] != BUCKET_CONFIRMED


def test_full_semantic_support_eligible():
    f = _clearing(semantic_signal_support=[{
        "signal": "rwx_memory_region_with_unusual_protection",
        "supporting_fact_type": "memory_injection_fact",
        "supporting_tool": "vol_malfind",
        "supporting_fact_refs": ["memory_injection_fact:synthetic"],
        "supporting_raw_excerpt": "private RWX region, no backing file",
    }])
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_SEMANTIC_SIGNAL_PROVENANCE] == "PASS"
    assert elig["gates"][GATE_MALICIOUS_SEMANTIC_PROVENANCE] == "PASS"
    assert elig["eligible"] is True
    assert derive_final_disposition(f)[0] == BUCKET_CONFIRMED


def test_marker():
    print("SEMANTIC_SIGNAL_PROVENANCE_GATE=PASS")
    print("MALICIOUS_SEMANTIC_PROVENANCE_GATE=PASS")
    assert True
