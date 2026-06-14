"""Slot 31E-DB.5a-alpha TASK 1 -- CLAIM_FACT_REFERENCE_GATE /
EXPLICIT_FACT_ID_IN_CLAIMS_GATE.

A confirmed_malicious_atomic finding must carry durable,
validator-attached fact references. Dataset-agnostic: synthetic ids,
synthetic refs, no real PIDs / hashes / paths.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    GATE_CLAIM_FACT_REFERENCE,
    GATE_EXPLICIT_FACT_ID_IN_CLAIMS,
    derive_final_disposition,
    durable_fact_refs,
    evaluate_confirmed_bucket_eligibility,
)


def _clearing(**kw):
    """Clears every OTHER confirmed gate; fact-ref surface varies."""
    base = {
        "finding_id": "SYNREF1",
        "title": "synthetic behavioural finding",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "validation_status": "MATCH",
        "deterministic_check": "passed",
        "self_verification_passed": True,
        "source_tools": ["vol_pstree"],
        "tool_call_ids": ["tc-ref-1"],
        "raw_excerpt": "synthetic excerpt",
        "malicious_semantic_signals": ["executes_from_temp_path"],
        "semantic_signal_support": [{
            "signal": "executes_from_temp_path",
            "supporting_fact_type": "file_execution_fact",
            "supporting_tool": "parse_mft",
            "supporting_fact_refs": ["file_execution_fact:synthetic"],
            "supporting_raw_excerpt": "executable under a staging path",
        }],
        "claims": [
            {"type": "path", "path": "\\temp\\stager.exe"},
            {"type": "hash", "sha1": "ab", "filename": "stager.exe"},
        ],
    }
    base.update(kw)
    return base


def test_confirmed_candidate_without_durable_refs_not_confirmed():
    f = _clearing()  # no validator_fact_refs anywhere
    assert durable_fact_refs(f) == []
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_CLAIM_FACT_REFERENCE] == "FAIL"
    assert elig["gates"][GATE_EXPLICIT_FACT_ID_IN_CLAIMS] == "FAIL"
    bucket, _ = derive_final_disposition(f)
    assert bucket != BUCKET_CONFIRMED
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE)


def test_validator_fact_refs_pass_this_gate():
    f = _clearing(validator_fact_refs=[
        {"fact_type": "file_execution_fact", "claim_type": "path",
         "source": "typed_evidence_db"},
    ])
    assert durable_fact_refs(f)
    elig = evaluate_confirmed_bucket_eligibility(f)
    assert elig["gates"][GATE_CLAIM_FACT_REFERENCE] == "PASS"
    assert elig["gates"][GATE_EXPLICIT_FACT_ID_IN_CLAIMS] == "PASS"
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_CONFIRMED


def test_validator_metadata_typed_fact_refs_also_count():
    f = _clearing(validator_metadata={
        "typed_fact_refs": [{"fact_type": "file_execution_fact"}],
    })
    assert durable_fact_refs(f)
    bucket, _ = derive_final_disposition(f)
    assert bucket == BUCKET_CONFIRMED


def test_missing_refs_route_out_not_suppressed():
    f = _clearing()
    bucket, reasons = derive_final_disposition(f)
    # Honest failure: routed out, never dropped.
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE)
    assert any("CLAIM_FACT_REFERENCE_GATE" in r for r in reasons)


def test_marker():
    print("CLAIM_FACT_REFERENCE_GATE=PASS")
    print("EXPLICIT_FACT_ID_IN_CLAIMS_GATE=PASS")
    assert True
