"""Slot 31E-DB.5.2/.3 -- confirmed-bucket evidence sufficiency gate.

Dataset-agnostic. No API key, no live run, no network. Synthetic
regression fixtures only; F001/F005 are regression *class* names, not
dataset case ids -- production code never special-cases them.
"""

from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    derive_final_disposition,
    evaluate_confirmed_bucket_eligibility,
    route_findings_for_report,
    validate_disposition_buckets,
)


def test_f001_speculative_must_not_be_confirmed_malicious():
    f001 = {
        "finding_id": "F001_regression",
        "title": "Synthetic speculative regression fixture",
        "severity": "CRITICAL",
        "confidence_level": "SPECULATIVE",
        "source_tools": [],
        "claims": [{"type": "process_fact", "value": "synthetic"}],
        "malicious_semantic_signals": [],
    }
    res = evaluate_confirmed_bucket_eligibility(f001)
    assert res["eligible"] is False
    g = res["gates"]
    assert g["NO_SPECULATIVE_CONFIRMED_GATE"] == "FAIL"
    assert g["NO_EMPTY_SOURCE_CONFIRMED_GATE"] == "FAIL"
    assert g["CONFIRMED_BUCKET_EVIDENCE_GATE"] == "FAIL"

    bucket, _ = derive_final_disposition(f001)
    assert bucket != BUCKET_CONFIRMED
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_INCONCLUSIVE)

    buckets = route_findings_for_report([f001])
    assert all(
        x.get("finding_id") != "F001_regression"
        for x in buckets[BUCKET_CONFIRMED]
    )
    assert validate_disposition_buckets(buckets) == []


def test_f005_environment_context_must_not_be_confirmed_malicious():
    f005 = {
        "finding_id": "F005_regression",
        "title": "synthetic environment context regression fixture",
        "severity": "HIGH",
        "confidence_level": "HIGH",
        "source_tools": ["parse_event_logs"],
        "tool_call_ids": ["synthetic_event_log_call"],
        "raw_excerpt": "Synthetic MsiInstaller event fixture",
        "claims": [{"type": "event_log_fact", "value": "synthetic"}],
        "post_sc": True,
        "malicious_semantic_signals": [],
        "environment_context_signals": ["msi_installer_event"],
    }
    res = evaluate_confirmed_bucket_eligibility(f005)
    assert res["eligible"] is False
    assert res["gates"]["MALICIOUS_SEMANTIC_GATE"] == "FAIL"
    assert "msi_installer_event" in res["environment_context_signals"]

    bucket, _ = derive_final_disposition(f005)
    assert bucket != BUCKET_CONFIRMED
    assert bucket in (BUCKET_SUSPICIOUS, BUCKET_BENIGN)


def test_confirmed_bucket_schema_completeness_blocks_missing_fields():
    def _base():
        return {
            "finding_id": "Fok",
            "title": "synthetic",
            "severity": "HIGH",
            "confidence_level": "HIGH",
            "source_tools": ["vol_malfind"],
            "tool_call_ids": ["tc1"],
            "raw_excerpt": "rwx",
            "claims": [{"type": "memory_injection_fact", "v": "s"}],
            "typed_fact_refs": ["mi:1"],
            "malicious_semantic_signals": [
                "rwx_memory_region_with_unusual_protection"
            ],
        }

    assert evaluate_confirmed_bucket_eligibility(_base())["eligible"] is True

    missing_src = _base()
    missing_src["source_tools"] = []
    assert evaluate_confirmed_bucket_eligibility(
        missing_src)["eligible"] is False

    missing_tc = _base()
    missing_tc["tool_call_ids"] = []
    assert evaluate_confirmed_bucket_eligibility(
        missing_tc)["eligible"] is False

    missing_re = _base()
    missing_re["raw_excerpt"] = ""
    assert evaluate_confirmed_bucket_eligibility(
        missing_re)["eligible"] is False

    no_claims = _base()
    no_claims["claims"] = []
    assert evaluate_confirmed_bucket_eligibility(
        no_claims)["eligible"] is False

    spec = _base()
    spec["confidence_level"] = "SPECULATIVE"
    assert evaluate_confirmed_bucket_eligibility(spec)["eligible"] is False

    react_benign = _base()
    react_benign["react_verdict"] = "confirmed_benign"
    rb = evaluate_confirmed_bucket_eligibility(react_benign)
    assert rb["eligible"] is False
    assert any("benign" in r for r in rb["blocking_reasons"])


def test_speculative_with_empty_source_triggers_both_gates():
    f = {
        "finding_id": "Fspec",
        "title": "synthetic",
        "severity": "HIGH",
        "confidence_level": "SPECULATIVE",
        "source_tools": [],
        "claims": [{"type": "process_fact", "v": "s"}],
    }
    g = evaluate_confirmed_bucket_eligibility(f)["gates"]
    assert g["NO_SPECULATIVE_CONFIRMED_GATE"] == "FAIL"
    assert g["NO_EMPTY_SOURCE_CONFIRMED_GATE"] == "FAIL"
