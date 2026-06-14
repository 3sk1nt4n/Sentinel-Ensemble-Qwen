"""Slot 31E-DB.5.1 -- canonical validation telemetry consistency.

Dataset-agnostic. No API key, no live run, no network.
"""

from __future__ import annotations

from sift_sentinel.validation.telemetry import (
    normalize_validation_telemetry,
    validate_telemetry_consistency,
)


def _full(used=True, t=3, r=2, u=1):
    return {
        "typed_evidence_db_used": used,
        "typed_fact_matches": t,
        "reference_set_fallback_matches": r,
        "unsupported_claim_type_count": u,
    }


def test_exact_backend_report_match_passes():
    backend = _full()
    report = dict(backend)
    ok, errs = validate_telemetry_consistency(backend, report)
    assert ok is True
    assert errs == []


def test_stale_zero_report_vs_backend_fails():
    backend = _full(t=4)
    report = _full(t=0)
    ok, errs = validate_telemetry_consistency(backend, report)
    assert ok is False
    assert any("typed_fact_matches" in e for e in errs)


def test_missing_telemetry_field_fails():
    backend = _full()
    report = {
        "typed_evidence_db_used": True,
        "typed_fact_matches": 3,
        "reference_set_fallback_matches": 2,
        # unsupported_claim_type_count missing entirely
    }
    ok, errs = validate_telemetry_consistency(backend, report)
    assert ok is False
    assert any(
        "report_missing_field:unsupported_claim_type_count" in e
        for e in errs
    )


def test_normalize_preserves_absence_not_zero():
    n = normalize_validation_telemetry({"typed_fact_matches": 5})
    assert n["typed_fact_matches"] == 5
    assert n["unsupported_claim_type_count"] is None
    assert n["typed_evidence_db_used"] is None


def test_normalize_coerces_types():
    n = normalize_validation_telemetry({
        "typed_evidence_db_used": 1,
        "typed_fact_matches": "7",
        "reference_set_fallback_matches": 0,
        "unsupported_claim_type_count": 2,
    })
    assert n["typed_evidence_db_used"] is True
    assert n["typed_fact_matches"] == 7
    assert n["reference_set_fallback_matches"] == 0
