"""Slot 31E-DB.5.7 -- report/bucket consistency.

Dataset-agnostic. No API key, no live run, no network. Confirmed /
critical atomic report sections may contain ONLY
confirmed_malicious_atomic; non-confirmed buckets and synthesis never
inflate the confirmed atomic count.
"""

from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    BUCKET_SYNTHESIS,
)
from sift_sentinel.validation.report_gates import (
    check_report_bucket_consistency,
)


def _f(fid, disp):
    return {"finding_id": fid, "title": fid, "final_disposition": disp}


def _buckets():
    return {
        BUCKET_CONFIRMED: [_f("S1", BUCKET_CONFIRMED),
                           _f("S2", BUCKET_CONFIRMED)],
        BUCKET_SUSPICIOUS: [_f("S6", BUCKET_SUSPICIOUS)],
        BUCKET_BENIGN: [_f("S3", BUCKET_BENIGN)],
        BUCKET_INCONCLUSIVE: [_f("S4", BUCKET_INCONCLUSIVE)],
        BUCKET_SYNTHESIS: [_f("S5", BUCKET_SYNTHESIS)],
    }


def test_clean_buckets_are_consistent():
    b = _buckets()
    counts = {
        BUCKET_CONFIRMED: 2,
        BUCKET_SUSPICIOUS: 1,
        BUCKET_BENIGN: 1,
        BUCKET_INCONCLUSIVE: 1,
        BUCKET_SYNTHESIS: 1,
    }
    rt = {"bucket_counts": dict(counts)}
    assert check_report_bucket_consistency(b, counts, rt) == []


def test_blocks_non_confirmed_items_from_critical_atomic_sections():
    b = _buckets()
    # benign / inconclusive / suspicious finding id leaks into confirmed
    leaked = _f("S3", BUCKET_CONFIRMED)
    b[BUCKET_CONFIRMED].append(leaked)
    v = check_report_bucket_consistency(b)
    assert any("benign" in x for x in v)


def test_disposition_count_mismatch_detected():
    b = _buckets()
    counts = {BUCKET_CONFIRMED: 5}  # bucket has 2
    v = check_report_bucket_consistency(b, counts)
    assert any("disposition_count_mismatch" in x for x in v)


def test_synthesis_does_not_increment_confirmed_count():
    b = _buckets()
    # report_truth claims confirmed == confirmed + synthesis (folded in)
    rt = {"bucket_counts": {BUCKET_CONFIRMED: 3}}
    v = check_report_bucket_consistency(b, None, rt)
    assert any("report_truth_confirmed_mismatch" in x for x in v)
    # synthesis bucket count itself never changes confirmed count
    assert len(b[BUCKET_CONFIRMED]) == 2
