"""TDD (D5 / A-finish): self-relative SRUM egress-outlier malicious semantic.

The recovered SRUM rows (D1b) carry per-app network egress. A row whose egress
is a statistical outlier RELATIVE TO THIS IMAGE's own SRUM distribution
(> mean + 2*stdev) is a candidate data-exfiltration-volume signal (MITRE
T1048/T1567). Registering it as a non-weak malicious semantic lets a corroborated
high-egress finding escape the disposition benign-floor to suspicious_needs_review.

Dataset-agnostic + self-relative: the threshold is derived from the image's own
SRUM corpus -- NO fixed byte constant, no host/app/path/case literal. Avoids the
flat-10MB flooding problem (only per-image outliers fire).
"""
from sift_sentinel.analysis import malicious_semantics as ms
from sift_sentinel.analysis import disposition as disp


def _srum(bt):
    return {"fact_type": "srum_usage_fact", "fields": {"bytes_total": bt}}


def _db(values):
    return {"typed_facts": {"srum_usage_fact": [_srum(v) for v in values]}}


def test_threshold_none_for_small_sample():
    # Too few rows to compute a meaningful distribution -> no outlier call.
    assert ms._srum_egress_outlier_threshold([1, 2, 3]) is None


def test_threshold_flags_only_the_outlier():
    vals = [1000] * 10 + [100_000_000]
    thr = ms._srum_egress_outlier_threshold(vals)
    assert thr is not None
    assert 100_000_000 > thr  # the huge sender is an outlier
    assert 1000 < thr          # the typical rows are not


def test_matcher_fires_on_outlier_row():
    vals = [1000] * 10 + [100_000_000]
    db = _db(vals)
    assert ms.match_srum_egress_outlier(_srum(100_000_000), evidence_db=db) is True


def test_matcher_ignores_typical_row():
    vals = [1000] * 10 + [100_000_000]
    db = _db(vals)
    assert ms.match_srum_egress_outlier(_srum(1000), evidence_db=db) is False


def test_matcher_no_evidence_db_is_false():
    assert ms.match_srum_egress_outlier(_srum(1), evidence_db=None) is False


def test_matcher_ignores_nonsrum_fact():
    db = _db([1000] * 10 + [100_000_000])
    assert ms.match_srum_egress_outlier(
        {"fact_type": "process_fact", "fields": {}}, evidence_db=db) is False


def test_signal_registered_and_not_weak_alone():
    assert "srum_egress_outlier" in ms.MALICIOUS_SEMANTIC_SIGNALS
    assert "srum_egress_outlier" not in disp._WEAK_ALONE_SEMANTIC_SIGNALS
    assert "srum_egress_outlier" not in disp._DISK_HISTORY_SEMANTIC_SIGNALS
