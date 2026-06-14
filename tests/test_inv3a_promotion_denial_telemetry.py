"""Denied promotions must self-explain: when inv3a's model verdict is
'confirmed' but the deterministic eligibility gate keeps the finding out of
confirmed_malicious_atomic, the ledger entry must carry WHICH gates blocked it.

Live gap: a run ended confirmed_malicious_atomic=0 with 30+ model-confirmed
verdicts, and nothing in the ledger or console said why -- the eligibility
result (blocking_reasons) was reduced to a bare bool and discarded. Universal
telemetry fix, no routing change: annotate_promotion_denials() attaches
``promotion_denied_by`` to each denied verdict and returns a reason histogram
for one console line (INV3A_PROMOTION_DENIALS ...).

Universal: structural ids only, no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.inv3a_finalize import (  # noqa: E402
    annotate_promotion_denials,
    BUCKET_CONFIRMED,
    BUCKET_SUSPICIOUS,
)


def test_denied_confirmed_verdict_gets_reasons_attached():
    verdicts = [
        {"finding_id": "F001", "disposition": "confirmed", "to": BUCKET_SUSPICIOUS},
        {"finding_id": "F002", "disposition": "confirmed", "to": BUCKET_CONFIRMED},
        {"finding_id": "F003", "disposition": "needs_review", "to": BUCKET_SUSPICIOUS},
    ]
    denials = {"F001": ["no_typed_or_validated_support", "missing_raw_excerpt"]}
    hist = annotate_promotion_denials(verdicts, denials)
    assert verdicts[0]["promotion_denied_by"] == [
        "no_typed_or_validated_support", "missing_raw_excerpt"]
    assert "promotion_denied_by" not in verdicts[1]      # promoted -> no denial
    assert "promotion_denied_by" not in verdicts[2]      # not a confirmed verdict
    assert hist == {"no_typed_or_validated_support": 1, "missing_raw_excerpt": 1}


def test_histogram_aggregates_across_findings():
    verdicts = [
        {"finding_id": f"F{i:03d}", "disposition": "confirmed", "to": BUCKET_SUSPICIOUS}
        for i in range(3)
    ]
    denials = {f"F{i:03d}": ["no_typed_or_validated_support"] for i in range(3)}
    hist = annotate_promotion_denials(verdicts, denials)
    assert hist == {"no_typed_or_validated_support": 3}


def test_garbage_safe():
    assert annotate_promotion_denials(None, {}) == {}
    assert annotate_promotion_denials([None, "x", {}], {"F1": ["r"]}) == {}


def test_reason_list_is_capped():
    verdicts = [{"finding_id": "F1", "disposition": "confirmed", "to": BUCKET_SUSPICIOUS}]
    denials = {"F1": [f"reason_{i}" for i in range(20)]}
    annotate_promotion_denials(verdicts, denials)
    assert len(verdicts[0]["promotion_denied_by"]) <= 6
