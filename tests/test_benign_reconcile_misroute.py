"""Late-benign reconciliation backstop (universal, structural).

Live bug (Opus rd01-style run): a finding the system itself assessed BENIGN —
either ReAct `react_conclusion.verdict == confirmed_benign` / `is_false_positive`,
or the `_fp_routing_benign` entity-propagation flag — stayed in
`suspicious_needs_review` because the benign signal was finalized by a pass that
runs AFTER `route_findings_for_report` built the buckets. The buckets were never
re-derived from the final finding state.

`reconcile_benign_misroutes` re-evaluates each suspicious/inconclusive finding
with the SAME canonical `derive_final_disposition` and moves it to benign only
when the router itself says benign. It keys on NOTHING case-specific — only the
structural verdict fields / override flags — so a contested finding
(`react_entity_conflict`) is never moved, and the confirmed bucket is untouched.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.disposition import (  # noqa: E402
    reconcile_benign_misroutes,
    BUCKET_BENIGN,
    BUCKET_SUSPICIOUS,
    BUCKET_INCONCLUSIVE,
    BUCKET_CONFIRMED,
)


def _empty():
    return {
        BUCKET_CONFIRMED: [],
        BUCKET_SUSPICIOUS: [],
        BUCKET_BENIGN: [],
        BUCKET_INCONCLUSIVE: [],
        "synthesis_narrative": [],
    }


def test_react_confirmed_benign_in_suspicious_is_moved():
    b = _empty()
    b[BUCKET_SUSPICIOUS].append({
        "finding_id": "F014",
        "react_conclusion": {"verdict": "confirmed_benign", "is_false_positive": True},
    })
    n = reconcile_benign_misroutes(b, enabled=True)
    assert n == 1
    assert not b[BUCKET_SUSPICIOUS]
    assert [f["finding_id"] for f in b[BUCKET_BENIGN]] == ["F014"]


def test_fp_routing_flag_in_suspicious_is_moved():
    b = _empty()
    b[BUCKET_SUSPICIOUS].append({
        "finding_id": "F050",
        "_fp_routing_benign": True,
        "_fp_routing_reason": "entity_benign_propagation",
    })
    n = reconcile_benign_misroutes(b, enabled=True)
    assert n == 1
    assert [f["finding_id"] for f in b[BUCKET_BENIGN]] == ["F050"]


def test_no_benign_signal_stays_suspicious():
    b = _empty()
    b[BUCKET_SUSPICIOUS].append({"finding_id": "F999", "title": "admin-share access"})
    n = reconcile_benign_misroutes(b, enabled=True)
    assert n == 0
    assert [f["finding_id"] for f in b[BUCKET_SUSPICIOUS]] == ["F999"]
    assert not b[BUCKET_BENIGN]


def test_react_entity_conflict_overrides_benign_NOT_moved():
    # CRITICAL: a finding flagged with a contradicting entity must NOT be moved
    # even if it carries a benign react_conclusion — the override precedence in
    # derive_final_disposition keeps it in suspicious.
    b = _empty()
    b[BUCKET_SUSPICIOUS].append({
        "finding_id": "F777",
        "react_entity_conflict": True,
        "react_conclusion": {"verdict": "confirmed_benign", "is_false_positive": True},
    })
    n = reconcile_benign_misroutes(b, enabled=True)
    assert n == 0
    assert [f["finding_id"] for f in b[BUCKET_SUSPICIOUS]] == ["F777"]


def test_confirmed_bucket_never_touched():
    b = _empty()
    b[BUCKET_CONFIRMED].append({
        "finding_id": "F008",
        "react_conclusion": {"verdict": "confirmed_benign", "is_false_positive": True},
    })
    n = reconcile_benign_misroutes(b, enabled=True)
    assert n == 0
    assert [f["finding_id"] for f in b[BUCKET_CONFIRMED]] == ["F008"]


def test_kill_switch_off_is_noop():
    b = _empty()
    b[BUCKET_SUSPICIOUS].append({"finding_id": "F050", "_fp_routing_benign": True})
    n = reconcile_benign_misroutes(b, enabled=False)
    assert n == 0
    assert [f["finding_id"] for f in b[BUCKET_SUSPICIOUS]] == ["F050"]


def test_idempotent():
    b = _empty()
    b[BUCKET_SUSPICIOUS].append({"finding_id": "F050", "_fp_routing_benign": True})
    reconcile_benign_misroutes(b, enabled=True)
    n2 = reconcile_benign_misroutes(b, enabled=True)
    assert n2 == 0
    assert [f["finding_id"] for f in b[BUCKET_BENIGN]] == ["F050"]
