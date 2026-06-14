"""Routing validator-blocked findings into a disposition bucket MUST also add
them to findings_final, or the PARTITION_GATE aborts the whole run.

Live crash: INV3A_REVIEW_BLOCKED routed 10 validator-blocked findings into
inconclusive_unresolved (so they are not silently dropped), but they were never
added to findings_final. The partition gate -- buckets MUST partition
findings_final -- then saw bucket_total=56 vs findings_final=46 and raised
RuntimeError("PARTITION_GATE=FAIL ... orphan_in_buckets") right before the
report, so the pipeline exited by itself.

The full suite never caught it because run_pipeline.py is a script the suite
does not execute. This test locks the invariant at the gate level: blocked
findings put into a bucket must also be in findings_final.

Universal: synthetic finding ids, no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.disposition import assert_buckets_partition_findings  # noqa: E402
from sift_sentinel.analysis.inv3a_finalize import prepare_blocked_for_review      # noqa: E402

BUCKETS = ("confirmed_malicious_atomic", "suspicious_needs_review",
           "benign_or_false_positive", "inconclusive_unresolved",
           "synthesis_narrative")


def _empty():
    return {k: [] for k in BUCKETS}


def _f(fid):
    return {"finding_id": fid}


def test_blocked_in_bucket_but_not_in_findings_final_is_an_orphan():
    # reproduce the crash: a routed-blocked finding sits in a bucket but not in
    # findings_final
    findings_final = [_f("F001"), _f("F002")]
    buckets = _empty()
    buckets["suspicious_needs_review"] = [_f("F001"), _f("F002")]
    buckets["inconclusive_unresolved"] = [_f("BLK1")]          # orphan
    violations = assert_buckets_partition_findings(buckets, findings_final)
    assert violations, "gate should flag the orphan-in-bucket"
    assert any("BLK1" in str(v) for v in violations)


def test_adding_routed_blocked_to_findings_final_restores_partition():
    # the fix: the routed-blocked findings are added to findings_final too
    base_final = [_f("F001"), _f("F002")]
    blocked = prepare_blocked_for_review(
        [({"finding_id": "BLK1", "description": "x",
           "source_tools": ["parse_event_logs"]}, "no recognized claim types"),
         ({"finding_id": "BLK2", "description": "y",
           "source_tools": ["parse_registry"]}, "no recognized claim types")])
    assert blocked, "prepare_blocked_for_review should normalize the blocked list"

    buckets = _empty()
    buckets["suspicious_needs_review"] = [_f("F001"), _f("F002")]
    buckets["inconclusive_unresolved"] = list(blocked)
    # apply the same consistency rule run_pipeline uses
    ff_ids = {f["finding_id"] for f in base_final}
    findings_final = base_final + [f for f in blocked if f.get("finding_id") not in ff_ids]

    violations = assert_buckets_partition_findings(buckets, findings_final)
    assert violations == [], f"partition should be clean, got: {violations}"
    assert len(findings_final) == sum(len(buckets[b]) for b in BUCKETS)


def test_no_duplicate_when_blocked_id_already_in_findings_final():
    # dedup guard: a blocked id already present must not be added twice
    blocked = prepare_blocked_for_review(
        [({"finding_id": "F001", "description": "x",
           "source_tools": ["parse_event_logs"]}, "no recognized claim types")])
    base_final = [_f("F001")]
    ff_ids = {f["finding_id"] for f in base_final}
    findings_final = base_final + [f for f in blocked if f.get("finding_id") not in ff_ids]
    assert [f["finding_id"] for f in findings_final] == ["F001"]   # not duplicated
