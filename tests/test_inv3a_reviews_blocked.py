"""inv3a must give validator-blocked / rejected findings a FINAL cross-check,
not let them be silently dropped.

Bug (a live paired run): 8 findings were validator-blocked ('no recognized
claim types'), logged 'deferred to Step 13AA finalization' -- but the deferral
did nothing; they never reached inv3a, never entered findings_final, and
vanished (56 merged -> 40 final). That violates 'honest failure > wrong answer'.

prepare_blocked_for_review normalizes the blocked list into inconclusive-bucket
entries so inv3a's select_ambiguous reviews them. Confirmed/high/medium are
untouched (already adjudicated); only the unresolved get the cross-check.
Promotion stays gated by eligibility (a claimless finding can never be
fabricated into confirmed). Universal: structural, no case data.
Kill-switch SIFT_INV3A_REVIEW_BLOCKED=0.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.inv3a_finalize import (  # noqa: E402
    prepare_blocked_for_review,
    select_ambiguous,
    BUCKET_INCONCLUSIVE,
)


def _blk(fid, err="no recognized claim types"):
    return ({"finding_id": fid, "description": "synthetic blocked finding",
             "source_tools": ["parse_event_logs"], "severity": "MEDIUM"}, err)


def test_tuple_list_normalized_to_inconclusive_entries():
    out = prepare_blocked_for_review([_blk("F012"), _blk("F014")])
    assert {f["finding_id"] for f in out} == {"F012", "F014"}
    for f in out:
        assert isinstance(f, dict)
        assert any("blocked" in str(r).lower() for r in f.get("disposition_reasons") or [])


def test_plain_dict_list_also_accepted():
    out = prepare_blocked_for_review([{"finding_id": "F020", "description": "x"}])
    assert out and out[0]["finding_id"] == "F020"


def test_already_dispositioned_ids_are_skipped():
    # a blocked finding already present in a bucket (e.g. ReAct-settled) is not re-added
    out = prepare_blocked_for_review([_blk("F012"), _blk("F014")], existing_ids={"F012"})
    assert {f["finding_id"] for f in out} == {"F014"}


def test_kill_switch_returns_empty(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_REVIEW_BLOCKED", "0")
    assert prepare_blocked_for_review([_blk("F012")]) == []


def test_routed_blocked_are_picked_up_by_select_ambiguous():
    # the whole point: once injected into inconclusive, inv3a's selector sees them
    entries = prepare_blocked_for_review([_blk("F012"), _blk("F014")])
    buckets = {BUCKET_INCONCLUSIVE: entries}
    chosen = {f["finding_id"] for f in select_ambiguous(buckets)}
    assert chosen == {"F012", "F014"}


def test_garbage_entries_are_dropped_safely():
    out = prepare_blocked_for_review([None, ("not-a-dict", "err"), ({}, "err")])
    assert all(isinstance(f, dict) and f.get("finding_id") for f in out)
