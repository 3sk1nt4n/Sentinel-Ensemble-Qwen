"""inv3a floored-benign sweep: LOW/info findings buried by an AUTOMATED
weakness floor (reason prefix ``benign:`` -- one_claim_weak / uncorroborated_weak)
were never seen by any AI -- inv3a now adjudicates them too, so a silently
buried true positive gets a second look.

Terminal exclusions preserved: ``override:``-class burials (ReAct-cleared FP,
JIT-RWX gate, tool-status noise, fp-routing) were adjudicated or zero-FP
validated and stay untouchable, as do confirmed and CRITICAL/HIGH rows
(operator rule). The existing confirm-clamp still applies: a swept benign can
never move to confirmed without the eligibility gate.

Kill-switch: SIFT_INV3A_SWEEP_FLOORED=0. Universal: keyed on the pipeline's
own disposition-reason grammar + severity rank -- no case data.
"""
import json

from sift_sentinel.analysis.inv3a_finalize import (
    BUCKET_BENIGN,
    BUCKET_SUSPICIOUS,
    finalize_dispositions,
    select_ambiguous,
)


def _floored(fid="FB1", severity="LOW"):
    return {
        "finding_id": fid,
        "description": "weak single-claim observation",
        "severity": severity,
        "disposition_reasons": [
            "react_verdict=None(none)",
            "gate:one_claim_unsupported[no_validator_metadata]",
            "benign:one_claim_weak_or_history_only",
        ],
    }


def _react_cleared(fid="FB2"):
    return {
        "finding_id": fid,
        "description": "vendor updater, AI cross-checked",
        "severity": "LOW",
        "disposition_reasons": [
            "react_verdict=benign(react)",
            "override:benign_or_fp",
        ],
    }


def _gate_cleared(fid="FB3"):
    return {
        "finding_id": fid,
        "description": "JIT RWX allocation",
        "severity": "MEDIUM",
        "disposition_reasons": ["override:benign_jit_rwx[managed_host]"],
    }


def _buckets(benign):
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            {"finding_id": "S1", "description": "rwx region"}],
        "benign_or_false_positive": list(benign),
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_floor_buried_low_benign_is_selected():
    picked = {f["finding_id"]
              for f in select_ambiguous(_buckets([_floored()]))}
    assert "FB1" in picked
    assert "S1" in picked  # existing tiers unchanged


def test_react_cleared_and_gate_cleared_stay_terminal():
    picked = {f["finding_id"] for f in select_ambiguous(
        _buckets([_react_cleared(), _gate_cleared()]))}
    assert "FB2" not in picked
    assert "FB3" not in picked


def test_critical_and_high_floored_excluded_by_operator_rule():
    picked = {f["finding_id"] for f in select_ambiguous(_buckets([
        _floored("FBH", severity="HIGH"),
        _floored("FBC", severity="CRITICAL"),
        _floored("FBM", severity="MEDIUM"),
    ]))}
    assert "FBH" not in picked and "FBC" not in picked
    assert "FBM" in picked  # MEDIUM floor-burial gets the second look


def test_kill_switch_disables_floored_sweep(monkeypatch):
    monkeypatch.setenv("SIFT_INV3A_SWEEP_FLOORED", "0")
    picked = {f["finding_id"]
              for f in select_ambiguous(_buckets([_floored()]))}
    assert "FB1" not in picked
    assert "S1" in picked  # core tiers unaffected by the switch


def test_floored_benign_moves_to_needs_review_on_verdict():
    buckets = _buckets([_floored()])

    def adjudicator(prompt):
        assert "FB1" in prompt  # the floored finding reached the AI
        return json.dumps([
            {"finding_id": "FB1", "disposition": "needs_review",
             "reason": "weak but unexplained persistence-shaped value"},
            {"finding_id": "S1", "disposition": "needs_review",
             "reason": "stays"},
        ])

    new, ledger = finalize_dispositions(buckets, adjudicator)
    moved = {m["finding_id"]: m for m in ledger}
    assert "FB1" in moved
    assert moved["FB1"]["from"] == BUCKET_BENIGN
    assert moved["FB1"]["to"] == BUCKET_SUSPICIOUS
    ids_susp = {f["finding_id"] for f in new[BUCKET_SUSPICIOUS]}
    ids_benign = {f["finding_id"] for f in new[BUCKET_BENIGN]}
    assert "FB1" in ids_susp and "FB1" not in ids_benign


def test_floored_benign_confirm_verdict_clamped_without_eligibility():
    buckets = _buckets([_floored()])

    def adjudicator(prompt):
        return json.dumps([{"finding_id": "FB1", "disposition": "confirmed",
                            "reason": "looks evil"}])

    new, ledger = finalize_dispositions(buckets, adjudicator)
    # clamp: no eligibility_fn => lands in needs-review, never confirmed
    assert not new["confirmed_malicious_atomic"]
    moved = {m["finding_id"]: m for m in ledger}
    assert moved["FB1"]["to"] == BUCKET_SUSPICIOUS


def test_floored_benign_false_positive_verdict_is_noop():
    buckets = _buckets([_floored()])

    def adjudicator(prompt):
        return json.dumps([{"finding_id": "FB1",
                            "disposition": "false_positive",
                            "reason": "vendor updater"}])

    new, ledger = finalize_dispositions(buckets, adjudicator)
    assert not ledger  # dest == src => no move, no badge
    assert {f["finding_id"] for f in new[BUCKET_BENIGN]} == {"FB1"}
