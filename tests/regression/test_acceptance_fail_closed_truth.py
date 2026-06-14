"""Slot 31E-DB.5d GROUP A TASK A1 -- ACCEPTANCE_RESULT_TRUTH_PROPAGATION.

A subgate FAIL must propagate into the final aggregate. Before this
slot the outer script could print a final PASS while a post-live
subgate had FAILed. The aggregate is fail-closed: PASS requires every
precondition AND a clean transcript. Dataset-agnostic, model-flexible.
"""
from __future__ import annotations

from sift_sentinel.acceptance_aggregate import (
    ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE,
    aggregate_acceptance_result,
    transcript_has_fail_gate,
)

_OK_KW = dict(
    live_rc=0,
    recorded_env_exists=True,
    recorded_state_dir_exists=True,
    post_live_rc=0,
)


def test_subgate_fail_then_attempted_final_pass_is_fail_review():
    transcript = "\n".join([
        "POST_LIVE_USES_RECORDED_RUN_GATE=PASS",
        "RAW_DISK_HASH_GATE=FAIL (no raw disk hash recorded)",
        "final result: PASS",  # the old bug -- attempted green
    ])
    res = aggregate_acceptance_result(transcript, **_OK_KW)
    assert res["result"] == "FAIL_REVIEW"
    assert res["passed"] is False
    assert "subgate_fail_line_in_transcript" in res["reasons"]
    assert res["gate"] == ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE


def test_all_clean_is_pass():
    transcript = "\n".join([
        "POST_LIVE_USES_RECORDED_RUN_GATE=PASS",
        "RAW_DISK_HASH_GATE=PASS",
        "MODEL_NAME_NONPERSISTENCE_GATE=PASS",
    ])
    res = aggregate_acceptance_result(transcript, **_OK_KW)
    assert res["result"] == "PASS"
    assert res["passed"] is True
    assert res["reasons"] == []


def test_live_rc_nonzero_fails_closed():
    res = aggregate_acceptance_result(
        "ALL_GATES=PASS",
        live_rc=1,
        recorded_env_exists=True,
        recorded_state_dir_exists=True,
        post_live_rc=0,
    )
    assert res["result"] == "FAIL_REVIEW"
    assert any(r.startswith("live_pipeline_rc!=0") for r in res["reasons"])


def test_missing_env_and_state_fail_closed():
    res = aggregate_acceptance_result(
        "ALL_GATES=PASS",
        live_rc=0,
        recorded_env_exists=False,
        recorded_state_dir_exists=False,
        post_live_rc=0,
    )
    assert res["result"] == "FAIL_REVIEW"
    assert "recorded_run_env_missing" in res["reasons"]
    assert "recorded_state_dir_missing" in res["reasons"]


def test_post_live_rc_nonzero_fails_closed():
    res = aggregate_acceptance_result("ALL_GATES=PASS", live_rc=0,
                                      recorded_env_exists=True,
                                      recorded_state_dir_exists=True,
                                      post_live_rc=2)
    assert res["result"] == "FAIL_REVIEW"


def test_reasoning_prose_does_not_trip_detector():
    # ZEROFAKE: plain narration containing the word "fail" is not a
    # structured gate failure and must NOT force FAIL_REVIEW.
    transcript = (
        "note: this run could fail if the disk were missing, but it "
        "did not. ALL_GATES=PASS"
    )
    assert transcript_has_fail_gate(transcript) is False
    res = aggregate_acceptance_result(transcript, **_OK_KW)
    assert res["result"] == "PASS"


def test_detector_catches_structured_forms():
    assert transcript_has_fail_gate("SOME_GATE=FAIL") is True
    assert transcript_has_fail_gate("ACCEPTANCE_RESULT=FAIL_REVIEW") is True
    assert transcript_has_fail_gate("RAW_DISK_HASH_GATE=FAIL (reason)") is True
    assert transcript_has_fail_gate("") is False


def test_marker():
    print(f"{ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE}=PASS")
    assert (ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE
            == "ACCEPTANCE_RESULT_TRUTH_PROPAGATION_GATE")
