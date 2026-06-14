from sift_sentinel.correction.sc_terminal import classify_self_correction_terminal_result


def test_legacy_error_only_without_error_is_honest_drop():
    result, status, reason = classify_self_correction_terminal_result(
        {
            "finding_id": "FGEN",
            "status": "FAILED",
            "outcome_kind": "ERROR_ONLY",
            "reason": "all 3 attempt(s) failed; kept as UNRESOLVED, not promoted",
        },
        "FGEN",
    )

    assert status == "dropped_honest"
    assert result["status"] == "dropped_honest"
    assert result["honest_drop"] is True
    assert "UNRESOLVED" in reason


def test_unfixable_wrapper_null_is_honest_drop():
    result, status, reason = classify_self_correction_terminal_result(
        {
            "finding_id": "FGEN",
            "validator_result": "UNFIXABLE",
            "reason": "wrapper finding=null (AI declined to rewrite)",
        },
        "FGEN",
    )

    assert status == "dropped_honest"
    assert result["status"] == "dropped_honest"
    assert "declined" in reason


def test_infrastructure_error_stays_failed():
    result, status, reason = classify_self_correction_terminal_result(
        {
            "finding_id": "FGEN",
            "status": "failed_with_reason",
            "error": "api timeout",
            "outcome_kind": "DROPPED_HONEST",
        },
        "FGEN",
    )

    assert status == "failed_with_reason"
    assert result["status"] == "failed_with_reason"
    assert "api timeout" in reason


def test_corrected_and_rejected_still_classify_normally():
    corrected, c_status, _ = classify_self_correction_terminal_result(
        {"finding_id": "FC", "corrected": True},
        "FC",
    )
    rejected, r_status, _ = classify_self_correction_terminal_result(
        {"finding_id": "FR", "status": "exhausted", "reason": "validator rejected"},
        "FR",
    )

    assert c_status == "corrected"
    assert corrected["status"] == "corrected"
    assert r_status == "rejected"
    assert rejected["status"] == "rejected"


def test_unknown_schema_fails_closed():
    result, status, reason = classify_self_correction_terminal_result(
        {"finding_id": "FU", "note": "not a terminal schema"},
        "FU",
    )

    assert status == "failed_with_reason"
    assert result["status"] == "failed_with_reason"
    assert reason == "unrecognized_result_schema"
