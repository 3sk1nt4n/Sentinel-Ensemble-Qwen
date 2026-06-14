from pathlib import Path


def test_sc_failed_status_without_error_is_rejected_not_infra_failure():
    text = Path("src/sift_sentinel/coordinator.py").read_text()
    assert 'raw_status in {"failed", "not_corrected", "uncorrected", "exhausted", "validator_rejected"}' in text
    assert 'return result, "rejected"' in text
    assert 'result.get("error") or raw_status in {"failed_with_reason", "error", "exception"}' in text


def test_no_old_parallel_sc_masking_log_remains():
    text = Path("src/sift_sentinel/coordinator.py").read_text()
    assert "Step 12 SC: parallel correction failed" not in text
    assert "SELF_CORRECTION_TRIGGERED" in text
    assert "SELF_CORRECTION_FINDING_RESULT" in text
    assert "SELF_CORRECTION_SUMMARY" in text
    assert "SELF_CORRECTION_EXECUTION_GATE" in text
