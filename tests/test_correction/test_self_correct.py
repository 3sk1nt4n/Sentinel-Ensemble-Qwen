"""
Sentinel Qwen Ensemble - Self-correction loop tests.
Validates: clean slate protocol, max attempts, UNRESOLVED score,
audit trail preservation (DRAFT + FINAL), exact error routing.
"""

from __future__ import annotations

import copy

import pytest

from sift_sentinel.correction.self_correct import self_correct
from sift_sentinel.validation.validator import validate_finding


# ── Fixtures ─────────────────────────────────────────────────────────────

REF_SET = {
    "hashes": {"abc123def456": "malware.exe"},
    "pid_to_process": {1234: ["svchost.exe"], 9004: ["sample_payload.exe"]},
    "timestamps_per_artifact": {"malware.exe": ["2018-04-11 14:22:07"]},
    "connections": {"9004:192.0.2.111:4444->192.0.2.129:443": "sample_payload.exe"},
    "paths": {},
}

WRONG_FINDING = {
    "finding_id": "F-001",
    "artifact": "malware.exe",
    "confidence_level": "HIGH",
    "claims": [
        {"type": "hash", "sha1": "abc123def456", "filename": "benign.exe"},
    ],
}

CORRECT_FINDING = {
    "finding_id": "F-001",
    "artifact": "malware.exe",
    "confidence_level": "HIGH",
    "claims": [
        {"type": "hash", "sha1": "abc123def456", "filename": "malware.exe"},
    ],
}

RAW_DATA = {
    "vol_pstree": {"output": [{"PID": 9004, "ImageFileName": "sample_payload.exe"}]},
    "get_amcache": {"output": [{"sha1": "abc123def456", "path": "C:\\malware.exe"}]},
}


# ── Test 1: MISMATCH triggers correction with exact error ────────────────

def test_mismatch_triggers_correction_with_exact_error():
    """Validator MISMATCH error string is passed verbatim to corrector."""
    validation = validate_finding(WRONG_FINDING, REF_SET)
    assert validation["status"] == "MISMATCH"
    exact_error = validation["detail"]

    received_errors = []

    def spy_corrector(raw_data, error):
        received_errors.append(error)
        return copy.deepcopy(CORRECT_FINDING)

    result = self_correct(
        finding=WRONG_FINDING,
        error=exact_error,
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=spy_corrector,
    )

    assert result["status"] == "CORRECTED"
    # Corrector now receives strategy-enriched prompt containing the error
    assert exact_error in received_errors[0]


# ── Test 2: Clean slate -- never sees previous wrong draft ────────────────

def test_clean_slate_no_previous_draft():
    """Corrector receives only (raw_data, error) each call, never previous drafts."""
    call_args = []
    call_count = [0]

    def recording_corrector(raw_data, error):
        call_count[0] += 1
        call_args.append({"raw_data": raw_data, "error": error})
        if call_count[0] < 3:
            return copy.deepcopy(WRONG_FINDING)
        return copy.deepcopy(CORRECT_FINDING)

    raw_snapshot = copy.deepcopy(RAW_DATA)

    result = self_correct(
        finding=WRONG_FINDING,
        error="initial hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=recording_corrector,
    )

    assert result["status"] == "CORRECTED"
    assert len(call_args) == 3

    for i, args in enumerate(call_args):
        assert set(args.keys()) == {"raw_data", "error"}, \
            f"attempt {i + 1}: corrector received unexpected keys"
        assert args["raw_data"] is RAW_DATA, \
            f"attempt {i + 1}: raw_data is not the same object"
        assert isinstance(args["error"], str), \
            f"attempt {i + 1}: error is not a string"

    assert RAW_DATA == raw_snapshot, "raw_data was mutated during correction"


# ── Test 3: Max 3 attempts then UNRESOLVED ───────────────────────────────

def test_max_three_attempts_then_unresolved():
    """After 3 failed attempts, status is UNRESOLVED."""
    attempt_count = [0]

    def always_wrong(raw_data, error):
        attempt_count[0] += 1
        return copy.deepcopy(WRONG_FINDING)

    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        max_attempts=3,
        corrector_fn=always_wrong,
    )

    assert result["status"] == "UNRESOLVED"
    assert attempt_count[0] == 3
    assert result["attempt_count"] == 3
    assert len(result["attempts"]) == 3


# ── Test 4: Successful correction has both versions ──────────────────────

def test_successful_correction_both_versions():
    """Corrected result preserves DRAFT (original) and FINAL (corrected)."""
    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=lambda rd, e: copy.deepcopy(CORRECT_FINDING),
    )

    assert result["status"] == "CORRECTED"
    assert result["self_corrected"] is True

    # DRAFT preserved at top level and inside finding
    assert result["original_draft"] is WRONG_FINDING
    assert result["original_draft"]["claims"][0]["filename"] == "benign.exe"

    # FINAL in finding with correction metadata
    corrected = result["finding"]
    assert corrected["self_corrected"] is True
    assert corrected["original_draft"] is WRONG_FINDING
    assert corrected["correction_reason"] == "hash mismatch"
    assert corrected["deterministic_check"] == "corrected"
    assert corrected["claims"][0]["filename"] == "malware.exe"


# ── Test 5: UNRESOLVED has score 0, not -2 ──────────────────────────────

def test_unresolved_score_zero_not_negative_two():
    """UNRESOLVED findings get score 0 (honest unknown), never -2 (wrong)."""
    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=lambda rd, e: copy.deepcopy(WRONG_FINDING),
    )

    assert result["status"] == "UNRESOLVED"
    assert result["finding"]["score"] == 0
    assert result["finding"]["score"] != -2
    assert result["finding"]["confidence_level"] == "UNRESOLVED"
    assert result["finding"]["self_corrected"] is False


# ── Edge cases ───────────────────────────────────────────────────────────

def test_corrector_exception_continues():
    """If corrector raises, loop continues to next attempt."""
    call_count = [0]

    def flaky_corrector(raw_data, error):
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("model timeout")
        return copy.deepcopy(CORRECT_FINDING)

    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=flaky_corrector,
    )

    assert result["status"] == "CORRECTED"
    assert result["attempt_count"] == 2
    assert result["attempts"][0]["status"] == "ERROR"
    assert result["attempts"][1]["status"] == "MATCH"


def test_missing_corrector_fn_raises():
    """Omitting corrector_fn raises ValueError."""
    with pytest.raises(ValueError, match="corrector_fn"):
        self_correct(
            finding=WRONG_FINDING,
            error="hash mismatch",
            raw_data=RAW_DATA,
            ref_set=REF_SET,
        )


def test_second_attempt_succeeds():
    """Correction on attempt 2 returns attempt_count=2."""
    call_count = [0]

    def fix_on_second(raw_data, error):
        call_count[0] += 1
        if call_count[0] == 1:
            return copy.deepcopy(WRONG_FINDING)
        return copy.deepcopy(CORRECT_FINDING)

    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=fix_on_second,
    )

    assert result["status"] == "CORRECTED"
    assert result["attempt_count"] == 2


def test_error_updates_between_attempts():
    """After first attempt fails, subsequent attempts see validator's specific error."""
    received_errors = []

    def recording_corrector(raw_data, error):
        received_errors.append(error)
        return copy.deepcopy(WRONG_FINDING)

    self_correct(
        finding=WRONG_FINDING,
        error="initial error",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=recording_corrector,
    )

    # Attempt 1 strategy prompt contains the initial error
    assert "initial error" in received_errors[0]
    # After attempt 1 fails validation, error updates to validator's detail
    assert "abc123def456" in received_errors[1]
    assert received_errors[1] != received_errors[0]


def test_correction_reason_preserves_original_error():
    """Even after error updates between attempts, correction_reason keeps original."""
    result = self_correct(
        finding=WRONG_FINDING,
        error="original error message",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=lambda rd, e: copy.deepcopy(WRONG_FINDING),
    )

    assert result["correction_reason"] == "original error message"
    assert result["finding"]["correction_reason"] == "original error message"


def test_pid_mismatch_correction():
    """Self-correction works for PID claims, not just hash claims."""
    wrong_pid = {
        "finding_id": "F-002",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 9004, "process": "wrong.exe"},
        ],
    }
    correct_pid = {
        "finding_id": "F-002",
        "artifact": "sample_payload.exe",
        "confidence_level": "HIGH",
        "claims": [
            {"type": "pid", "pid": 9004, "process": "sample_payload.exe"},
        ],
    }

    result = self_correct(
        finding=wrong_pid,
        error="PID 9004 is sample_payload.exe, not wrong.exe (cross-contamination)",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=lambda rd, e: copy.deepcopy(correct_pid),
    )

    assert result["status"] == "CORRECTED"
    assert result["finding"]["claims"][0]["process"] == "sample_payload.exe"


def test_corrector_returns_list_continues():
    """Corrector returning a list instead of dict is handled gracefully."""
    call_count = [0]

    def list_then_correct(raw_data, error):
        call_count[0] += 1
        if call_count[0] == 1:
            return [{"finding": "oops"}]  # non-dict
        return copy.deepcopy(CORRECT_FINDING)

    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=list_then_correct,
    )
    assert result["status"] == "CORRECTED"
    assert result["attempts"][0]["status"] == "ERROR"
    assert "list" in result["attempts"][0]["detail"]


def test_corrector_returns_string_continues():
    """Corrector returning a string instead of dict is handled gracefully."""
    call_count = [0]

    def string_then_correct(raw_data, error):
        call_count[0] += 1
        if call_count[0] == 1:
            return "just some text"
        return copy.deepcopy(CORRECT_FINDING)

    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=string_then_correct,
    )
    assert result["status"] == "CORRECTED"
    assert result["attempts"][0]["status"] == "ERROR"
    assert "str" in result["attempts"][0]["detail"]


def test_corrected_finding_instantiates_as_pydantic_model():
    """Finding(**corrected_result) succeeds; original_draft is a dict with prior fields."""
    from sift_sentinel.schema.finding import Finding

    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=lambda rd, e: copy.deepcopy(CORRECT_FINDING),
    )

    assert result["status"] == "CORRECTED"
    corrected = result["finding"]

    # Fill required Finding fields that self_correct doesn't populate
    corrected.setdefault("timestamp", None)
    corrected.setdefault("source_tools", ["get_amcache"])
    corrected.setdefault("tool_call_ids", ["tc-001"])
    corrected.setdefault("raw_excerpt", "test excerpt")
    corrected.setdefault("evidence_type", "hash")
    corrected.setdefault("alternative_explanations", [])
    corrected.setdefault("model_outputs", {})
    corrected.setdefault("self_verification_passed", True)

    finding = Finding(**corrected)

    assert isinstance(finding.original_draft, dict)
    assert finding.original_draft["finding_id"] == "F-001"
    assert finding.original_draft["claims"][0]["filename"] == "benign.exe"
    assert finding.self_corrected is True


# ── Normalization inside self-correction ─────────────────────────────────


class TestSelfCorrectNormalization:
    """Verify normalize_claims is applied before re-validation."""

    def test_process_name_alias_gets_corrected(self):
        """Corrector returns process_name instead of process.
        Normalization should rename it so validation succeeds."""
        ref_set = {
            "hashes": {},
            "pid_to_process": {100: ["sqlsvc.exe"]},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        blocked = {
            "finding_id": "F-BAD",
            "claims": [{"type": "pid", "pid": 100, "process": "wrong"}],
        }
        corrected = {
            "finding_id": "F-FIXED",
            "claims": [
                {"type": "pid", "pid": 100, "process_name": "sqlsvc.exe"},
            ],
        }

        def fake_corrector(raw, error):
            return corrected

        result = self_correct(
            finding=blocked,
            error="PID 100 is sqlsvc.exe, not wrong",
            raw_data={},
            ref_set=ref_set,
            corrector_fn=fake_corrector,
        )
        assert result["status"] == "CORRECTED"

    def test_string_pid_gets_coerced(self):
        """Corrector returns pid as string. Normalization should int() it."""
        ref_set = {
            "hashes": {},
            "pid_to_process": {42: ["test.exe"]},
            "timestamps_per_artifact": {},
            "connections": {},
            "paths": {},
        }
        blocked = {
            "finding_id": "F-BAD",
            "claims": [{"type": "pid", "pid": "bad", "process": "test.exe"}],
        }
        corrected = {
            "finding_id": "F-FIXED",
            "claims": [
                {"type": "pid", "pid": "42", "process": "test.exe"},
            ],
        }

        def fake_corrector(raw, error):
            return corrected

        result = self_correct(
            finding=blocked,
            error="PID bad not found",
            raw_data={},
            ref_set=ref_set,
            corrector_fn=fake_corrector,
        )
        assert result["status"] == "CORRECTED"


# ── Strategy-specific prompt tests ──────────────────────────────────────


def test_sc_attempt1_targeted_fix():
    """Attempt 1 prompt contains EXPLAIN_AND_RETRY language, validation error,
    and the specific failed claim."""
    received = []

    def spy(raw_data, error):
        received.append(error)
        return copy.deepcopy(CORRECT_FINDING)

    validation = validate_finding(WRONG_FINDING, REF_SET)
    exact_error = validation["detail"]

    self_correct(
        finding=WRONG_FINDING,
        error=exact_error,
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=spy,
    )

    prompt = received[0]
    # Strategy-specific language
    assert "REJECTED" in prompt
    assert "verifiable claims" in prompt
    # Validation error included
    assert exact_error in prompt
    # Failed claim included (first claim from the finding)
    assert "benign.exe" in prompt


def test_sc_attempt2_different_evidence():
    """Attempt 2 prompt simplifies to PID-only claims."""
    received = []
    call_count = [0]

    def spy(raw_data, error):
        call_count[0] += 1
        received.append(error)
        return copy.deepcopy(WRONG_FINDING)  # always wrong

    self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=spy,
    )

    assert len(received) >= 2
    prompt2 = received[1]
    assert "Simplify" in prompt2
    assert "PID-based claims" in prompt2
    assert "vol_pstree" in prompt2


def test_sc_attempt3_minimal_claim():
    """Attempt 3 prompt says 'ONE claim' and allows drop action."""
    received = []

    def spy(raw_data, error):
        received.append(error)
        return copy.deepcopy(WRONG_FINDING)  # always wrong

    self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=spy,
    )

    assert len(received) == 3
    prompt3 = received[2]
    assert "ONE claim" in prompt3
    assert "drop" in prompt3
    assert "pstree/psscan" in prompt3


def test_sc_strategy_names_logged(caplog):
    """Log output contains graduated strategy descriptions."""
    import logging

    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=WRONG_FINDING,
            error="hash mismatch",
            raw_data=RAW_DATA,
            ref_set=REF_SET,
            corrector_fn=lambda rd, e: copy.deepcopy(WRONG_FINDING),
        )

    log_text = caplog.text
    assert "Explain and retry" in log_text
    assert "Simplify" in log_text
    assert "Last chance" in log_text


def test_sc_attempts_include_claims_and_validation():
    """Each attempt entry includes claims_submitted and validation_result for debugging."""
    result = self_correct(
        finding=WRONG_FINDING,
        error="hash mismatch",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=lambda rd, e: copy.deepcopy(WRONG_FINDING),
    )

    assert result["status"] == "UNRESOLVED"
    for attempt in result["attempts"]:
        assert "claims_submitted" in attempt, \
            f"attempt {attempt['attempt']} missing claims_submitted"
        assert "validation_result" in attempt, \
            f"attempt {attempt['attempt']} missing validation_result"
        assert isinstance(attempt["claims_submitted"], list)
        assert isinstance(attempt["validation_result"], dict)
        assert "status" in attempt["validation_result"]


def test_sc_passes_validation_error():
    """SC function uses validation_result from previous attempt to build
    the next prompt, including the specific failed claim details."""
    received = []

    def spy(raw_data, error):
        received.append(error)
        return copy.deepcopy(WRONG_FINDING)  # always wrong

    self_correct(
        finding=WRONG_FINDING,
        error="initial error",
        raw_data=RAW_DATA,
        ref_set=REF_SET,
        corrector_fn=spy,
    )

    # Attempt 2+ prompts should contain the validator's specific error
    # from the previous attempt (not just the initial error)
    assert len(received) == 3
    # Attempt 2 should reference the validator detail from attempt 1
    assert "abc123def456" in received[1]
    # Attempt 3 should reference the validator detail from attempt 2
    assert "abc123def456" in received[2]
